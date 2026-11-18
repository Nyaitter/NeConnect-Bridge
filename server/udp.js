'use strict';

// UDP のまとまりを、TCP の中継の上でそのまま運ぶ。
// 宛先は一つに決めず、まとまりごとに相手を添えてやり取りする。
// 一つのソケットから複数の相手（STUN やメディアのサーバー）へ投げる通信も、
// これならそのまま通る。

const dgram = require('dgram');
const dns = require('dns');

const TYPE_IPV4 = 0x01;
const TYPE_DOMAIN = 0x03;
const TYPE_IPV6 = 0x04;

// 2 バイトの長さの最上位ビットは、UDP のまとまりの始まりを表す。
// 通常の宛先の長さは 1024 までなので、ぶつからない。
const UDP_REQUEST = 0x8000;

// 一度に運ぶ量の上限。UDP の最大値を超えない範囲に収める。
const MAX_PAYLOAD = 65000;

// 中継の向きを変える相手を決めるための待ち時間。
const IDLE_MS = 120 * 1000;

function ipv6Text(buf) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(buf.readUInt16BE(i).toString(16));
  }
  // 続く 0 の並びは :: に縮める。
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < groups.length; ) {
    if (groups[i] !== '0') {
      i += 1;
      continue;
    }
    let j = i;
    while (j < groups.length && groups[j] === '0') j += 1;
    if (j - i > bestLen) {
      bestLen = j - i;
      bestStart = i;
    }
    i = j;
  }
  if (bestLen > 1) {
    const head = groups.slice(0, bestStart).join(':');
    const tail = groups.slice(bestStart + bestLen).join(':');
    return `${head}::${tail}`;
  }
  return groups.join(':');
}

function encodeAddr(host, port) {
  const text = String(host || '').trim();
  const number = Number(port);
  if (!text || !Number.isInteger(number) || number < 0 || number > 65535) {
    throw new Error('invalid destination');
  }
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const parts = v4.slice(1).map((part) => Number(part));
    if (parts.every((part) => part <= 255)) {
      const out = Buffer.alloc(1 + 4 + 2);
      out[0] = TYPE_IPV4;
      out.set(parts, 1);
      out.writeUInt16BE(number, 5);
      return out;
    }
  }
  if (text.includes(':')) {
    const parts = expandIPv6(text);
    if (parts) {
      const out = Buffer.alloc(1 + 16 + 2);
      out[0] = TYPE_IPV6;
      for (let i = 0; i < 8; i += 1) out.writeUInt16BE(parts[i], 1 + i * 2);
      out.writeUInt16BE(number, 17);
      return out;
    }
  }
  const name = Buffer.from(text, 'utf8');
  if (name.length === 0 || name.length > 255) {
    throw new Error('invalid destination');
  }
  const out = Buffer.alloc(1 + 1 + name.length + 2);
  out[0] = TYPE_DOMAIN;
  out[1] = name.length;
  name.copy(out, 2);
  out.writeUInt16BE(number, 2 + name.length);
  return out;
}

function expandIPv6(text) {
  let value = text;
  const zone = value.indexOf('%');
  if (zone >= 0) value = value.slice(0, zone);
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
  } else if (missing < 1) {
    return null;
  }
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  const out = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    out.push(parseInt(group, 16));
  }
  return out;
}

function decodeAddr(buf, offset) {
  if (buf.length < offset + 1) return null;
  const type = buf[offset];
  let p = offset + 1;
  let host;
  if (type === TYPE_IPV4) {
    if (buf.length < p + 4) return null;
    host = `${buf[p]}.${buf[p + 1]}.${buf[p + 2]}.${buf[p + 3]}`;
    p += 4;
  } else if (type === TYPE_IPV6) {
    if (buf.length < p + 16) return null;
    host = ipv6Text(buf.subarray(p, p + 16));
    p += 16;
  } else if (type === TYPE_DOMAIN) {
    if (buf.length < p + 1) return null;
    const length = buf[p];
    p += 1;
    if (length === 0 || buf.length < p + length) return null;
    host = buf.toString('utf8', p, p + length);
    p += length;
  } else {
    return null;
  }
  if (buf.length < p + 2) return null;
  const port = buf.readUInt16BE(p);
  p += 2;
  return { host, port, size: p - offset };
}

function encodeFrame(host, port, payload) {
  const addr = encodeAddr(host, port);
  const body = payload && payload.length > MAX_PAYLOAD ? payload.subarray(0, MAX_PAYLOAD) : payload || Buffer.alloc(0);
  const total = addr.length + body.length;
  if (total > 65535) throw new Error('frame too large');
  const head = Buffer.alloc(2);
  head.writeUInt16BE(total, 0);
  return Buffer.concat([head, addr, body]);
}

// 届いた分をまとまりに切り分ける。途中で切れていれば、次に来た分とつなぐ。
class FrameDecoder {
  constructor(limit = 65535) {
    this.limit = limit;
    this.pending = Buffer.alloc(0);
  }

  push(chunk) {
    if (!chunk || chunk.length === 0) return { frames: [] };
    this.pending = this.pending.length === 0 ? chunk : Buffer.concat([this.pending, chunk]);
    const frames = [];
    for (;;) {
      if (this.pending.length < 2) break;
      const total = this.pending.readUInt16BE(0);
      if (total < 3 || total > this.limit) {
        return { frames, error: new Error(`invalid frame length ${total}`) };
      }
      if (this.pending.length < 2 + total) break;
      const body = this.pending.subarray(2, 2 + total);
      const addr = decodeAddr(body, 0);
      if (!addr || addr.size > body.length) {
        return { frames, error: new Error('invalid frame address') };
      }
      frames.push({ host: addr.host, port: addr.port, payload: body.subarray(addr.size) });
      this.pending = this.pending.subarray(2 + total);
    }
    if (this.pending.length > this.limit * 2) {
      return { frames, error: new Error('frame buffer overflow') };
    }
    return { frames };
  }
}

function isPrivateAddress(ip) {
  if (!ip) return true;
  const text = String(ip).replace(/^::ffff:/i, '');
  if (text === '0.0.0.0' || text === '::' || text === '::1' || text === '127.0.0.1') return true;
  if (text.startsWith('127.') || text.startsWith('10.') || text.startsWith('192.168.') || text.startsWith('169.254.')) {
    return true;
  }
  if (text.startsWith('100.64.') || text.startsWith('100.65.') || text.startsWith('100.66.') || text.startsWith('100.67.')) {
    return true;
  }
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(text)) return true;
  const lower = text.toLowerCase();
  if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe8') || lower.startsWith('fe9') ||
      lower.startsWith('fea') || lower.startsWith('feb')) {
    return true;
  }
  return false;
}

// 相手の名前を、少しの間だけ覚えておく。
// 同じ相手へ続けて投げるときに、毎回引き直さない。
function createResolver(options = {}) {
  const lookup = options.lookup || dns.promises.lookup;
  const ttl = options.ttl || 60 * 1000;
  const cache = new Map();
  return async function resolve(host) {
    const key = String(host || '').toLowerCase();
    if (!key) throw new Error('empty host');
    if (/^[\d.]+$/.test(key) || key.includes(':')) return key;
    const hit = cache.get(key);
    if (hit && hit.until > Date.now()) {
      if (hit.error) throw new Error(hit.error);
      return hit.address;
    }
    let result;
    try {
      const found = await lookup(key, { family: 4 });
      result = { address: found.address, until: Date.now() + ttl };
    } catch (err) {
      result = { error: err.message, until: Date.now() + Math.min(ttl, 10000) };
    }
    if (cache.size > 512) cache.clear();
    cache.set(key, result);
    if (result.error) throw new Error(result.error);
    return result.address;
  };
}

// 一つのまとまりに対して一つだけソケットを持ち、宛先ごとに送り分ける。
class UdpRelay {
  constructor(stream, options = {}) {
    this.stream = stream;
    this.log = options.log || (() => {});
    this.idleMs = options.idleMs || IDLE_MS;
    this.maxBuffered = options.maxBuffered || 2 * 1024 * 1024;
    this.resolve = options.resolve || createResolver();
    this.blocked = options.blocked || isPrivateAddress;
    this.createSocket = options.createSocket || ((family) => dgram.createSocket(family === 6 ? 'udp6' : 'udp4'));
    this.decoder = new FrameDecoder();
    this.sockets = new Map();
    this.sendQueue = Promise.resolve();
    this.closed = false;
    this.timer = null;
    this.stats = { toRemote: 0, toClient: 0, dropped: 0 };
  }

  start() {
    this.stream.on('data', (chunk) => this.onData(chunk));
    this.stream.on('error', () => this.close());
    this.stream.on('close', () => this.close());
    this.stream.on('end', () => this.close());
    this.touch();
    return this;
  }

  touch() {
    if (this.closed) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.close(), this.idleMs);
    if (this.timer.unref) this.timer.unref();
  }

  onData(chunk) {
    if (this.closed) return;
    this.touch();
    const { frames, error } = this.decoder.push(chunk);
    if (error) {
      this.log(`[udp] frame error: ${error.message}`);
      this.close();
      return;
    }
    for (const frame of frames) this.queueSend(frame);
  }

  // 同じ相手への順番を入れ替えないよう、送る順に並べて処理する。
  queueSend(frame) {
    this.sendQueue = this.sendQueue.then(() => this.sendFrame(frame)).catch((err) => {
      this.log(`[udp] send failed: ${err.message}`);
    });
  }

  async sendFrame(frame) {
    if (this.closed) return;
    if (!frame.payload || frame.payload.length === 0) return;
    let ip;
    try {
      ip = await this.resolve(frame.host);
    } catch {
      this.stats.dropped += 1;
      return;
    }
    if (this.closed) return;
    if (!ip || this.blocked(ip)) {
      this.stats.dropped += 1;
      return;
    }
    const family = ip.includes(':') ? 6 : 4;
    const socket = this.socketFor(family);
    try {
      socket.send(frame.payload, frame.port, ip, (err) => {
        if (err) this.stats.dropped += 1;
        else this.stats.toRemote += 1;
      });
    } catch {
      this.stats.dropped += 1;
    }
  }

  socketFor(family) {
    const existing = this.sockets.get(family);
    if (existing) return existing;
    const socket = this.createSocket(family);
    socket.on('message', (msg, rinfo) => this.onMessage(rinfo, msg));
    socket.on('error', (err) => this.log(`[udp] socket error: ${err.message}`));
    this.sockets.set(family, socket);
    return socket;
  }

  onMessage(rinfo, msg) {
    if (this.closed || !msg || msg.length === 0) return;
    this.touch();
    let frame;
    try {
      frame = encodeFrame(rinfo.address, rinfo.port, msg);
    } catch {
      this.stats.dropped += 1;
      return;
    }
    // 受け手が詰まっているときは、古い分を捨てて先へ進む。
    if (this.stream.writableLength > this.maxBuffered) {
      this.stats.dropped += 1;
      return;
    }
    try {
      this.stream.write(frame);
      this.stats.toClient += 1;
    } catch {
      this.stats.dropped += 1;
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    for (const socket of this.sockets.values()) {
      try {
        socket.close();
      } catch {
        // すでに閉じている
      }
    }
    this.sockets.clear();
    this.log(`[udp] closed (up ${this.stats.toRemote} / down ${this.stats.toClient} / dropped ${this.stats.dropped})`);
    try {
      this.stream.destroy();
    } catch {
      // すでに切れている
    }
  }
}

module.exports = {
  MAX_PAYLOAD,
  UDP_REQUEST,
  TYPE_IPV4,
  TYPE_DOMAIN,
  TYPE_IPV6,
  FrameDecoder,
  UdpRelay,
  createResolver,
  decodeAddr,
  encodeAddr,
  encodeFrame,
  isPrivateAddress,
};
