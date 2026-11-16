'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const { WebSocketServer } = require('ws');

const { loadConfig } = require('./config');
const { BridgePool } = require('./pool');
const { ReleaseStore } = require('./versions');
const { Auth, randomURLSafe } = require('./auth');
const { TunnelManager } = require('./tunnels');
const { TunnelPipe } = require('./tunnelpipe');
const { acceptFakeHandshake, PeekSocket } = require('./tlsmask');
const {
  joinStreams,
  readExactly,
  SocketDuplex,
  wrapObfs,
  wrapServerAead,
  WsDuplex,
} = require('./streams');

const config = loadConfig(process.argv.slice(2));

function log(message) {
  process.stdout.write(`[${new Date().toISOString()}] ${message}\n`);
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function readSecretFile(file) {
  try {
    const value = fs.readFileSync(file, 'utf8').trim();
    return value.length > 0 ? value : '';
  } catch {
    return '';
  }
}

function loadE2EKey(file) {
  const raw = readSecretFile(file);
  if (!raw) fail(`鍵ファイルが見つかりません: ${file}`);
  const key = Buffer.from(raw, 'base64');
  if (key.length !== 32) fail(`鍵ファイルの形式が正しくありません: ${file}`);
  return key;
}

const e2eKey = loadE2EKey(config.e2eKeyFile);
const obfsPassphrase = readSecretFile(config.obfsSecretFile);
const obfsKey = obfsPassphrase ? crypto.createHash('sha256').update(obfsPassphrase).digest() : null;

const pool = new BridgePool(config.bridgesFile, config.maxClients);
const releases = new ReleaseStore({
  releasesDir: config.releasesDir,
  fallbackExe: config.clientExe,
  fallbackVersion: config.clientVersion,
});
const auth = new Auth(config);
const tunnels = new TunnelManager({ listenPort: config.listenPort });

const homeHTML = fs.readFileSync(path.join(__dirname, 'home.html'));
const dashboardHTML = fs.readFileSync(path.join(__dirname, 'dashboard.html'));

function loadAdminToken() {
  const existing = readSecretFile(config.adminTokenFile);
  if (existing) return existing;
  const token = crypto.randomBytes(24).toString('hex');
  fs.writeFileSync(config.adminTokenFile, token, { mode: 0o600 });
  return token;
}
const adminToken = loadAdminToken();

let obfsServerRef = null;

function challengeProof(challenge) {
  return crypto.createHmac('sha256', auth.secret).update(`nctb-verify:${challenge}`).digest('hex');
}

function parseAddress(value) {
  const idx = value.lastIndexOf(':');
  if (idx < 0) return { host: value, port: 0 };
  return { host: value.slice(0, idx), port: Number(value.slice(idx + 1)) };
}

class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function connect(address, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(parseAddress(address));
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('connect timeout'));
    }, timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.setNoDelay(true);
      resolve(socket);
    });
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function bridgeToLocalSsh(stream, tag) {
  try {
    if (!obfsKey) {
      throw new Error('obfs secret is not configured');
    }
    const wrapped = await wrapObfs(stream, obfsKey);
    const socket = await connect(config.localSsh, 5000);
    log(`[${tag}] bridged to ${config.localSsh}`);
    joinStreams(wrapped, new SocketDuplex(socket));
  } catch (err) {
    log(`[${tag}] bridge failed: ${err.message}`);
    stream.destroy();
  }
}

async function handleStream(stream, highSpeed) {
  let remote;
  let target = '';
  try {
    const header = await readExactly(stream, 2);
    const length = header.readUInt16BE(0);
    if (length <= 0 || length > 1024) throw new Error('invalid target frame');
    target = (await readExactly(stream, length)).toString('utf8');
    remote = await connect(target, 10000);
  } catch (err) {
    log(`[stream] dial failed target="${target}" speed=${highSpeed}: ${err.message}`);
    try {
      stream.write(Buffer.from([1]));
    } catch {
      // the connection is already gone
    }
    stream.destroy();
    return;
  }
  log(`[stream] open ${target} speed=${highSpeed}`);
  stream.write(Buffer.from([0]));
  const socketStream = new SocketDuplex(remote);
  remote.on('close', (hadError) => {
    log(`[stream] remote closed ${target}${hadError ? ' with error' : ''}`);
  });
  stream.on('error', (err) => {
    log(`[stream] stream error ${target}: ${err.message}`);
  });
  joinStreams(stream, socketStream);
}

const tunnelSessions = new Map();

const MAX_TUNNEL_SESSIONS = 2048;

function pruneTunnelSessions() {
  if (tunnelSessions.size <= MAX_TUNNEL_SESSIONS) return;
  for (const [key, pipe] of tunnelSessions) {
    if (tunnelSessions.size <= MAX_TUNNEL_SESSIONS) break;
    if (pipe.closed) tunnelSessions.delete(key);
  }
}

function openTunnel(sid, tag) {
  let pipe = tunnelSessions.get(sid);
  if (pipe) return pipe;
  pruneTunnelSessions();
  pipe = new TunnelPipe(sid);
  tunnelSessions.set(sid, pipe);
  pipe.stream.on('close', () => {
    if (tunnelSessions.get(sid) === pipe) tunnelSessions.delete(sid);
  });
  bridgeToLocalSsh(pipe.stream, tag);
  return pipe;
}

async function handlePoll(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const sid = url.searchParams.get('sid') || '';
  const op = url.searchParams.get('op') || '';
  if (!sid) {
    res.writeHead(400).end('missing sid');
    return;
  }

  if (op === 'open' && req.method === 'POST') {
    log(`[poll:${sid}] open`);
    openTunnel(sid, `poll:${sid}`);
    res.writeHead(200).end();
    return;
  }

  const pipe = tunnelSessions.get(sid);
  if (!pipe) {
    res.writeHead(410).end('session gone');
    return;
  }

  if (op === 'close' && req.method === 'POST') {
    pipe.close();
    res.writeHead(200).end();
    return;
  }

  if (req.method === 'POST') {
    const body = await readBody(req, 4 * 1024 * 1024);
    if (body.length > 0) pipe.fromClient(body);
    res.writeHead(200).end();
    return;
  }

  if (req.method === 'GET') {
    const first = await pipe.next(20000);
    if (first === null) {
      res.writeHead(410).end('session closed');
      return;
    }
    if (first === undefined) {
      res.writeHead(204).end();
      return;
    }
    const parts = [first];
    while (pipe.chunks.length > 0) parts.push(pipe.chunks.shift());
    res.writeHead(200, { 'content-type': 'application/octet-stream' }).end(Buffer.concat(parts));
    return;
  }

  res.writeHead(405).end('method not allowed');
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > limit) {
        settled = true;
        reject(new RequestError(413, 'body too large'));
        req.pause();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });
    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
    req.on('aborted', () => {
      if (settled) return;
      settled = true;
      reject(new RequestError(400, 'request aborted'));
    });
  });
}

async function readJSON(req, limit) {
  const body = await readBody(req, limit);
  const text = body.toString('utf8').trim();
  if (text === '') return {};
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('object expected');
    }
    return value;
  } catch {
    throw new RequestError(400, '入力が不正です');
  }
}


function extractMultipart(body, contentType) {
  const match = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType || '');
  if (!match) return Buffer.alloc(0);
  const boundary = `--${match[1] || match[2]}`;
  const start = body.indexOf(Buffer.from(`${boundary}\r\n`));
  if (start < 0) return Buffer.alloc(0);
  const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), start);
  if (headerEnd < 0) return Buffer.alloc(0);
  const payloadStart = headerEnd + 4;
  const payloadEnd = body.indexOf(Buffer.from(`\r\n${boundary}`), payloadStart);
  if (payloadEnd < 0) return Buffer.alloc(0);
  return body.subarray(payloadStart, payloadEnd);
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let value = i;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[i] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngFrame(payload) {
  const width = 1;
  const ihdr = Buffer.alloc(25);
  ihdr.writeUInt32BE(13, 0);
  ihdr.write('IHDR', 4, 'latin1');
  ihdr.writeUInt32BE(width, 8);
  ihdr.writeUInt32BE(width, 12);
  ihdr[16] = 8;
  ihdr[17] = 2;
  ihdr[18] = 0;
  ihdr[19] = 0;
  ihdr[20] = 0;
  ihdr.writeUInt32BE(crc32(ihdr.subarray(4, 21)), 21);
  const iend = Buffer.alloc(12);
  iend.writeUInt32BE(0, 0);
  iend.write('IEND', 4, 'latin1');
  iend.writeUInt32BE(0xae426082, 8);
  return Buffer.concat([PNG_SIGNATURE, ihdr, payload, iend]);
}

async function handleEventStream(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const sid = (url.searchParams.get('sid') || '').trim();
  if (!sid) {
    res.writeHead(400).end('missing sid');
    return;
  }
  const pipe = openTunnel(sid, `sse:${sid}`);
  log(`[sse:${sid}] open`);
  res.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'x-accel-buffering': 'no',
  });
  res.write(': open\n\n');
  const ping = setInterval(() => {
    if (!res.writableEnded) res.write(': ping\n\n');
  }, 15000);
  let active = true;
  req.on('close', () => {
    active = false;
    clearInterval(ping);
    pipe.close();
    const current = tunnelSessions.get(sid);
    if (current === pipe) tunnelSessions.delete(sid);
  });
  while (active && !res.writableEnded) {
    const chunk = await pipe.next(20000);
    if (chunk === null) break;
    if (chunk === undefined) continue;
    res.write(`data: ${chunk.toString('base64')}\n\n`);
  }
  clearInterval(ping);
  if (!res.writableEnded) res.end();
}

async function handleUpload(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const sid = (url.searchParams.get('sid') || '').trim();
  if (req.method !== 'POST') {
    res.writeHead(405).end('method not allowed');
    return;
  }
  const pipe = tunnelSessions.get(sid);
  if (!pipe) {
    res.writeHead(410).end('session gone');
    return;
  }
  const body = await readBody(req, 8 * 1024 * 1024);
  const data = extractMultipart(body, req.headers['content-type']);
  if (data.length > 0) pipe.fromClient(data);
  res.writeHead(200).end();
}

async function handleAsset(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const sid = (url.searchParams.get('sid') || '').trim();
  if (!sid) {
    res.writeHead(400).end('missing sid');
    return;
  }
  const pipe = openTunnel(sid, `asset:${sid}`);
  const cookie = req.headers.cookie || '';
  const match = /(?:^|;\s*)nctb=([A-Za-z0-9_-]+)/.exec(cookie);
  if (match) {
    try {
      pipe.fromClient(Buffer.from(match[1], 'base64url'));
    } catch {
      // malformed payloads are ignored
    }
  }
  const chunk = await pipe.next(1200);
  const payload = chunk && chunk !== null ? chunk : Buffer.alloc(0);
  const body = pngFrame(payload);
  res.writeHead(200, {
    'content-type': 'image/png',
    'cache-control': 'no-store, no-transform',
    'content-length': body.length,
  });
  res.end(body);
}

function json(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': payload.length });
  res.end(payload);
}

function html(res, body) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(body);
}

function normalizeBridgeURL(raw) {
  let value = String(raw || '').trim();
  if (!value) throw new Error('ブリッジURLを入力してください');
  if (!value.includes('://')) value = `https://${value}`;
  if (!/^(https?|ssh):\/\//.test(value)) {
    throw new Error('https で始まるURLを入力してください');
  }
  return value;
}

async function verifyBridgeURL(raw) {
  if (raw.startsWith('ssh://')) throw new Error('https で始まるURLを入力してください');
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('URLの形式が正しくありません');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new Error('URLの形式が正しくありません');
  const challenge = randomURLSafe(16);
  parsed.searchParams.set('challenge', challenge);
  let response;
  try {
    response = await fetch(parsed.toString(), {
      headers: { 'user-agent': 'NeConnectBridge-Check/1.0' },
      signal: AbortSignal.timeout(6000),
    });
  } catch {
    throw new Error('サーバーへ接続できませんでした');
  }
  if (response.status !== 200) throw new Error('ブリッジURLを確認できませんでした');
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error('ブリッジURLを確認できませんでした');
  }
  const expected = challengeProof(challenge);
  if (result.service !== 'NeConnect Bridge Server' || result.status !== 'ok' || result.proof !== expected) {
    throw new Error('このブリッジURLは登録できません');
  }
}

function requireAdmin(req, res) {
  if (req.headers['x-nctb-admin'] !== adminToken) {
    json(res, 401, { ok: false, error: 'unauthorized' });
    return false;
  }
  return true;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  try {
    if (pathname === '/bridge/server') {
      const payload = {
        service: 'NeConnect Bridge Server',
        status: 'ok',
        modes: ['secure', 'balance', 'speed'],
      };
      const challenge = (url.searchParams.get('challenge') || '').trim();
      if (challenge) payload.proof = challengeProof(challenge);
      json(res, 200, payload);
      return;
    }

    if (pathname === '/bridge/versions') {
      const all = releases.list();
      json(res, 200, {
        latest: all.length > 0 ? all[0].version : null,
        versions: all.map((item) => ({ version: item.version, size: item.size, released_at: item.released_at })),
      });
      return;
    }

    if (pathname === '/bridge/download' || pathname === '/bridge/NeConnectBridge.exe') {
      const requested = (url.searchParams.get('version') || '').trim();
      const release = releases.resolve(requested);
      if (!release) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('release not found');
        return;
      }
      const filename = requested ? `NeConnectBridge-${release.version}.exe` : path.basename(release.file);
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-disposition': `attachment; filename="${filename}"`,
        'content-length': release.size,
      });
      fs.createReadStream(release.file).pipe(res);
      return;
    }

    if (pathname === '/bridge/server-bin') {
      let stat;
      try {
        stat = fs.statSync(config.serverBin);
      } catch {
        res.writeHead(404).end('not found');
        return;
      }
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-disposition': 'attachment; filename="nctb-server"',
        'content-length': stat.size,
      });
      fs.createReadStream(config.serverBin).pipe(res);
      return;
    }

    if (pathname === '/bridge/generate' || pathname === '/bridge/request') {
      let cid = (url.searchParams.get('cid') || '').trim();
      if (!cid) {
        const remote = req.socket.remoteAddress || '';
        cid = `ip:${remote.replace(/^::ffff:/, '')}`;
      }
      const picked = pool.pick(cid);
      if (picked) {
        log(`[request] served registered bridge ${picked} to ${cid}`);
        json(res, 200, { ok: true, url: picked, provider: 'registered' });
        return;
      }
      log(`[request] pool exhausted for ${cid}, spawning temporary tunnel`);
      try {
        const tunnel = await tunnels.spawnTunnel();
        log(`[request] issued ${tunnel.url} via ${tunnel.provider} to ${cid}`);
        json(res, 200, { ok: true, url: tunnel.url, provider: tunnel.provider });
      } catch (err) {
        json(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    if (pathname === '/bridge/register') {
      if (req.method !== 'POST') {
        res.writeHead(405).end('method not allowed');
        return;
      }
      const user = auth.readSession(req);
      if (!user) {
        json(res, 401, { ok: false, error: 'Nyaitter でサインインしてください' });
        return;
      }
      const body = await readJSON(req, 4096);
      let normalized;
      try {
        normalized = normalizeBridgeURL(body.url);
        await verifyBridgeURL(normalized);
      } catch (err) {
        json(res, 400, { ok: false, error: err.message });
        return;
      }
      const added = pool.add({
        url: normalized,
        ownerId: user.id,
        ownerHandle: user.handle,
        ownerName: user.name,
      });
      if (added.duplicate) {
        json(res, 200, { ok: true, url: normalized, duplicate: true });
        return;
      }
      log(`[register] added bridge ${normalized}`);
      json(res, 200, { ok: true, url: normalized });
      return;
    }

    if (pathname === '/bridge/auth/login') {
      if (!auth.configured) {
        res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' }).end('NyaitterAuth is not configured');
        return;
      }
      try {
        const target = await auth.initiate(req);
        res.writeHead(302, { location: target }).end();
      } catch (err) {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' }).end(`NyaitterAuth error: ${err.message}`);
      }
      return;
    }

    if (pathname === '/bridge/auth/callback') {
      try {
        const user = await auth.exchange(url.searchParams.get('state') || '', url.searchParams.get('code') || '', req);
        const cookie = [
          `nctb_session=${auth.signSession(user)}`,
          'Path=/',
          'HttpOnly',
          'SameSite=Lax',
          `Max-Age=${86400 * 30}`,
        ].join('; ');
        res.writeHead(302, { 'set-cookie': cookie, location: '/bridge/dashboard' }).end();
      } catch (err) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }).end(err.message);
      }
      return;
    }

    if (pathname === '/bridge/auth/me') {
      const user = auth.readSession(req);
      json(res, 200, user ? { logged_in: true, user } : { logged_in: false });
      return;
    }

    if (pathname === '/bridge/auth/logout') {
      res.writeHead(200, { 'set-cookie': 'nctb_session=; Path=/; HttpOnly; Max-Age=0' }).end();
      return;
    }

    if (pathname === '/bridge/api/my-bridges') {
      const user = auth.readSession(req);
      if (!user) {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' }).end('unauthorized');
        return;
      }
      const items = pool.listOwned(user.id).map((entry) => ({
        url: entry.url,
        used: entry.used,
        max: entry.max,
        active: entry.used < entry.max,
      }));
      json(res, 200, { items });
      return;
    }

    if (pathname === '/bridge/api/delete') {
      const user = auth.readSession(req);
      if (!user) {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' }).end('unauthorized');
        return;
      }
      const body = await readJSON(req, 4096);
      pool.removeOwned(String(body.url || ''), user.id);
      json(res, 200, { ok: true });
      return;
    }

    if (pathname === '/bridge/api/admin/status') {
      if (!requireAdmin(req, res)) return;
      json(res, 200, {
        ok: true,
        listen: config.listen,
        obfs: config.obfs,
        local_ssh: config.localSsh,
        max_clients: pool.maxClients,
        tunnels: tunnels.active(),
        bridges: pool.list(),
        releases: releases.list().map((item) => ({ version: item.version, size: item.size })),
        uptime_seconds: Math.round(process.uptime()),
      });
      return;
    }

    if (pathname === '/bridge/api/admin/add') {
      if (!requireAdmin(req, res)) return;
      const body = await readJSON(req, 65536);
      let normalized;
      try {
        normalized = normalizeBridgeURL(body.url);
        if (body.verify) await verifyBridgeURL(normalized);
      } catch (err) {
        json(res, 400, { ok: false, error: err.message });
        return;
      }
      const added = pool.add({ url: normalized });
      json(res, 200, { ok: true, url: normalized, duplicate: added.duplicate });
      return;
    }

    if (pathname === '/bridge/api/admin/remove') {
      if (!requireAdmin(req, res)) return;
      const body = await readJSON(req, 65536);
      const removed = pool.remove(String(body.url || ''));
      json(res, removed ? 200 : 404, { ok: removed });
      return;
    }

    if (pathname === '/bridge/api/admin/reset') {
      if (!requireAdmin(req, res)) return;
      const body = await readJSON(req, 65536);
      const count = pool.reset(body.url ? String(body.url) : '');
      json(res, 200, { ok: true, reset: count });
      return;
    }

    if (pathname === '/bridge/api/admin/max') {
      if (!requireAdmin(req, res)) return;
      const body = await readJSON(req, 65536);
      const value = Number(body.value);
      if (!Number.isInteger(value) || value < 1) {
        json(res, 400, { ok: false, error: '1以上の整数を指定してください' });
        return;
      }
      pool.setMax(value);
      json(res, 200, { ok: true, max_clients: value });
      return;
    }


    if (pathname === '/bridge/stream') {
      await handleEventStream(req, res);
      return;
    }

    if (pathname === '/bridge/upload') {
      await handleUpload(req, res);
      return;
    }

    if (pathname.startsWith('/bridge/assets/')) {
      await handleAsset(req, res);
      return;
    }

    if (pathname === '/bridge/poll') {
      await handlePoll(req, res);
      return;
    }

    if (pathname === '/bridge/dashboard') {
      html(res, dashboardHTML);
      return;
    }

    html(res, homeHTML);
  } catch (err) {
    if (err instanceof RequestError) {
      log(`[http] ${pathname} rejected: ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(err.status, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' }).end(err.message);
      } else {
        res.end();
      }
      req.resume();
      return;
    }
    log(`[http] ${pathname} failed: ${err.message}`);
    if (!res.headersSent) res.writeHead(500).end('internal error');
    else res.end();
  }
});

const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/bridge/server') {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    handleBridgeSocket(ws, url);
  });
});

async function handleBridgeSocket(ws, url) {
  const mode = (url.searchParams.get('mode') || '').trim().toLowerCase();
  const remote = `${ws._socket.remoteAddress || ''}:${ws._socket.remotePort || ''}`;
  const stream = new WsDuplex(ws);
  log(`[ws:${mode || 'default'}] connected from ${remote}`);

  if (mode === 'secure') {
    log(`[ws-secure] connected from ${remote}`);
    await bridgeToLocalSsh(stream, `ws-secure:${remote}`);
    return;
  }

  let secured;
  try {
    secured = await wrapServerAead(stream, e2eKey);
  } catch {
    stream.destroy();
    return;
  }
  await handleStream(secured, mode === 'speed');
}

if (config.obfs) {
  const obfsServer = net.createServer(async (socket) => {
    socket.setNoDelay(true);
    const peek = new PeekSocket(socket);
    try {
      const masked = await acceptFakeHandshake(peek);
      bridgeToLocalSsh(peek.toDuplex(), `obfs:${socket.remoteAddress || ''}${masked ? ':masked' : ''}`);
    } catch (err) {
      log(`obfs handshake failed: ${err.message}`);
      socket.destroy();
    }
  });
  obfsServer.listen(Number(parseAddress(config.obfs).port) || 8443, () => {
    log(`Obfs-SSH listening on ${config.obfs} to ${config.localSsh}`);
  });
  obfsServer.on('error', (err) => {
    log(`Obfs listen error on ${config.obfs}: ${err.message}`);
  });
  obfsServerRef = obfsServer;
}

server.listen(Number(config.listenPort) || 8090, () => {
  log(`NeConnect Bridge Server listening on ${config.listen}`);
});

// 中継の応答待ちで固まらないよう、待ち時間に上限を置く。
server.headersTimeout = 65 * 1000;
server.requestTimeout = 120 * 1000;
server.keepAliveTimeout = 65 * 1000;

process.on('SIGTERM', () => {
  tunnels.closeAll();
  if (obfsServerRef) obfsServerRef.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
});

process.on('unhandledRejection', (err) => {
  log(`[process] unhandled rejection: ${err && err.message ? err.message : err}`);
});
