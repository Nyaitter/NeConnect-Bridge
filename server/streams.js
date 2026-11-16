'use strict';

const crypto = require('crypto');
const net = require('net');
const { Duplex } = require('stream');
const { ChaCha20Stream } = require('./chacha');

function randomBytes(n) {
  return crypto.randomBytes(n);
}

function readExactly(stream, n) {
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const chunk = stream.read(n);
      if (!chunk) return;
      // 終端では要求より短い分だけ返ることがあるので、そのまま受け取らない。
      if (chunk.length < n) {
        cleanup();
        reject(new Error('stream closed'));
        return;
      }
      cleanup();
      resolve(chunk);
    };
    const onEnd = () => {
      cleanup();
      reject(new Error('stream closed'));
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error('stream closed'));
    };
    function cleanup() {
      stream.off('readable', attempt);
      stream.off('end', onEnd);
      stream.off('error', onError);
      stream.off('close', onClose);
    }
    stream.on('readable', attempt);
    stream.on('end', onEnd);
    stream.on('error', onError);
    stream.on('close', onClose);
    attempt();
  });
}

function joinStreams(a, b) {
  let closing = false;
  const abort = () => {
    if (closing) return;
    closing = true;
    a.destroy();
    b.destroy();
  };
  a.on('error', abort);
  b.on('error', abort);
  a.pipe(b);
  b.pipe(a);
  // 片側が閉じても、もう片側にたまっている書き込みを捨てないよう、
  // すぐには破棄せず流し切る猶予を置いてから閉じる。
  const settle = (peer) => {
    if (closing) return;
    const timer = setTimeout(() => {
      closing = true;
      try {
        peer.destroy();
      } catch {
        // already closed
      }
    }, 4000);
    if (timer.unref) timer.unref();
  };
  a.once('close', () => settle(b));
  b.once('close', () => settle(a));
}

class SocketDuplex extends Duplex {
  constructor(socket) {
    super();
    this.socket = socket;
    socket.setNoDelay(true);
    socket.on('data', (chunk) => {
      if (!this.push(chunk)) socket.pause();
    });
    socket.on('end', () => {
      if (!this.readableEnded) this.push(null);
    });
    socket.on('error', (err) => this.destroy(err));
    socket.on('close', () => {
      // 受信済みのデータを読み切ってから終わる。
      if (!this.readableEnded) this.push(null);
    });
  }

  _read() {
    this.socket.resume();
  }

  _write(chunk, _encoding, callback) {
    this.socket.write(chunk, callback);
  }

  _final(callback) {
    this.socket.end();
    callback();
  }

  _destroy(err, callback) {
    this.socket.destroy();
    callback(err);
  }
}

class WsDuplex extends Duplex {
  constructor(ws) {
    super();
    this.ws = ws;
    ws.on('message', (data) => {
      this.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
    });
    ws.on('close', () => {
      if (!this.readableEnded) this.push(null);
    });
    ws.on('error', (err) => this.destroy(err));
  }

  _read() {}

  _write(chunk, _encoding, callback) {
    if (this.ws.readyState !== this.ws.OPEN) {
      callback(new Error('websocket closed'));
      return;
    }
    this.ws.send(chunk, { binary: true }, (err) => callback(err));
  }

  _final(callback) {
    try {
      this.ws.close();
    } catch {
      // closing an already closed socket needs no handling
    }
    callback();
  }

  _destroy(err, callback) {
    try {
      this.ws.terminate();
    } catch {
      // terminating an already closed socket needs no handling
    }
    callback(err);
  }
}

function nonceFor(seq) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(seq), 4);
  return nonce;
}

function deriveKeys(shared, clientPub, isServer) {
  const k1 = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('c2s:'), shared, clientPub])).digest();
  const k2 = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('s2c:'), shared, clientPub])).digest();
  return isServer ? { readKey: k1, writeKey: k2 } : { readKey: k2, writeKey: k1 };
}

function rawToPublicKey(raw) {
  const prefix = Buffer.from('302a300506032b656e032100', 'hex');
  return crypto.createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' });
}

function rawToPrivateKey(raw) {
  const prefix = Buffer.from('302e020100300506032b656e04220420', 'hex');
  return crypto.createPrivateKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'pkcs8' });
}

function publicKeyToRaw(keyObject) {
  return keyObject.export({ format: 'der', type: 'spki' }).subarray(-32);
}

class AeadDuplex extends Duplex {
  constructor(inner, readKey, writeKey) {
    super();
    this.inner = inner;
    this.readKey = readKey;
    this.writeKey = writeKey;
    this.readSeq = 0;
    this.writeSeq = 0;
    this.pending = Buffer.alloc(0);
    inner.on('data', (chunk) => {
      this.pending = Buffer.concat([this.pending, chunk]);
      this.drain();
    });
    inner.on('end', () => {
      if (this.pending.length > 0) {
        this.destroy(new Error('encrypted stream ended mid-frame'));
        return;
      }
      if (!this.readableEnded) this.push(null);
    });
    inner.on('error', (err) => this.destroy(err));
    inner.on('close', () => {
      // 復号済みでまだ読み出されていないデータを捨てないよう、即座には破棄しない。
      if (!this.readableEnded) this.push(null);
    });
  }

  drain() {
    while (this.pending.length >= 4) {
      const length = this.pending.readUInt32BE(0);
      if (length <= 0 || length > 512 * 1024) {
        this.destroy(new Error('invalid encrypted frame length'));
        return;
      }
      if (this.pending.length < 4 + length) return;
      const body = this.pending.subarray(4, 4 + length);
      this.pending = this.pending.subarray(4 + length);
      this.readSeq += 1;
      let plain;
      try {
        const decipher = crypto.createDecipheriv('chacha20-poly1305', this.readKey, nonceFor(this.readSeq), {
          authTagLength: 16,
        });
        decipher.setAuthTag(body.subarray(body.length - 16));
        plain = Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()]);
      } catch {
        this.destroy(new Error('encrypted frame failed to authenticate'));
        return;
      }
      this.push(plain);
    }
  }

  _read() {}

  _write(chunk, _encoding, callback) {
    const frames = [];
    let offset = 0;
    while (offset < chunk.length) {
      const piece = chunk.subarray(offset, Math.min(offset + 64 * 1024, chunk.length));
      this.writeSeq += 1;
      const cipher = crypto.createCipheriv('chacha20-poly1305', this.writeKey, nonceFor(this.writeSeq), {
        authTagLength: 16,
      });
      const body = Buffer.concat([cipher.update(piece), cipher.final(), cipher.getAuthTag()]);
      const frame = Buffer.alloc(4 + body.length);
      frame.writeUInt32BE(body.length, 0);
      body.copy(frame, 4);
      frames.push(frame);
      offset += piece.length;
    }
    const payload = frames.length === 1 ? frames[0] : Buffer.concat(frames);
    if (!this.inner.write(payload)) {
      const done = () => {
        this.inner.off('drain', done);
        this.inner.off('close', done);
        callback();
      };
      this.inner.once('drain', done);
      this.inner.once('close', done);
      return;
    }
    callback();
  }

  _final(callback) {
    this.inner.end();
    callback();
  }

  _destroy(err, callback) {
    this.inner.destroy();
    callback(err);
  }
}

async function wrapClientAead(inner, serverPublicKey) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const clientPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const shared = crypto.diffieHellman({ privateKey, publicKey: rawToPublicKey(serverPublicKey) });
  inner.write(clientPub);
  const { readKey, writeKey } = deriveKeys(shared, clientPub, false);
  return new AeadDuplex(inner, readKey, writeKey);
}

async function wrapServerAead(inner, serverPrivateKey) {
  const clientPub = await readExactly(inner, 32);
  const shared = crypto.diffieHellman({
    privateKey: rawToPrivateKey(serverPrivateKey),
    publicKey: rawToPublicKey(clientPub),
  });
  const { readKey, writeKey } = deriveKeys(shared, clientPub, true);
  return new AeadDuplex(inner, readKey, writeKey);
}

class ObfsDuplex extends Duplex {
  constructor(inner, readCipher, writeCipher) {
    super();
    this.inner = inner;
    this.readCipher = readCipher;
    this.writeCipher = writeCipher;
    inner.on('data', (chunk) => this.push(readCipher.xor(chunk)));
    inner.on('end', () => {
      if (!this.readableEnded) this.push(null);
    });
    inner.on('error', (err) => this.destroy(err));
    inner.on('close', () => {
      if (!this.readableEnded) this.push(null);
    });
  }

  _read() {}

  _write(chunk, _encoding, callback) {
    this.inner.write(this.writeCipher.xor(chunk));
    callback();
  }

  _final(callback) {
    this.inner.end();
    callback();
  }

  _destroy(err, callback) {
    this.inner.destroy();
    callback(err);
  }
}

async function wrapObfs(inner, secret) {
  const sendNonce = randomBytes(24);
  const padLength = randomBytes(1)[0] & 0x3f;
  const pad = randomBytes(padLength);
  const writeCipher = new ChaCha20Stream(secret, sendNonce);
  const encodedPadLength = writeCipher.xor(Buffer.from([padLength]));
  inner.write(Buffer.concat([sendNonce, encodedPadLength, pad]));

  const header = await readExactly(inner, 25);
  const readCipher = new ChaCha20Stream(secret, header.subarray(0, 24));
  const readPadLength = readCipher.xor(Buffer.from([header[24]]))[0] & 0x3f;
  if (readPadLength > 0) await readExactly(inner, readPadLength);
  return new ObfsDuplex(inner, readCipher, writeCipher);
}

class PollDuplex extends Duplex {
  constructor(baseURL, sid, closed) {
    super();
    this.baseURL = baseURL;
    this.sid = sid;
    this.closed = closed;
    this.stopped = false;
    this.reading = false;
  }

  _read() {
    if (this.reading || this.stopped) return;
    this.reading = true;
    this.pump();
  }

  async pump() {
    while (!this.stopped) {
      let response;
      let body;
      try {
        response = await fetch(`${this.baseURL}?sid=${encodeURIComponent(this.sid)}`, {
          headers: { 'user-agent': USER_AGENT },
          signal: AbortSignal.timeout(30000),
        });
        body = Buffer.from(await response.arrayBuffer());
      } catch {
        if (this.stopped) return;
        this.reading = false;
        setTimeout(() => this._read(), 500);
        return;
      }
      if (response.status === 410) {
        this.reading = false;
        this.push(null);
        return;
      }
      if (response.status !== 200 && response.status !== 204) {
        this.reading = false;
        this.destroy(new Error(`poll read failed: ${response.status}`));
        return;
      }
      if (body.length > 0) {
        this.push(body);
        this.reading = false;
        return;
      }
    }
  }

  _write(chunk, _encoding, callback) {
    fetch(`${this.baseURL}?sid=${encodeURIComponent(this.sid)}`, {
      method: 'POST',
      headers: { 'user-agent': USER_AGENT, 'content-type': 'application/octet-stream' },
      body: chunk,
      signal: AbortSignal.timeout(30000),
    }).then(
      (response) => {
        if (response.status === 200) callback();
        else callback(new Error(`poll write failed: ${response.status}`));
      },
      (err) => callback(err),
    );
  }

  _final(callback) {
    this.stopped = true;
    fetch(`${this.baseURL}?sid=${encodeURIComponent(this.sid)}&op=close`, {
      method: 'POST',
      headers: { 'user-agent': USER_AGENT },
    }).catch(() => {});
    callback();
  }

  _destroy(err, callback) {
    this.stopped = true;
    callback(err);
  }
}

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

async function openPollTunnel(baseURL) {
  const sid = randomBytes(12).toString('hex');
  const response = await fetch(`${baseURL}?sid=${sid}&op=open`, {
    method: 'POST',
    headers: { 'user-agent': USER_AGENT },
    signal: AbortSignal.timeout(30000),
  });
  if (response.status !== 200) throw new Error(`poll open failed: ${response.status}`);
  return new PollDuplex(baseURL, sid, false);
}

module.exports = {
  AeadDuplex,
  joinStreams,
  openPollTunnel,
  publicKeyToRaw,
  rawToPrivateKey,
  rawToPublicKey,
  readExactly,
  SocketDuplex,
  USER_AGENT,
  wrapClientAead,
  wrapObfs,
  wrapServerAead,
  WsDuplex,
};
