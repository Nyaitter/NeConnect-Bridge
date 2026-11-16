'use strict';

const crypto = require('crypto');
const { Duplex } = require('stream');

const TLS_HANDSHAKE = 0x16;
const TLS_MAJOR = 0x03;

class PeekSocket {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.ended = false;
    this.handlers = [];
    socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this.wake();
    });
    socket.on('end', () => {
      this.ended = true;
      this.wake();
    });
    socket.on('error', () => {
      this.ended = true;
      this.wake();
    });
  }

  wake() {
    const waiting = this.handlers;
    this.handlers = [];
    for (const handler of waiting) handler();
  }

  async need(count, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (this.buffer.length < count) {
      if (this.ended) throw new Error('connection closed');
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('timed out waiting for data');
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          const index = this.handlers.indexOf(handler);
          if (index >= 0) this.handlers.splice(index, 1);
          resolve();
        }, remaining);
        const handler = () => {
          clearTimeout(timer);
          resolve();
        };
        this.handlers.push(handler);
      });
    }
    return this.buffer.subarray(0, count);
  }

  take(count) {
    const out = this.buffer.subarray(0, count);
    this.buffer = this.buffer.subarray(count);
    return out;
  }

  toDuplex() {
    const socket = this.socket;
    const leftover = this.buffer;
    this.buffer = Buffer.alloc(0);
    const duplex = new Duplex({
      read: () => socket.resume(),
      write: (chunk, _encoding, callback) => socket.write(chunk, callback),
      final: (callback) => {
        socket.end();
        callback();
      },
      destroy: (err, callback) => {
        socket.destroy();
        callback(err);
      },
    });
    if (leftover.length > 0) duplex.push(leftover);
    socket.removeAllListeners('data');
    socket.on('data', (chunk) => {
      if (!duplex.push(chunk)) socket.pause();
    });
    socket.once('end', () => duplex.push(null));
    socket.once('error', (err) => duplex.destroy(err));
    socket.once('close', () => duplex.destroy());
    return duplex;
  }
}

function recordHeader(length) {
  const header = Buffer.alloc(5);
  header[0] = TLS_HANDSHAKE;
  header[1] = TLS_MAJOR;
  header[2] = 0x03;
  header.writeUInt16BE(length, 3);
  return header;
}

function looksLikeTLS(head) {
  return head.length >= 2 && head[0] === TLS_HANDSHAKE && head[1] === TLS_MAJOR;
}

async function acceptFakeHandshake(peek) {
  const head = await peek.need(5, 4000);
  if (!looksLikeTLS(head)) return false;
  const header = peek.take(5);
  const length = header.readUInt16BE(3);
  if (length <= 0 || length > 8192) throw new Error('invalid hello');
  await peek.need(length, 4000);
  peek.take(length);

  const body = crypto.randomBytes(160 + crypto.randomInt(120));
  body[0] = 0x03;
  body[1] = 0x03;
  peek.socket.write(Buffer.concat([recordHeader(body.length), body]));
  return true;
}

module.exports = { acceptFakeHandshake, PeekSocket };
