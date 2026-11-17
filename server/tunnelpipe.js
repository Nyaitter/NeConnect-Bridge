'use strict';

const { Duplex } = require('stream');

class TunnelPipe {
  constructor(sid) {
    this.sid = sid;
    this.chunks = [];
    this.waiters = [];
    this.closed = false;
    this.stream = new Duplex({
      read: () => {},
      write: (chunk, _encoding, callback) => {
        this.chunks.push(chunk);
        this.flush();
        callback();
      },
      final: (callback) => {
        this.closed = true;
        this.flush();
        callback();
      },
      destroy: (err, callback) => {
        this.closed = true;
        this.flush();
        callback(err);
      },
    });
    this.stream.on('close', () => {
      this.closed = true;
      this.flush();
    });
  }

  flush() {
    while (this.waiters.length > 0 && this.chunks.length > 0) {
      this.waiters.shift()(this.chunks.shift());
    }
    while (this.waiters.length > 0 && this.closed) {
      this.waiters.shift()(null);
    }
  }

  next(timeoutMs) {
    if (this.chunks.length > 0) return Promise.resolve(this.chunks.shift());
    if (this.closed) return Promise.resolve(null);
    if (timeoutMs <= 0) return Promise.resolve(undefined);
    return new Promise((resolve) => {
      const deliver = (chunk) => {
        clearTimeout(timer);
        resolve(chunk);
      };
      const timer = setTimeout(() => {
        const index = this.waiters.indexOf(deliver);
        if (index >= 0) this.waiters.splice(index, 1);
        resolve(undefined);
      }, timeoutMs);
      this.waiters.push(deliver);
    });
  }

  fromClient(chunk) {
    if (this.closed || chunk.length === 0) return;
    this.stream.push(chunk);
  }

  close() {
    if (this.closed) return;
    this.stream.push(null);
    this.closed = true;
    this.flush();
  }
}

module.exports = { TunnelPipe };
