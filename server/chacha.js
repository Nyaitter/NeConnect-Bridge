'use strict';

const SIGMA = Buffer.from('expand 32-byte k', 'latin1');

function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function quarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 7);
}

function initialState(key, counter, nonce, nonceWords) {
  const s = new Uint32Array(16);
  s[0] = SIGMA.readUInt32LE(0);
  s[1] = SIGMA.readUInt32LE(4);
  s[2] = SIGMA.readUInt32LE(8);
  s[3] = SIGMA.readUInt32LE(12);
  for (let i = 0; i < 8; i += 1) s[4 + i] = key.readUInt32LE(i * 4);
  if (nonceWords) {
    for (let i = 0; i < 4; i += 1) s[12 + i] = nonceWords[i];
  }
  if (counter !== null) {
    s[12] = counter >>> 0;
    s[13] = nonce.readUInt32LE(0);
    s[14] = nonce.readUInt32LE(4);
    s[15] = nonce.readUInt32LE(8);
  }
  return s;
}

function rounds(s) {
  const x = Uint32Array.from(s);
  for (let i = 0; i < 10; i += 1) {
    quarterRound(x, 0, 4, 8, 12);
    quarterRound(x, 1, 5, 9, 13);
    quarterRound(x, 2, 6, 10, 14);
    quarterRound(x, 3, 7, 11, 15);
    quarterRound(x, 0, 5, 10, 15);
    quarterRound(x, 1, 6, 11, 12);
    quarterRound(x, 2, 7, 8, 13);
    quarterRound(x, 3, 4, 9, 14);
  }
  return x;
}

function block(key, counter, nonce) {
  const s = initialState(key, counter, nonce, null);
  const x = rounds(s);
  const out = Buffer.alloc(64);
  for (let i = 0; i < 16; i += 1) out.writeUInt32LE((x[i] + s[i]) >>> 0, i * 4);
  return out;
}

function hchacha20(key, nonce16) {
  const words = new Uint32Array(4);
  for (let i = 0; i < 4; i += 1) words[i] = nonce16.readUInt32LE(i * 4);
  const s = initialState(key, null, null, words);
  const x = rounds(s);
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i += 1) out.writeUInt32LE(x[i], i * 4);
  for (let i = 0; i < 4; i += 1) out.writeUInt32LE(x[12 + i], 16 + i * 4);
  return out;
}

class ChaCha20Stream {
  constructor(key, nonce) {
    if (key.length !== 32) throw new Error('chacha20 key must be 32 bytes');
    if (nonce.length === 24) {
      this.key = hchacha20(key, nonce.subarray(0, 16));
      this.nonce = Buffer.concat([Buffer.alloc(4), nonce.subarray(16, 24)]);
    } else if (nonce.length === 12) {
      this.key = Buffer.from(key);
      this.nonce = Buffer.from(nonce);
    } else {
      throw new Error('chacha20 nonce must be 12 or 24 bytes');
    }
    this.counter = 0;
    this.keystream = null;
    this.offset = 64;
  }

  xor(input) {
    const out = Buffer.allocUnsafe(input.length);
    let done = 0;
    while (done < input.length) {
      if (this.offset >= 64) {
        this.keystream = block(this.key, this.counter, this.nonce);
        this.counter = (this.counter + 1) >>> 0;
        this.offset = 0;
      }
      const take = Math.min(64 - this.offset, input.length - done);
      for (let i = 0; i < take; i += 1) {
        out[done + i] = input[done + i] ^ this.keystream[this.offset + i];
      }
      this.offset += take;
      done += take;
    }
    return out;
  }
}

module.exports = { ChaCha20Stream, hchacha20, block };
