'use strict';

const crypto = require('crypto');
const fs = require('fs');

function randomURLSafe(bytes) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function readFileSecure(file) {
  try {
    return fs.readFileSync(file);
  } catch {
    return null;
  }
}

function loadSessionSecret(file) {
  const existing = readFileSecure(file);
  if (existing && existing.length >= 32) return existing;
  const secret = crypto.randomBytes(32);
  fs.writeFileSync(file, secret, { mode: 0o600 });
  return secret;
}

function loadAppToken(file, provided) {
  if (provided) return provided;
  const existing = readFileSecure(file);
  if (existing && existing.toString().trim().length > 0) return existing.toString().trim();
  const token = `nctb_${randomURLSafe(24)}`;
  fs.writeFileSync(file, token, { mode: 0o600 });
  return token;
}

class Auth {
  constructor(config) {
    this.config = config;
    this.secret = loadSessionSecret(config.sessionSecretFile);
    this.appToken = loadAppToken(config.appTokenFile, config.authToken);
    this.pending = new Map();
  }

  get configured() {
    return Boolean(this.config.authApi && this.appToken);
  }

  // 途中でやめたサインインの情報が残り続けないようにする。
  rememberPending(state, verifier) {
    const now = Date.now();
    for (const [key, item] of this.pending) {
      if (now - item.at > 10 * 60 * 1000) this.pending.delete(key);
    }
    if (this.pending.size >= 1000) {
      const oldest = this.pending.keys().next();
      if (!oldest.done) this.pending.delete(oldest.value);
    }
    this.pending.set(state, { verifier, at: now });
  }

  takePending(state) {
    const item = this.pending.get(state);
    this.pending.delete(state);
    if (!item) return null;
    if (Date.now() - item.at > 10 * 60 * 1000) return null;
    return item.verifier;
  }

  signSession(user) {
    const payload = Buffer.from(JSON.stringify(user)).toString('base64url');
    const signature = crypto.createHmac('sha256', this.secret).update(payload).digest('base64url');
    return `${payload}.${signature}`;
  }

  readSession(req) {
    const cookie = req.headers.cookie || '';
    const match = cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith('nctb_session='));
    if (!match) return null;
    const value = decodeURIComponent(match.slice('nctb_session='.length));
    const dot = value.lastIndexOf('.');
    if (dot <= 0) return null;
    const payload = value.slice(0, dot);
    const signature = value.slice(dot + 1);
    const expected = crypto.createHmac('sha256', this.secret).update(payload).digest('base64url');
    const left = Buffer.from(signature);
    const right = Buffer.from(expected);
    if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) return null;
    try {
      const user = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      if (!user || !user.id) return null;
      return user;
    } catch {
      return null;
    }
  }

  redirectURI(req) {
    const host = req.headers.host || '';
    const forwarded = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    const loopback = host.startsWith('127.0.0.1') || host.startsWith('localhost');
    const scheme = forwarded || (loopback ? 'http' : 'https');
    return `${scheme}://${host}/bridge/auth/callback`;
  }

  async initiate(req) {
    const state = randomURLSafe(16);
    const verifier = randomURLSafe(32);
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    this.rememberPending(state, verifier);
    const body = {
      app_id: this.config.authAppId,
      name: 'NeConnect Bridge',
      api_token: this.appToken,
      redirect_uri: this.redirectURI(req),
      scopes: ['profile:read'],
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    };
    const response = await fetch(`${this.config.authApi}/initiate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'NeConnectBridge/1.0' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
    const result = await response.json().catch(() => ({}));
    if (!result.success || !result.auth_url) {
      throw new Error(result.error || 'authorization request failed');
    }
    return result.auth_url;
  }

  async exchange(state, code, req) {
    const verifier = this.takePending(state);
    if (!verifier || !code) throw new Error('invalid callback');
    const body = {
      app_id: this.config.authAppId,
      api_token: this.appToken,
      code,
      code_verifier: verifier,
    };
    if (req) body.redirect_uri = this.redirectURI(req);
    const response = await fetch(`${this.config.authApi}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'NeConnectBridge/1.0' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
    const result = await response.json().catch(() => ({}));
    if (!result.success || !result.user || !result.user.id) {
      throw new Error(result.error || 'token exchange failed');
    }
    return result.user;
  }
}

module.exports = { Auth, randomURLSafe };
