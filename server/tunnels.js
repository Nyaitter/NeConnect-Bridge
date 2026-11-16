'use strict';

const { spawn, execFileSync } = require('child_process');
const fs = require('fs');

const CLOUDFLARE_URL = /https:\/\/[a-zA-Z0-9.-]+\.trycloudflare\.com/;
const SERVEO_URL = /https:\/\/[a-zA-Z0-9.-]+\.(serveo\.net|serveousercontent\.com)/;
const LOCALHOST_RUN_URL = /https:\/\/[a-zA-Z0-9.-]+\.lhr\.life/;
const PINGGY_URL = /https:\/\/[a-zA-Z0-9.-]+\.pinggy\.(link|io)/;

const SSH_OPTIONS = ['-o', 'StrictHostKeyChecking=no', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30'];

function findCloudflared() {
  for (const candidate of ['/usr/local/bin/cloudflared', '/usr/bin/cloudflared']) {
    if (fs.existsSync(candidate)) return candidate;
  }
  try {
    return execFileSync('sh', ['-c', 'command -v cloudflared'], { encoding: 'utf8' }).trim() || null;
  } catch {
    return null;
  }
}

function watchOutput(child, pattern, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const scan = (chunk) => {
      const match = pattern.exec(String(chunk));
      if (match) finish(match[0]);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    child.stdout?.on('data', scan);
    child.stderr?.on('data', scan);
    child.on('exit', () => finish(null));
  });
}

class TunnelManager {
  constructor({ listenPort }) {
    this.listenPort = listenPort;
    this.tunnels = [];
    this.sequence = 0;
  }

  register(child, url) {
    const record = { child, url, startedAt: Date.now() };
    this.tunnels.push(record);
    while (this.tunnels.length > 3) {
      const old = this.tunnels.shift();
      old.child.kill('SIGKILL');
    }
    setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        // process already exited
      }
    }, 2 * 60 * 60 * 1000).unref();
    return record;
  }

  async tryCloudflared() {
    const binary = findCloudflared();
    if (!binary) return null;
    const child = spawn(binary, ['tunnel', '--url', `http://127.0.0.1:${this.listenPort}`], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const url = await watchOutput(child, CLOUDFLARE_URL, 12000);
    if (!url) {
      child.kill('SIGKILL');
      return null;
    }
    this.register(child, url);
    return { url: `${url}/bridge/server`, provider: 'trycloudflare' };
  }

  async trySsh(pattern, provider, args) {
    const child = spawn('ssh', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const url = await watchOutput(child, pattern, 10000);
    if (!url) {
      child.kill('SIGKILL');
      return null;
    }
    this.register(child, url);
    return { url: `${url}/bridge/server`, provider };
  }

  tryServeo() {
    return this.trySsh(SERVEO_URL, 'serveo', [
      ...SSH_OPTIONS,
      '-R',
      `80:127.0.0.1:${this.listenPort}`,
      'serveo.net',
    ]);
  }

  tryLocalhostRun() {
    return this.trySsh(LOCALHOST_RUN_URL, 'localhost.run', [
      ...SSH_OPTIONS,
      '-R',
      `80:127.0.0.1:${this.listenPort}`,
      'nokey@localhost.run',
    ]);
  }

  tryPinggy() {
    return this.trySsh(PINGGY_URL, 'pinggy', [
      '-p',
      '443',
      ...SSH_OPTIONS,
      '-R0:127.0.0.1:' + this.listenPort,
      'a.pinggy.io',
    ]);
  }

  async spawnTunnel() {
    const providers = [() => this.tryCloudflared(), () => this.tryServeo(), () => this.tryLocalhostRun(), () => this.tryPinggy()];
    const start = this.sequence % providers.length;
    this.sequence += 1;
    for (let i = 0; i < providers.length; i += 1) {
      const provider = providers[(start + i) % providers.length];
      const result = await provider();
      if (result) return result;
    }
    throw new Error('failed to generate tunnel URL');
  }

  active() {
    return this.tunnels.map((tunnel) => ({
      url: tunnel.url,
      started_at: new Date(tunnel.startedAt).toISOString(),
    }));
  }

  closeAll() {
    for (const tunnel of this.tunnels) {
      try {
        tunnel.child.kill('SIGKILL');
      } catch {
        // process already exited
      }
    }
    this.tunnels = [];
  }
}

module.exports = { TunnelManager };
