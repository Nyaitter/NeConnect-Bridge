'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function readTrimmed(file) {
  try {
    return fs.readFileSync(file, 'utf8').trim();
  } catch {
    return '';
  }
}

function parseArgs(argv, spec) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    if (!(key in spec)) {
      throw new Error(`unknown option: --${key}`);
    }
    if (spec[key] === 'boolean') {
      out[key] = true;
    } else {
      i += 1;
      if (i >= argv.length) throw new Error(`missing value for --${key}`);
      out[key] = argv[i];
    }
  }
  return out;
}

function loadConfig(argv) {
  const flags = parseArgs(argv, {
    listen: 'string',
    obfs: 'string',
    'local-ssh': 'string',
    'ssh-host': 'string',
    'obfs-host': 'string',
    'releases': 'string',
    'max-clients': 'string',
    'data-dir': 'string',
    'auth-api': 'string',
    'auth-app-id': 'string',
    'auth-token': 'string',
    help: 'boolean',
  });

  const dataDir = path.resolve(flags['data-dir'] || process.env.NCTB_DATA_DIR || ROOT);
  const socketPort = (value, fallback) => {
    const idx = String(value || '').lastIndexOf(':');
    if (idx < 0) return fallback;
    return value.slice(idx + 1) || fallback;
  };

  return {
    dataDir,
    listen: flags.listen || process.env.NCTB_LISTEN || ':8090',
    listenPort: socketPort(flags.listen || process.env.NCTB_LISTEN || ':8090', '8090'),
    obfs: flags.obfs || process.env.NCTB_OBFS || ':8443',
    localSsh: flags['local-ssh'] || process.env.NCTB_LOCAL_SSH || '127.0.0.1:22',
    sshHost: flags['ssh-host'] || process.env.NCTB_SSH_HOST || '',
    obfsHost: flags['obfs-host'] || process.env.NCTB_OBFS_HOST || '',
    releasesDir: path.resolve(flags.releases || process.env.NCTB_RELEASES || path.join(dataDir, 'releases')),
    maxClients: Number(flags['max-clients'] || process.env.NCTB_MAX_CLIENTS || 5),
    authApi: (flags['auth-api'] || process.env.NCTB_AUTH_API || '').replace(/\/+$/, ''),
    authAppId: flags['auth-app-id'] || process.env.NCTB_AUTH_APP_ID || 'neconnect-bridge',
    authToken: (flags['auth-token'] || process.env.NCTB_AUTH_TOKEN || '').trim(),
    e2eKeyFile: process.env.NCTB_E2E_KEY_FILE || path.join(dataDir, 'e2e_key'),
    obfsSecretFile: process.env.NCTB_OBFS_SECRET_FILE || path.join(dataDir, 'obfs_secret'),
    sessionSecretFile: path.join(dataDir, '.session_secret'),
    appTokenFile: path.join(dataDir, '.nyaitter_app_token'),
    adminTokenFile: path.join(dataDir, '.admin_token'),
    bridgesFile: path.join(dataDir, 'bridges.json'),
    clientExe: path.join(dataDir, 'NeConnectBridge.exe'),
    serverBin: path.join(dataDir, 'releases', 'nctb-server'),
  };
}

module.exports = { loadConfig, readTrimmed };
