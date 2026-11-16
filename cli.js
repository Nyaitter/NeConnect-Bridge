#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname);

function usage() {
  return [
    '使い方: nctb <コマンド> [指定] [オプション]',
    '',
    '  list              登録済みのブリッジURLを一覧します',
    '  add <URL>         ブリッジURLを登録します',
    '  remove <URL>      ブリッジURLを取り消します',
    '  reset [URL]       使用回数を戻します。URLを省くとすべて戻します',
    '  status            サーバーの状態を表示します',
    '  set-max <数>      URLごとに受け入れる人数を変えます',
    '',
    'オプション:',
    '  --server <URL>    サーバーの場所。既定は http://127.0.0.1:8090',
    '  --data-dir <パス> 管理用の設定があるフォルダ。既定はこのプログラムのフォルダ',
  ].join('\n');
}

function parse(argv) {
  const options = { server: process.env.NCTB_SERVER || 'http://127.0.0.1:8090', dataDir: ROOT };
  const rest = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--server') {
      i += 1;
      options.server = argv[i];
    } else if (arg === '--data-dir') {
      i += 1;
      options.dataDir = path.resolve(argv[i]);
    } else {
      rest.push(arg);
    }
  }
  return { options, rest };
}

function readToken(dataDir) {
  try {
    const token = fs.readFileSync(path.join(dataDir, '.admin_token'), 'utf8').trim();
    if (token) return token;
  } catch {
    // reported below
  }
  throw new Error('.admin_token が見つかりません。サーバーを起動したフォルダを --data-dir で指定してください');
}

async function call(options, method, route, body) {
  const token = readToken(options.dataDir);
  const response = await fetch(`${options.server.replace(/\/+$/, '')}${route}`, {
    method,
    headers: { 'x-nctb-admin': token, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const text = await response.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (!response.ok) throw new Error(data.error || `サーバーが ${response.status} を返しました`);
  return data;
}

function formatDate(seconds) {
  if (!seconds) return '';
  const date = new Date(seconds * 1000);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

async function main() {
  const { options, rest } = parse(process.argv.slice(2));
  const command = rest[0];
  if (options.help || !command) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  if (command === 'list') {
    const status = await call(options, 'GET', '/bridge/api/admin/status');
    if (status.bridges.length === 0) {
      process.stdout.write('登録されているブリッジURLはありません。\n');
      return;
    }
    for (const bridge of status.bridges) {
      const owner = bridge.owner_handle ? ` @${bridge.owner_handle}` : '';
      const added = formatDate(bridge.added_at);
      process.stdout.write(`${bridge.url}  使用 ${bridge.used} / ${bridge.max}${owner}${added ? `  ${added}` : ''}\n`);
    }
    return;
  }

  if (command === 'add') {
    const url = rest[1];
    if (!url) throw new Error('URLを指定してください');
    const result = await call(options, 'POST', '/bridge/api/admin/add', { url });
    process.stdout.write(result.duplicate ? 'すでに登録されています。\n' : '登録しました。\n');
    return;
  }

  if (command === 'remove') {
    const url = rest[1];
    if (!url) throw new Error('URLを指定してください');
    await call(options, 'POST', '/bridge/api/admin/remove', { url });
    process.stdout.write('取り消しました。\n');
    return;
  }

  if (command === 'reset') {
    const url = rest[1];
    const result = await call(options, 'POST', '/bridge/api/admin/reset', url ? { url } : {});
    process.stdout.write(`${result.reset} 件の使用回数を戻しました。\n`);
    return;
  }

  if (command === 'set-max') {
    const value = Number(rest[1]);
    if (!Number.isInteger(value) || value < 1) throw new Error('1以上の数を指定してください');
    const result = await call(options, 'POST', '/bridge/api/admin/max', { value });
    process.stdout.write(`URLごとの人数を ${result.max_clients} にしました。\n`);
    return;
  }

  if (command === 'status') {
    const status = await call(options, 'GET', '/bridge/api/admin/status');
    const latest = status.releases.length > 0 ? status.releases[0].version : 'なし';
    process.stdout.write(`稼働 ${status.uptime_seconds} 秒\n`);
    process.stdout.write(`受付 ${status.listen}\n`);
    process.stdout.write(`URLごとの人数 ${status.max_clients}\n`);
    process.stdout.write(`登録済みのブリッジURL ${status.bridges.length} 件\n`);
    process.stdout.write(`配布中のバージョン ${latest}\n`);
    if (status.tunnels.length > 0) {
      for (const tunnel of status.tunnels) process.stdout.write(`臨時の接続先 ${tunnel.url}\n`);
    }
    return;
  }

  throw new Error(`不明なコマンドです: ${command}`);
}

main().catch((err) => {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
});
