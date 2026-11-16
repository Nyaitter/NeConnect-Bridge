#!/usr/bin/env node
'use strict';

// relay/index.js を単体で動く配布物にまとめる。
// 使い方: node tools/build-server-package.mjs --target https://bridge.example.com --out nctb-server

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
let target = '';
let out = 'nctb-server';
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--target') target = args[(i += 1)];
  else if (args[i] === '--out') out = args[(i += 1)];
}

if (!target) {
  process.stderr.write('中継先の URL を --target で指定してください\n');
  process.exit(1);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const relaySource = fs.readFileSync(path.join(root, 'relay', 'index.js'), 'utf8');
if (relaySource.includes('NCTB_RELAY_EOF')) {
  process.stderr.write('中継プログラムに埋め込めない文字列が含まれています\n');
  process.exit(1);
}

const script = `#!/bin/sh
# NeConnect Bridge 中継サーバー
set -e
DIR="\${TMPDIR:-/tmp}/nctb-relay-\$\$"
mkdir -p "$DIR"
trap 'rm -rf "$DIR"' EXIT
cat > "$DIR/relay.js" <<'NCTB_RELAY_EOF'
${relaySource}NCTB_RELAY_EOF
NCTB_RELAY_TARGET="\${NCTB_RELAY_TARGET:-${target}}" exec node "$DIR/relay.js" "$@"
`;

fs.writeFileSync(path.resolve(root, out), script, { mode: 0o755 });
process.stdout.write(`${path.resolve(root, out)} を作成しました\n`);
