'use strict';

const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (key === 'relay' || key === 'help' || next === undefined || next.startsWith('--')) {
      out[key] = true;
      continue;
    }
    i += 1;
    out[key] = next;
  }
  return out;
}

const flags = parseArgs(process.argv.slice(2));
if (flags.help) {
  process.stdout.write('使い方: nctb-server --relay [--listen :8090] [--relay-target <URL>]\n');
  process.exit(0);
}

const listen = flags.listen || process.env.NCTB_RELAY_LISTEN || ':8090';
const targetValue = flags['relay-target'] || process.env.NCTB_RELAY_TARGET || '';
if (!targetValue) {
  process.stderr.write('中継先を指定してください: --relay-target <URL>\n');
  process.exit(1);
}

const target = new URL(targetValue);
const isSecure = target.protocol === 'https:';
const targetPort = Number(target.port || (isSecure ? 443 : 80));
const targetPath = target.pathname.replace(/\/+$/, '');
const listenPort = Number(String(listen).slice(String(listen).lastIndexOf(':') + 1)) || 8090;

function joinPath(incoming) {
  if (!targetPath) return incoming;
  if (incoming.startsWith(targetPath)) return incoming;
  return targetPath + incoming;
}

const agent = isSecure
  ? new https.Agent({ keepAlive: true, maxSockets: 256 })
  : new http.Agent({ keepAlive: true, maxSockets: 256 });

const client = isSecure ? https : http;

const server = http.createServer((req, res) => {
  const headers = { ...req.headers, host: target.host };
  const proxyReq = client.request(
    {
      host: target.hostname,
      port: targetPort,
      method: req.method,
      path: joinPath(req.url),
      headers,
      agent,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res);
    },
  );
  proxyReq.on('error', () => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('中継先に接続できませんでした');
  });
  req.pipe(proxyReq);
});

server.on('upgrade', (req, socket, head) => {
  const upstream = isSecure
    ? tls.connect({ host: target.hostname, port: targetPort, servername: target.hostname, ALPNProtocols: ['http/1.1'] })
    : net.connect({ host: target.hostname, port: targetPort });

  const fail = () => socket.destroy();

  upstream.on(isSecure ? 'secureConnect' : 'connect', () => {
    const lines = [`${req.method} ${joinPath(req.url)} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      const value = name.toLowerCase() === 'host' ? target.host : req.rawHeaders[i + 1];
      lines.push(`${name}: ${value}`);
    }
    upstream.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length > 0) upstream.write(head);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });

  upstream.on('error', fail);
  socket.on('error', fail);
  upstream.on('close', fail);
  socket.on('close', () => upstream.destroy());
});

server.listen(listenPort, () => {
  process.stdout.write(`中継サーバーを ${listen} で起動しました。中継先: ${target.origin}${targetPath}\n`);
});
