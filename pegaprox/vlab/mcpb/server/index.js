#!/usr/bin/env node
// MOAVI Desk MCP - the Claude Desktop extension's server (moavi-desk.mcpb, pegaprox/api/vlab_mcp.py).
// Claude Desktop runs it with its own Node: it reads JSON-RPC messages from stdin (one per line), sends
// each to the MOAVI Desk MCP server (POST /api/vlab/mcp) and writes the answers to stdout. No packages.
//   MOAVI_DESK_URL    https://<server>/api/vlab/mcp
//   MOAVI_DESK_TOKEN  mcp_... (플랫폼 설정 > MCP 연동)
//   MOAVI_DESK_CA     optional: the server's certificate (a self-signed one: https://<server>/moavi-gateway.crt)
'use strict';
const fs = require('fs');
const http = require('http');
const https = require('https');
const readline = require('readline');

// an optional field left empty can arrive as the placeholder itself
const env = (k) => {
  const v = (process.env[k] || '').trim();
  return v.startsWith('${') ? '' : v;
};
const URL_ = env('MOAVI_DESK_URL');
const TOKEN = env('MOAVI_DESK_TOKEN');
const CA = env('MOAVI_DESK_CA');

function log(msg) {
  process.stderr.write(`[moavi-desk] ${msg}\n`);
}

function out(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

function fail(id, message) {
  if (id !== undefined && id !== null) out({ jsonrpc: '2.0', id, error: { code: -32000, message } });
}

if (!URL_ || !TOKEN) {
  log('MOAVI_DESK_URL and MOAVI_DESK_TOKEN are required (the extension settings)');
}

let target = null;
let agent;
try {
  target = new URL(URL_);
  if (target.protocol === 'https:') {
    agent = new https.Agent({ keepAlive: true, ca: CA ? fs.readFileSync(CA) : undefined });
  }
} catch (e) {
  log(`bad server settings: ${e.message}`);
}

function send(line, id) {
  return new Promise((resolve) => {
    if (!target || !TOKEN) {
      fail(id, 'MOAVI Desk: set the server address and the token in the extension settings');
      return resolve();
    }
    const body = Buffer.from(line, 'utf8');
    const lib = target.protocol === 'https:' ? https : http;
    const req = lib.request(target, {
      method: 'POST', agent, timeout: 300000,
      headers: {
        'Content-Type': 'application/json', 'Content-Length': body.length,
        Accept: 'application/json, text/event-stream', Authorization: `Bearer ${TOKEN}`,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode === 202 || !text.trim()) return resolve();
        let data = null;
        try { data = JSON.parse(text); } catch { /* not JSON */ }
        if (res.statusCode >= 400) {
          fail(id, `MOAVI Desk HTTP ${res.statusCode}: ${(data && data.error) || text.slice(0, 200)}`);
        } else if (data) {
          out(data);
        } else {
          fail(id, 'MOAVI Desk answered something that is not JSON');
        }
        resolve();
      });
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', (e) => {
      const hint = /self.signed|unable to verify|certificate/i.test(e.message)
        ? ' - choose the server certificate (moavi-gateway.crt) in the extension settings' : '';
      fail(id, `MOAVI Desk unreachable: ${e.message}${hint}`);
      resolve();
    });
    req.end(body);
  });
}

// one request at a time, in order: answers keep the order of the questions
let chain = Promise.resolve();
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  line = line.trim();
  if (!line) return;
  let id;
  try { id = JSON.parse(line).id; } catch { /* the server says it */ }
  chain = chain.then(() => send(line, id));
});
rl.on('close', () => { chain.then(() => process.exit(0)); });
