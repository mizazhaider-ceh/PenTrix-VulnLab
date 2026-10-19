'use strict';
// Shared helpers for the regression suite: boots the real app as a child
// process on a free port against a throwaway database, and gives each test a
// cookie-jar client that behaves like one student's browser.
const { spawn } = require('node:child_process');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

const ROOT = path.join(__dirname, '..');
const FLAG_RE = /PENTRIX\{[0-9a-f]{32}\}/g;
const EXPECTED_MODULES = 29;
const EXPECTED_CHALLENGES = 201;

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

async function startServer(dataDir) {
  const port = await freePort();
  const child = spawn(process.execPath, ['app.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(port), DB_PATH: path.join(dataDir, 'vulnlab.db'), SESSION_SECRET: 'test-only-secret' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  child.stdout.on('data', (d) => { log += d; });
  child.stderr.on('data', (d) => { log += d; });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw new Error(`server exited early:\n${log}`);
    try { await fetch(base + '/'); break; } catch { await new Promise((r) => setTimeout(r, 100)); }
    if (i === 99) throw new Error(`server did not start:\n${log}`);
  }
  return { base, log: () => log, stop: () => new Promise((resolve) => { child.once('exit', resolve); child.kill(); }) };
}

// One instance == one student browser (own cookie jar).
function client(base) {
  let cookie = '';
  async function req(method, url, { form, json, headers } = {}) {
    const res = await fetch(base + url, {
      method,
      redirect: 'manual',
      headers: {
        ...(cookie ? { cookie } : {}),
        ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
        ...(json ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
      body: form ? new URLSearchParams(form).toString() : json ? JSON.stringify(json) : undefined,
    });
    const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of set) {
      const pair = c.split(';')[0];
      const name = pair.split('=')[0];
      cookie = cookie.split('; ').filter((p) => p && !p.startsWith(name + '=')).concat(pair).join('; ');
    }
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, text, body, headers: res.headers };
  }
  return {
    get: (url, headers) => req('GET', url, { headers }),
    post: (url, form, headers) => req('POST', url, { form, headers }),
    postJson: (url, json, headers) => req('POST', url, { json, headers }),
    patchJson: (url, json, headers) => req('PATCH', url, { json, headers }),
    cookie: () => cookie,
    setCookie: (c) => { cookie = c; },
  };
}

async function scoreOf(c) {
  const { text } = await c.get('/scoreboard');
  const m = text.match(/<b>(\d+) \/ (\d+)<\/b> flags/);
  assert.ok(m, 'scoreboard total not found');
  return { got: Number(m[1]), total: Number(m[2]) };
}

// Which challenges this student has captured, from the scoreboard page.
async function capturedSet(c) {
  const { text } = await c.get('/scoreboard');
  return text.split('<section class="sb-module"').slice(1).flatMap((sec) => {
    const mod = (sec.match(/<a href="\/(\w+)">/) || [])[1];
    return [...sec.matchAll(/data-key="captured">\s*<td>[\s\S]*?<\/td><td><b>(.*?)<\/b>/g)].map((m) => `${mod}:${m[1]}`);
  });
}

function flagFromDb(dataDir, modId, vulnId) {
  const Database = require('better-sqlite3');
  const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
  const row = db.prepare('SELECT flag FROM flags WHERE module_id = ? AND vuln_id = ?').get(modId, vulnId);
  db.close();
  return row.flag;
}

// Boots a server on a fresh temp data dir; call cleanup() when done.
async function bootLab(t) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentrix-test-'));
  const srv = await startServer(dataDir);
  t.after(async () => {
    await srv.stop();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  return { srv, dataDir };
}

module.exports = {
  ROOT, FLAG_RE, EXPECTED_MODULES, EXPECTED_CHALLENGES,
  freePort, startServer, client, scoreOf, capturedSet, flagFromDb, bootLab,
};
