'use strict';
// M13 paths infra tests (framework-owned): mounts only the paths router on a
// throwaway express app with a fresh SQLite DB. Covers the certificate 403,
// the verify flow, prereq gating, unit functions, and no-em-dash rule.
// The full-app regression suite lives in tests/paths.test.js.
const assert = require('node:assert/strict');
const { describe, it, before, after } = require('node:test');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

const ROOT = path.join(__dirname, '..');
const CERT_PATH = path.join(ROOT, 'lib', 'certpng.js');

let tmpDir;
let base;
let server;
let pathsMod;

function client(baseUrl) {
  let cookie = '';
  async function req(method, url) {
    const res = await fetch(baseUrl + url, {
      method,
      redirect: 'manual',
      headers: cookie ? { cookie } : {},
    });
    const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of set) {
      const pair = c.split(';')[0];
      const name = pair.split('=')[0];
      cookie = cookie.split('; ').filter((p) => p && !p.startsWith(name + '=')).concat(pair).join('; ');
    }
    return { status: res.status, text: await res.text(), headers: res.headers };
  }
  return { get: (u) => req('GET', u) };
}

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

function fakeReq(flags) {
  return { session: { flags: Object.assign({}, flags) } };
}

describe('M13 paths framework', () => {
  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentrix-paths-test-'));
    // lib/db reads DB_PATH at load time: set it before the first require.
    process.env.DB_PATH = path.join(tmpDir, 'vulnlab.db');

    const express = require('express');
    const session = require('express-session');
    pathsMod = require('../paths/index');

    // Minimal registry: some steps resolve to real challenge links, the
    // rest fall back to the module index (tests both branches).
    pathsMod.setPathsRegistry([
      { id: 'xss', name: 'Cross-Site Scripting', vulns: [{ id: 'reflected', name: 'Reflected XSS', link: '/xss/reflected' }] },
      { id: 'sqli', name: 'SQL Injection', vulns: [{ id: 'login-bypass', name: 'Login Bypass', link: '/sqli/login-bypass' }] },
      { id: 'auth', name: 'Broken Authentication', vulns: [{ id: 'user-enum', name: 'User Enumeration', link: '/auth/user-enum' }] },
    ]);

    const app = express();
    app.use(session({ secret: 'paths-test-secret', resave: false, saveUninitialized: true }));
    // Test-only seeding hook: mark a challenge captured for this session.
    app.get('/__seed/:moduleId/:vulnId', (req, res) => {
      req.session.flags = req.session.flags || {};
      req.session.flags[`${req.params.moduleId}:${req.params.vulnId}`] = true;
      res.json({ ok: true });
    });
    app.use('/paths', pathsMod.router);

    const port = await freePort();
    base = `http://127.0.0.1:${port}`;
    await new Promise((resolve) => { server = app.listen(port, '127.0.0.1', resolve); });
  });

  after(async () => {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads path defs matching the contract', () => {
    assert.ok(pathsMod.paths.length >= 1, 'at least one path def loaded');
    for (const p of pathsMod.paths) {
      assert.ok(typeof p.id === 'string' && p.id.length, 'def has id');
      assert.ok(typeof p.name === 'string' && p.name.length, 'def has name');
      assert.ok(typeof p.tagline === 'string', 'def has tagline');
      assert.ok(typeof p.difficulty === 'string', 'def has difficulty');
      assert.ok(Array.isArray(p.prerequisites), 'def has prerequisites array');
      assert.ok(typeof p.description === 'string', 'def has description');
      assert.ok(Array.isArray(p.steps) && p.steps.length > 0, 'def has steps');
      for (const s of p.steps) {
        assert.ok(typeof s.moduleId === 'string' && typeof s.vulnId === 'string', 'step has moduleId/vulnId');
      }
    }
  });

  it('every prerequisite id resolves to a real path', () => {
    const ids = new Set(pathsMod.paths.map((p) => p.id));
    for (const p of pathsMod.paths) {
      for (const pre of p.prerequisites) {
        assert.ok(ids.has(pre), `prerequisite ${pre} of ${p.id} must be a real path`);
      }
    }
  });

  it('GET /paths lists every path with progress and prereq badges', async () => {
    const c = client(base);
    const { status, text } = await c.get('/paths');
    assert.equal(status, 200);
    for (const p of pathsMod.paths) {
      assert.ok(text.includes(p.name), `index lists ${p.name}`);
    }
    assert.ok(text.includes('Requires: Zero to Web Pentester'), 'prereq badge shown');
    assert.ok(text.includes('Locked: finish'), 'lock guidance shown');
    assert.ok(text.includes('/paths/zero-to-web-pentester'), 'lock links to the prerequisite path');
  });

  it('unknown path id returns 404 on every :id route', async () => {
    const c = client(base);
    for (const u of ['/paths/no-such-path', '/paths/no-such-path/certificate', '/paths/no-such-path/verify']) {
      const { status } = await c.get(u);
      assert.equal(status, 404, `${u} should 404`);
    }
  });

  it('GET /paths/:id shows steps with resolved and fallback links', async () => {
    const c = client(base);
    const { status, text } = await c.get('/paths/zero-to-web-pentester');
    assert.equal(status, 200);
    assert.ok(text.includes('/xss/reflected'), 'resolved challenge link present');
    assert.ok(text.includes('href="/misconfig"'), 'module-index fallback link present');
    assert.ok(text.includes('Not captured'), 'uncaptured status pill present');
  });

  it('GET /paths/:id/certificate returns 403 while the path is incomplete', async () => {
    const c = client(base);
    const { status, text } = await c.get('/paths/zero-to-web-pentester/certificate');
    assert.equal(status, 403);
    assert.ok(text.includes('not unlocked yet'), '403 page explains the lock');
  });

  it('prereq banner shows until the prerequisite path is complete', async () => {
    const c = client(base);
    const beforeRes = await c.get('/paths/api-hacker');
    assert.equal(beforeRes.status, 200);
    assert.ok(beforeRes.text.includes('Requires: Zero to Web Pentester'), 'detail page shows Requires badge');
    assert.ok(beforeRes.text.includes('Locked: finish'), 'banner shown when prereq unmet');

    const zero = pathsMod.paths.find((p) => p.id === 'zero-to-web-pentester');
    for (const s of zero.steps) await c.get(`/__seed/${s.moduleId}/${s.vulnId}`);
    const afterRes = await c.get('/paths/api-hacker');
    assert.ok(!afterRes.text.includes('Locked: finish'), 'banner gone when prereq met');
  });

  it('verify page rejects a wrong code and accepts the derived one', async () => {
    const c = client(base);
    const pageRes = await c.get('/paths/zero-to-web-pentester/verify');
    assert.equal(pageRes.status, 200);
    assert.ok(pageRes.text.includes('PTX-XXXXXXXX'), 'form present');

    const wrong = await c.get('/paths/zero-to-web-pentester/verify?code=PTX-DEADBEEF');
    assert.equal(wrong.status, 200);
    assert.ok(wrong.text.includes('not</b> a valid certificate code'), 'wrong code rejected');

    // Read install_id straight from this test DB and derive the expected code.
    const Database = require('better-sqlite3');
    const db = new Database(path.join(tmpDir, 'vulnlab.db'), { readonly: true });
    const row = db.prepare("SELECT value FROM meta WHERE key = 'install_id'").get();
    db.close();
    assert.ok(row && /^[0-9a-f]{32}$/.test(row.value), 'install_id minted as 32 hex chars');
    const expected = 'PTX-' + crypto.createHash('sha256')
      .update(row.value + ':zero-to-web-pentester')
      .digest('hex').slice(0, 8).toUpperCase();
    const right = await c.get('/paths/zero-to-web-pentester/verify?code=' + expected.toLowerCase());
    assert.ok(right.text.includes('Valid'), 'derived code validates (case-insensitively)');
  });

  it('certificate route degrades to 500 when lib/certpng.js is missing', async () => {
    const c = client(base);
    const zero = pathsMod.paths.find((p) => p.id === 'zero-to-web-pentester');
    for (const s of zero.steps) await c.get(`/__seed/${s.moduleId}/${s.vulnId}`);
    const { status, text } = await c.get('/paths/zero-to-web-pentester/certificate');
    if (fs.existsSync(CERT_PATH)) {
      assert.equal(status, 200, 'renderer present: expect a PNG');
      return;
    }
    assert.equal(status, 500);
    assert.ok(text.includes('renderer'), '500 page names the missing renderer');
  });

  it('pathProgress/pathComplete/prereqsMet behave on synthetic sessions', () => {
    const zero = pathsMod.paths.find((p) => p.id === 'zero-to-web-pentester');
    const apiHacker = pathsMod.paths.find((p) => p.id === 'api-hacker');
    const first = zero.steps[0];
    const req = fakeReq({ [`${first.moduleId}:${first.vulnId}`]: true });
    const prog = pathsMod.pathProgress(req, zero);
    assert.equal(prog.done, 1);
    assert.equal(prog.total, zero.steps.length);
    assert.equal(pathsMod.pathComplete(req, zero), false);
    assert.equal(pathsMod.prereqsMet(req, apiHacker), false);

    const all = {};
    for (const s of zero.steps) all[`${s.moduleId}:${s.vulnId}`] = true;
    const full = fakeReq(all);
    assert.equal(pathsMod.pathComplete(full, zero), true);
    assert.equal(pathsMod.prereqsMet(full, apiHacker), true);
  });

  it('verifyCodeFor is deterministic, path-bound, and install-bound', () => {
    const a1 = pathsMod.verifyCodeFor('zero-to-web-pentester');
    const a2 = pathsMod.verifyCodeFor('zero-to-web-pentester');
    assert.equal(a1, a2);
    assert.ok(/^PTX-[0-9A-F]{8}$/.test(a1), 'code has PTX- + 8 uppercase hex shape');
    assert.notEqual(a1, pathsMod.verifyCodeFor('api-hacker'), 'different paths get different codes');
    assert.equal(pathsMod.installFingerprint().length, 12, 'fingerprint is 12 chars');
  });

  it('prereq edge cases: no prereqs (array or missing prop) is met; unknown id stays locked', () => {
    const zero = pathsMod.paths.find((p) => p.id === 'zero-to-web-pentester');
    const req = fakeReq({});
    // Path with an empty prerequisites array: prerequisites trivially met.
    assert.equal(pathsMod.prereqsMet(req, zero), true, 'path with prerequisites: [] must be met');
    // Path def with no prerequisites property at all: also met.
    assert.equal(pathsMod.prereqsMet(req, { id: 'bare', steps: [{ moduleId: 'a', vulnId: 'b' }] }), true,
      'path def missing the prerequisites property must be met');
    // Unknown prerequisite id can never be complete: stays locked, never errors.
    assert.equal(pathsMod.prereqsMet(req, { id: 'odd', prerequisites: ['no-such-path'], steps: [{ moduleId: 'a', vulnId: 'b' }] }), false,
      'unknown prerequisite id must leave the path locked');
  });

  it('locked path still lists its steps and enter links (guidance, not a hard block)', async () => {
    const c = client(base);
    const api = pathsMod.paths.find((p) => p.id === 'api-hacker');
    const { status, text } = await c.get('/paths/api-hacker');
    assert.equal(status, 200);
    assert.ok(text.includes('Locked: finish'), 'lock banner shown');
    // All steps render even while locked, each with a working challenge link.
    const stepCount = (text.match(/aria-label="Step /g) || []).length;
    assert.equal(stepCount, api.steps.length, `expected all ${api.steps.length} steps listed while locked`);
    assert.ok(text.includes('Enter the challenge'), 'enter links still present while locked');
  });

  it('pathProgress edge cases: 0 done, all done, captured-twice is not double counted', () => {
    const zero = pathsMod.paths.find((p) => p.id === 'zero-to-web-pentester');
    const zeroProg = pathsMod.pathProgress(fakeReq({}), zero);
    assert.equal(zeroProg.done, 0, 'fresh session has 0 steps done');
    assert.equal(zeroProg.total, zero.steps.length, 'total equals step count');

    const all = {};
    for (const s of zero.steps) all[`${s.moduleId}:${s.vulnId}`] = true;
    const fullProg = pathsMod.pathProgress(fakeReq(all), zero);
    assert.equal(fullProg.done, fullProg.total, 'all steps captured: done equals total');
    assert.equal(pathsMod.pathComplete(fakeReq(all), zero), true, 'path is complete');

    // Session flags are a boolean map, so capturing the same challenge twice
    // (two awards, or two def steps pointing at it) never double counts:
    // each step contributes at most 1 to done.
    const dup = { id: 'dup', steps: [{ moduleId: 'x', vulnId: 'r' }, { moduleId: 'x', vulnId: 'r' }] };
    const dupProg = pathsMod.pathProgress(fakeReq({ 'x:r': true }), dup);
    assert.equal(dupProg.done, 2, 'each step counted once, not per award');
    assert.equal(dupProg.done <= dupProg.total, true, 'done never exceeds total');
    assert.equal(pathsMod.pathProgress(fakeReq({}), { id: 'empty' }).done, 0,
      'def with no steps array reports 0 done');
  });

  it('two clients: session progress is isolated (A completes 5 steps, B sees 0)', async () => {
    const a = client(base);
    const b = client(base);
    const zero = pathsMod.paths.find((p) => p.id === 'zero-to-web-pentester');

    for (let i = 0; i < 5; i++) {
      const s = zero.steps[i];
      const r = await a.get(`/__seed/${s.moduleId}/${s.vulnId}`);
      assert.equal(r.status, 200, 'seed capture ok');
    }

    const pageA = await a.get('/paths/zero-to-web-pentester');
    assert.equal(pageA.status, 200);
    assert.ok(pageA.text.includes('5/10'), 'client A sees its own progress 5/10');

    const pageB = await b.get('/paths/zero-to-web-pentester');
    assert.equal(pageB.status, 200);
    assert.ok(pageB.text.includes('0/10'), 'client B still sees 0/10 (sessions isolated)');
    // The lock a client earned is its own: A completed 5 of 10 so its prereq
    // is still unmet too, but give A a full completion and B must still be locked.
    for (let i = 5; i < zero.steps.length; i++) {
      const s = zero.steps[i];
      await a.get(`/__seed/${s.moduleId}/${s.vulnId}`);
    }
    const aApi = await a.get('/paths/api-hacker');
    assert.ok(!aApi.text.includes('Locked: finish'), 'client A unlocked the prereq banner');
    const bApi = await b.get('/paths/api-hacker');
    assert.ok(bApi.text.includes('Locked: finish'), 'client B still sees the locked banner');
  });

  it('framework files contain no em dashes', () => {
    const files = [
      path.join(ROOT, 'paths', 'index.js'),
      path.join(ROOT, 'paths', 'zero-to-web-pentester.js'),
      path.join(ROOT, 'paths', 'api-hacker.js'),
      path.join(ROOT, 'paths', 'authentication-assassin.js'),
      path.join(ROOT, 'tests', 'paths-infra.test.js'),
      path.join(ROOT, 'lib', 'db.js'),
    ];
    for (const f of files) {
      const content = fs.readFileSync(f, 'utf8');
      assert.ok(!content.includes('\u2014'), `${path.basename(f)} must not contain em dashes`);
    }
  });
});
