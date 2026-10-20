'use strict';
// CSTI module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut (a bare beacon curl with no page
// load, a blocked delimiter, a wrong result, arbitrary constructor data, a
// replayed token, or a scraped share array). Tokens are never in the raw page
// source: the tests run each page's scripts in a vm sandbox (the honest
// browser simulation) to obtain the computed CSTI_NONCE.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

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

function decodeEntities(s) {
  return s
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

// Run a lab page's scripts the way a browser would and read back the token
// the page's own script computed at load.
async function pageToken(c, path) {
  const r = await c.get(path);
  assert.equal(r.status, 200, path);
  const badgeValue = (r.text.match(/id="badge"[^>]*value="([^"]*)"/) || [])[1];
  const calls = [];
  const el = (id) => {
    if (id === 'badge') {
      return { value: '', getAttribute: () => (badgeValue ? decodeEntities(badgeValue) : null) };
    }
    return { innerHTML: '', textContent: '', value: '' };
  };
  const ctx = {
    document: { getElementById: el, createElement: () => ({ className: '', innerHTML: '' }) },
    fetch: (u) => { calls.push(String(u)); return Promise.resolve({ json: () => Promise.resolve({ captured: false }) }); },
    URLSearchParams,
    decodeURIComponent,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  for (const code of liveScripts(r.text)) {
    try { vm.runInContext(code, ctx, { timeout: 1000 }); } catch (e) { /* a broken template is the student's problem */ }
  }
  const token = ctx.CSTI_NONCE;
  assert.match(token, /^[0-9a-f]{32}$/, 'page did not compute a page-bound token: ' + path);
  return { text: r.text, token, calls, ctx };
}

test('csti module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'csti', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/csti');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 5);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/csti/basic', '/csti/filter-bypass', '/csti/constructor', '/csti/attr', '/csti/stored']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
    // The module-level beacon route exists (400 without a token, not 404).
    assert.equal((await c.get('/csti/beacon')).status, 400);
  });

  await t.test('basic: bare beacon fails, the real template evaluation with the page token earns the flag', async () => {
    const c = client(srv.base);
    // The obvious shortcut: a bare beacon curl with no page load has no token.
    const bare = await c.get('/csti/beacon?v=basic&d=49');
    assert.equal(bare.status, 400);
    assert.ok(!bare.text.includes(flagOf('basic')), 'failure page must not leak the flag');
    // Benign greeting plus a guessed token: still no flag.
    await c.post('/csti/basic', { tpl: 'hello there' });
    assert.equal((await c.get('/csti/beacon?v=basic&d=49&n=deadbeef')).status, 400);
    // Scraped share arrays from the HTML are not usable as the token.
    const rawPage = await c.get('/csti/basic');
    const shares = rawPage.text.match(/__tkA=\[([0-9,]+)\]/);
    assert.ok(shares, 'share arrays must be present');
    assert.equal((await c.get(`/csti/beacon?v=basic&d=49&n=${encodeURIComponent(shares[1])}`)).status, 400);
    // The real exploit: save {{7*7}}, load the page for its token, beacon with it.
    await c.post('/csti/basic', { tpl: '{{7*7}}' });
    const { token } = await pageToken(c, '/csti/basic');
    assert.equal((await c.get('/csti/claim-status?v=basic')).body.captured, false);
    const hit = await c.get(`/csti/beacon?v=basic&d=49&n=${token}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('basic')));
    assert.ok((await capturedSet(c)).includes('csti:Basic Template Evaluation'));
    // The token is single-use: replaying it earns nothing.
    assert.equal((await c.get(`/csti/beacon?v=basic&d=49&n=${token}`)).status, 400);
  });

  await t.test('filter-bypass: {{ }} is blocked server-side, the [[ ]] delimiter earns the flag', async () => {
    const c = client(srv.base);
    // The obvious path is blocked by the naive blacklist.
    const blocked = await c.post('/csti/filter-bypass', { tpl: '{{7*7}}' });
    assert.equal(blocked.status, 400);
    assert.ok(blocked.text.includes('Blocked by the filter'));
    // The bypass: the client engine also evaluates [[ ]], which the filter never heard of.
    const { token } = await pageToken(c, '/csti/filter-bypass');
    await c.post('/csti/filter-bypass', { tpl: '[[7*7]]' });
    // A wrong result with a valid token still earns nothing.
    assert.equal((await c.get(`/csti/beacon?v=filter-bypass&d=48&n=${token}`)).status, 400);
    const hit = await c.get(`/csti/beacon?v=filter-bypass&d=49&n=${token}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('filter-bypass')));
    assert.ok((await capturedSet(c)).includes('csti:Filter Bypass via Alternative Delimiter'));
  });

  await t.test('constructor: arbitrary beacon data is rejected, the execution proof earns the flag', async () => {
    const c = client(srv.base);
    // No data and no token: nothing.
    assert.equal((await c.get('/csti/beacon?v=constructor')).status, 400);
    const { text, token, ctx } = await pageToken(c, '/csti/constructor');
    assert.ok(!text.includes(token), 'raw token must not appear in the page source');
    // Arbitrary non-empty data used to award here: now rejected even with a
    // valid page token.
    assert.equal((await c.get(`/csti/beacon?v=constructor&d=exfiltrated-data&n=${token}`)).status, 400);
    // Scraped shares are not the token either.
    assert.equal((await c.get('/csti/beacon?v=constructor&d=exfiltrated-data')).status, 400);
    // The real exploit: executing the template reaches Function and beacons
    // with the execution proof derived from the page token.
    const proof = 'ctor:' + ctx.cstiDjb2(token);
    const hit = await c.get(`/csti/beacon?v=constructor&d=${encodeURIComponent(proof)}&n=${token}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('constructor')));
    assert.ok((await capturedSet(c)).includes('csti:Constructor Breakout to Code Execution'));
  });

  await t.test('attr: entity-encoded badge text still evaluates, beacon with the token earns the flag', async () => {
    const c = client(srv.base);
    // Beacon with no page load never works.
    assert.equal((await c.get('/csti/beacon?v=attr&d=49')).status, 400);
    await c.post('/csti/attr', { tpl: '{{7*"7"}}' });
    const { text, token } = await pageToken(c, '/csti/attr');
    // The payload sits entity-encoded in the attribute source, yet evaluates client-side.
    assert.ok(text.includes('&quot;7&quot;'), 'badge value should be entity-encoded in the page source');
    const hit = await c.get(`/csti/beacon?v=attr&d=49&n=${token}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('attr')));
    assert.ok((await capturedSet(c)).includes('csti:CSTI Inside an HTML Attribute'));
  });

  await t.test('stored: direct beacons earn nothing, the victim-visit flow earns the flag', async () => {
    const c = client(srv.base);
    // An empty display name is rejected, no flag.
    assert.equal((await c.post('/csti/stored/profile', { name: '' })).status, 400);
    assert.ok(!(await capturedSet(c)).some((s) => s.startsWith('csti:')));
    // A victim visit with no stored template earns nothing.
    const idle = await c.get('/csti/stored/victim-visit');
    assert.equal(idle.status, 200);
    assert.ok(!idle.text.includes(flagOf('stored')));
    // A hand-fired beacon with a real page token is rejected for this lab.
    const { token } = await pageToken(c, '/csti/stored');
    assert.equal((await c.get(`/csti/beacon?v=stored&d=49&n=${token}`)).status, 400);
    // The real exploit: store the template as a display name, then a victim
    // visit evaluates it in the victim session and claims the flag.
    await c.post('/csti/stored/profile', { name: '{{7*7}}' });
    const hit = await c.get('/csti/stored/victim-visit');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('stored')));
    assert.ok((await capturedSet(c)).includes('csti:Stored Template in Profile Name'));
  });

  await t.test('scoreboard lists each captured challenge exactly once', async () => {
    const c = client(srv.base);
    async function capture(path, v, d) {
      const { token } = await pageToken(c, path);
      const hit = await c.get(`/csti/beacon?v=${v}&d=${encodeURIComponent(d)}&n=${token}`);
      assert.equal(hit.status, 200, v);
    }
    await capture('/csti/basic', 'basic', '49');
    await capture('/csti/filter-bypass', 'filter-bypass', '49');
    const ctor = await pageToken(c, '/csti/constructor');
    const ctorProof = 'ctor:' + ctor.ctx.cstiDjb2(ctor.token);
    const ctorHit = await c.get(`/csti/beacon?v=constructor&d=${encodeURIComponent(ctorProof)}&n=${ctor.token}`);
    assert.equal(ctorHit.status, 200, 'constructor');
    await capture('/csti/attr', 'attr', '49');
    await c.post('/csti/stored/profile', { name: '{{7*7}}' });
    const storedHit = await c.get('/csti/stored/victim-visit');
    assert.equal(storedHit.status, 200, 'stored');
    const got = (await capturedSet(c)).filter((s) => s.startsWith('csti:')).sort();
    assert.deepEqual(got, [
      'csti:Basic Template Evaluation',
      'csti:CSTI Inside an HTML Attribute',
      'csti:Constructor Breakout to Code Execution',
      'csti:Filter Bypass via Alternative Delimiter',
      'csti:Stored Template in Profile Name',
    ]);
  });
});

// ---------------------------------------------------------------------------
// A1B adversarial negatives (appended): constructor proof must be the exact
// hash of the page token, failed attempts must not consume the token, tokens
// are bound to one lab, and a winning beacon cannot be replayed.
// ---------------------------------------------------------------------------
test('csti A1B adversarial negatives', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'csti', id);

  await t.test('constructor: wrong execution proofs are rejected and consume nothing', async () => {
    const c = client(srv.base);
    const { token, ctx } = await pageToken(c, '/csti/constructor');
    const goodProof = 'ctor:' + ctx.cstiDjb2(token);
    const wrongProofs = [
      'ctor:' + ctx.cstiDjb2('some-other-string'),
      'ctor:',
      token,
      'ctor:' + ctx.cstiDjb2(token) + '00',
      '49',
    ];
    for (const d of wrongProofs) {
      const r = await c.get('/csti/beacon?v=constructor&d=' + encodeURIComponent(d) + '&n=' + token);
      assert.equal(r.status, 400, 'proof must be rejected: ' + d.slice(0, 24));
      assert.ok(!r.text.includes(flagOf('constructor')));
    }
    // The right proof with the wrong token also fails.
    assert.equal((await c.get('/csti/beacon?v=constructor&d=' + encodeURIComponent(goodProof) + '&n=deadbeef')).status, 400);
    // None of the failures consumed the token: the honest beacon still wins.
    const hit = await c.get('/csti/beacon?v=constructor&d=' + encodeURIComponent(goodProof) + '&n=' + token);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('constructor')));
    // And it cannot be replayed.
    assert.equal((await c.get('/csti/beacon?v=constructor&d=' + encodeURIComponent(goodProof) + '&n=' + token)).status, 400, 'replayed beacon must not award');
  });

  await t.test('cross-vuln token earns nothing and is not consumed', async () => {
    const c = client(srv.base);
    const { token } = await pageToken(c, '/csti/basic');
    assert.equal((await c.get('/csti/beacon?v=attr&d=49&n=' + token)).status, 400, 'basic token must not award attr');
    assert.equal((await c.get('/csti/beacon?v=filter-bypass&d=49&n=' + token)).status, 400, 'basic token must not award filter-bypass');
    const hit = await c.get('/csti/beacon?v=basic&d=49&n=' + token);
    assert.equal(hit.status, 200, 'cross-vuln attempts must not consume the token');
    assert.ok(hit.text.includes(flagOf('basic')));
  });
});

// ---------------------------------------------------------------------------
// Regression: stored victim-visit vm sandbox host escape (SUPERVISION_REPORT
// blocking item 2). The old sandbox injected host fetch, host
// encodeURIComponent and host console into the vm context, so a stored
// template could reach the host Function constructor and the host process
// (fetch.constructor('return typeof process')() returned "object"). The fix
// rebuilds the sandbox like lib/fix-worker.js: fresh vm context, every
// helper built INSIDE the guest context, zero host-realm values. Escape
// payloads must now stay in the guest realm (typeof process is "undefined")
// and earn nothing, while the honest {{7*7}} solve still awards.
// ---------------------------------------------------------------------------
test('csti stored vm sandbox host escape regression', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'csti', id);

  await t.test('escape payloads via fetch.constructor and encodeURIComponent.constructor earn nothing', async () => {
    const c = client(srv.base);
    const payloads = [
      "{{fetch.constructor('return typeof process')()}}",
      '{{encodeURIComponent.constructor("return typeof process")()}}',
      "{{fetch.constructor('return process')()}}",
    ];
    for (const p of payloads) {
      const r = await c.post('/csti/stored/profile', { name: p });
      assert.equal(r.status, 302, 'profile plant must redirect: ' + p.slice(0, 30));
    }
    const visit = await c.get('/csti/stored/victim-visit');
    assert.equal(visit.status, 200);
    assert.ok(!visit.text.includes(flagOf('stored')), 'escape payloads must not earn the flag');
    assert.ok(!(await capturedSet(c)).some((s) => s.startsWith('csti:')), 'escape payloads must not capture');
  });

  await t.test('guest realm cannot reach the host process (fixed sandbox shape)', async () => {
    // Mirror the fixed construction in modules/csti/challenges/stored.js:
    // fresh context, bootstrap built inside the guest, only strings out.
    const context = vm.createContext(Object.create(null));
    const bootstrap = new vm.Script(
      'var __beacons = [];\n' +
      'var console = { log: function () {}, warn: function () {}, error: function () {}, info: function () {}, debug: function () {} };\n' +
      'function fetch(u) { __beacons.push(String(u)); }\n' +
      'var document = {\n' +
      '  getElementById: function () { return { appendChild: function () {} }; },\n' +
      '  createElement: function () { return { className: \'\', innerHTML: \'\' }; }\n' +
      '};\n',
      { filename: 'test-csti-bootstrap.js' }
    );
    bootstrap.runInContext(context, { timeout: 2000 });
    const viaFetch = new vm.Script("fetch.constructor('return typeof process')()").runInContext(context, { timeout: 1000 });
    assert.equal(viaFetch, 'undefined', 'fetch.constructor must stay in guest realm, not reach host process');
    const viaEnc = new vm.Script("encodeURIComponent.constructor('return typeof process')()").runInContext(context, { timeout: 1000 });
    assert.equal(viaEnc, 'undefined', 'encodeURIComponent.constructor must stay in guest realm, not reach host process');
    const viaObj = new vm.Script("({}).constructor.constructor('return typeof process')()").runInContext(context, { timeout: 1000 });
    assert.equal(viaObj, 'undefined', 'guest Object chain must not reach host process');
    const guestFn = new vm.Script('Function').runInContext(context, { timeout: 1000 });
    assert.notEqual(guestFn, Function, 'guest Function must not be the host Function');
    const typeofProcess = new vm.Script('typeof process').runInContext(context, { timeout: 1000 });
    assert.equal(typeofProcess, 'undefined', 'guest must have no host process global');
  });

  await t.test('honest stored solve still awards after escape attempts', async () => {
    const c = client(srv.base);
    await c.post('/csti/stored/profile', { name: '{{7*7}}' });
    const hit = await c.get('/csti/stored/victim-visit');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('stored')), 'honest {{7*7}} must still award after the sandbox fix');
    assert.ok((await capturedSet(c)).includes('csti:Stored Template in Profile Name'));
  });
});
