'use strict';
// postmsg module: browser-side labs. The tests drive the server endpoints the
// victim pages' scripts call (the flag beacon), proving the intended flow
// earns the flag and the obvious shortcut earns nothing. Tokens are never in
// the raw page source: the tests run each victim page's scripts in a vm
// sandbox (the honest browser simulation) to obtain the computed values.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const VULNS = ['no-check', 'wildcard', 'data-xss', 'substring', 'csrf-action'];

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

// Execute a victim page's scripts and read the value its script computed.
function executePage(text, varName) {
  const ctx = {
    document: { getElementById: () => ({ style: {}, textContent: '', innerHTML: '' }) },
    addEventListener: () => {},
    fetch: () => Promise.resolve({ json: () => Promise.resolve({}) }),
    URLSearchParams,
    decodeURIComponent,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  for (const code of liveScripts(text)) {
    try { vm.runInContext(code, ctx, { timeout: 1000 }); } catch (e) { /* not every script matters here */ }
  }
  const value = ctx[varName];
  assert.match(value, /^[0-9a-f]{32}$/, 'victim page did not compute ' + varName);
  return value;
}

// The page-bound one-time token the victim page's script computes at load.
function pageNonce(text) {
  return executePage(text, 'PM_NONCE');
}

function secretToken(text) {
  return executePage(text, 'SECRET_TOKEN');
}

// Fire the token beacon for a prefix-match lab (victim page load first).
async function fireTokenBeacon(c, vulnId, payload) {
  const v = await c.get('/postmsg/' + vulnId);
  const d = encodeURIComponent(vulnId + ':' + payload);
  return c.get('/postmsg/beacon?v=' + vulnId + '&d=' + d + '&n=' + pageNonce(v.text));
}

test('postmsg module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'postmsg', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/postmsg');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 5);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of VULNS.flatMap((v) => ['/postmsg/' + v, '/postmsg/' + v + '/attacker'])) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
    for (const href of ['/postmsg/claim-status?v=no-check', '/postmsg/beacon']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
    // No flags leak before anything is captured.
    const before = await c.get('/postmsg/claim-status?v=no-check');
    assert.equal(before.body.captured, false);
  });

  await t.test('no-check: bare beacon earns nothing, victim page token earns the flag, token is single-use', async () => {
    const c = client(srv.base);
    const bare = await c.get('/postmsg/beacon?v=no-check&d=' + encodeURIComponent('no-check:<img src=x>'));
    assert.equal(bare.status, 400, 'bare beacon must not award');
    // The raw token never appears in the victim page source: only shares.
    const vpage = await c.get('/postmsg/no-check');
    assert.ok(!vpage.text.includes(pageNonce(vpage.text)), 'raw token must not appear in HTML');
    const hit = await fireTokenBeacon(c, 'no-check', '<img src=x>');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('no-check')));
    assert.ok((await capturedSet(c)).includes('postmsg:No Origin Check on Message Handler'));
    const status = await c.get('/postmsg/claim-status?v=no-check');
    assert.equal(status.body.captured, true);
    // A fresh client has no victim-page token, so its beacon fails too.
    const other = client(srv.base);
    const fail = await other.get('/postmsg/beacon?v=no-check&d=' + encodeURIComponent('no-check:x') + '&n=deadbeef');
    assert.equal(fail.status, 400, 'a guessed token must not award');
    // Scraped share arrays are not the token.
    const shares = vpage.text.match(/__tkA=\[([0-9,]+)\]/);
    assert.ok(shares, 'share arrays must be present');
    const forged = await other.get('/postmsg/beacon?v=no-check&d=' + encodeURIComponent('no-check:x') + '&n=' + encodeURIComponent(shares[1]));
    assert.equal(forged.status, 400, 'share array is not the token');
  });

  await t.test('wildcard: a guessed secret earns nothing, the broadcast secret earns the flag', async () => {
    const c = client(srv.base);
    const guess = await c.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:guessed-secret'));
    assert.equal(guess.status, 400, 'guessed secret must not award');
    const v = await c.get('/postmsg/wildcard');
    const secret = secretToken(v.text);
    assert.ok(!v.text.includes(secret), 'raw secret must not appear in HTML');
    const hit = await c.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + secret));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('wildcard')));
    assert.ok((await capturedSet(c)).includes('postmsg:Secret Leaked via Wildcard targetOrigin'));
  });

  await t.test('data-xss: unsanitized payload through the victim page earns the flag', async () => {
    const c = client(srv.base);
    const bare = await c.get('/postmsg/beacon?v=data-xss&d=' + encodeURIComponent("data-xss:<img src=x>"));
    assert.equal(bare.status, 400, 'bare beacon must not award');
    const hit = await fireTokenBeacon(c, 'data-xss', '<img src=x onerror=alert(1)>');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('data-xss')));
    assert.ok((await capturedSet(c)).includes('postmsg:Unsanitized Message Data Rendered as HTML'));
  });

  await t.test('substring: simulated attacker origin plus the victim page token earns the flag', async () => {
    const c = client(srv.base);
    // The origin check itself is client-side JavaScript; the server awards
    // only when the victim page that ran it echoes its page-bound token.
    const bare = await c.get('/postmsg/beacon?v=substring&d=' + encodeURIComponent('substring:pwned'));
    assert.equal(bare.status, 400, 'bare beacon must not award');
    const v = await c.get('/postmsg/substring?simulateOrigin=' + encodeURIComponent('https://pentrix.lab.evil.com'));
    assert.ok(v.text.includes('LAB SIMULATION'), 'attacker origin must be simulated');
    const hit = await c.get('/postmsg/beacon?v=substring&d=' + encodeURIComponent('substring:pwned via substring check') + '&n=' + pageNonce(v.text));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('substring')));
    assert.ok((await capturedSet(c)).includes('postmsg:Substring Origin Check Bypass'));
  });

  await t.test('csrf-action: bare delete plus beacon earns nothing, the victim script token flow earns the flag', async () => {
    const c = client(srv.base);
    const beacon = '/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted');
    const pre = await c.get(beacon);
    assert.equal(pre.status, 400, 'beacon without a deletion must not award');
    // The sanctioned cheat, verbatim: a bare client POSTs the delete and
    // then fires the beacon, with no browser and no JavaScript. The account
    // is deleted, but no victim page ever loaded, so there is no token and
    // the deletion does not count as message-driven.
    const del = await c.post('/postmsg/csrf-action/delete');
    assert.equal(del.status, 200);
    assert.equal(del.body.status, 'account deleted (lab only)');
    assert.equal((await c.get(beacon)).status, 400, 'bare curl delete plus beacon must not award');
    // Even a client that loaded the victim page and presents its token to
    // the beacon earns nothing when the delete itself was bare: the delete
    // request must also have presented the token, as the victim script does.
    const vpage = await c.get('/postmsg/csrf-action');
    const n = pageNonce(vpage.text);
    assert.ok(!vpage.text.includes(n), 'raw token must not appear in HTML');
    assert.equal((await c.get(beacon + '&n=' + n)).status, 400, 'beacon token without a token-driven deletion must not award');
    // The genuine flow, as the victim page's handler runs it: the delete
    // presents the page token, then the beacon echoes it.
    const del2 = await c.post('/postmsg/csrf-action/delete', { n });
    assert.equal(del2.status, 200);
    const hit = await c.get(beacon + '&n=' + n);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('csrf-action')));
    assert.ok((await capturedSet(c)).includes('postmsg:Privileged Action via Forged Message'));
    // The token is single-use: replaying the winning beacon earns nothing.
    assert.equal((await c.get(beacon + '&n=' + n)).status, 400, 'replayed beacon must not award');
    // The lab is replayable: resetting clears the deleted state, and a
    // fresh victim page token on its own still earns nothing after reset.
    await c.get('/postmsg/csrf-action/reset');
    const fresh = pageNonce((await c.get('/postmsg/csrf-action')).text);
    const after = await c.get(beacon + '&n=' + fresh);
    assert.equal(after.status, 400, 'beacon after reset must not award');
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await fireTokenBeacon(c, 'no-check', 'x');
    const w = await c.get('/postmsg/wildcard');
    await c.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + secretToken(w.text)));
    await fireTokenBeacon(c, 'data-xss', 'x');
    await fireTokenBeacon(c, 'substring', 'x');
    const cp = await c.get('/postmsg/csrf-action');
    const cn = pageNonce(cp.text);
    await c.post('/postmsg/csrf-action/delete', { n: cn });
    await c.get('/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted') + '&n=' + cn);
    let got = (await capturedSet(c)).filter((s) => s.startsWith('postmsg:'));
    assert.equal(got.length, 5);
    assert.equal(new Set(got).size, 5);
    // Re-capturing a lab must not duplicate its scoreboard entry.
    await fireTokenBeacon(c, 'no-check', 'x');
    got = (await capturedSet(c)).filter((s) => s.startsWith('postmsg:'));
    assert.equal(got.length, 5, 're-capture must not duplicate');
  });
});

// ---------------------------------------------------------------------------
// A1B adversarial negatives (appended): explicit beacon replay, cross-vuln
// token misuse, cross-session secret and deletion-state isolation.
// ---------------------------------------------------------------------------
test('postmsg A1B adversarial negatives', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'postmsg', id);

  await t.test('no-check: cross-vuln token fails without consuming; replay fails after the win', async () => {
    const c = client(srv.base);
    const v = await c.get('/postmsg/no-check');
    const n = pageNonce(v.text);
    const cross = await c.get('/postmsg/beacon?v=data-xss&d=' + encodeURIComponent('data-xss:x') + '&n=' + n);
    assert.equal(cross.status, 400, 'no-check token must not award data-xss');
    const url = '/postmsg/beacon?v=no-check&d=' + encodeURIComponent('no-check:x') + '&n=' + n;
    const hit = await c.get(url);
    assert.equal(hit.status, 200, 'cross-vuln attempt must not consume the token');
    assert.ok(hit.text.includes(flagOf('no-check')));
    assert.equal((await c.get(url)).status, 400, 'replayed beacon must not award');
  });

  await t.test('wildcard: one session secret is useless in another session', async () => {
    const a = client(srv.base);
    const b = client(srv.base);
    const secretA = secretToken((await a.get('/postmsg/wildcard')).text);
    assert.equal((await b.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + secretA))).status, 400, 'a secret broadcast to another session must not award');
    const secretB = secretToken((await b.get('/postmsg/wildcard')).text);
    assert.notEqual(secretB, secretA, 'sessions must have distinct secrets');
    assert.equal((await b.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + secretA))).status, 400, 'foreign secret must not award even after own page load');
    const hit = await b.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + secretB));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('wildcard')));
  });

  await t.test('csrf-action: the beacon only works in the session where the account was deleted', async () => {
    const a = client(srv.base);
    const b = client(srv.base);
    const beacon = '/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted');
    const na = pageNonce((await a.get('/postmsg/csrf-action')).text);
    const nb = pageNonce((await b.get('/postmsg/csrf-action')).text);
    const del = await a.post('/postmsg/csrf-action/delete', { n: na });
    assert.equal(del.status, 200);
    assert.equal((await b.get(beacon + '&n=' + nb)).status, 400, 'no deletion in this session: beacon must not award even with its own page token');
    const hit = await a.get(beacon + '&n=' + na);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('csrf-action')));
  });

  await t.test('csrf-action: header evidence alone earns nothing, with or without a foreign origin', async () => {
    const c = client(srv.base);
    const beacon = '/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted');
    // Same-site evidence on both requests: exactly what a student replaying
    // the flow in Repeater inside their own session produces.
    const delSame = await c.post('/postmsg/csrf-action/delete', undefined, { origin: srv.base, referer: srv.base + '/postmsg/csrf-action' });
    assert.equal(delSame.status, 200);
    assert.equal((await c.get(beacon, { referer: srv.base + '/postmsg/csrf-action' })).status, 400, 'same-site delete plus beacon must not award');
    // Foreign Origin and Referer headers are one header edit away in curl
    // or Repeater, so they cannot be the award evidence either: without
    // the victim page token on the delete and the beacon, they earn nothing.
    await c.get('/postmsg/csrf-action/reset');
    const delForeign = await c.post('/postmsg/csrf-action/delete', undefined, { origin: 'http://evil.example', referer: 'http://evil.example/attack.html' });
    assert.equal(delForeign.status, 200);
    assert.equal((await c.get(beacon, { origin: 'http://evil.example', referer: 'http://evil.example/attack.html' })).status, 400, 'foreign headers without the page token must not award');
    // A guessed token on both requests is likewise worth nothing, and the
    // failed guesses must not consume the real token.
    const vpage = await c.get('/postmsg/csrf-action');
    await c.post('/postmsg/csrf-action/delete', { n: 'deadbeefdeadbeefdeadbeefdeadbeef' });
    assert.equal((await c.get(beacon + '&n=deadbeefdeadbeefdeadbeefdeadbeef')).status, 400, 'guessed token must not award');
    const n = pageNonce(vpage.text);
    await c.post('/postmsg/csrf-action/delete', { n });
    const hit = await c.get(beacon + '&n=' + n);
    assert.equal(hit.status, 200, 'the genuine victim script flow must still award after failed guesses');
    assert.ok(hit.text.includes(flagOf('csrf-action')));
  });
});
