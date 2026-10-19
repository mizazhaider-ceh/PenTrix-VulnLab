'use strict';
// postmsg module: browser-side labs. The tests drive the server endpoints the
// victim pages' scripts call (the flag beacon), proving the intended flow
// earns the flag and the obvious shortcut earns nothing.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const VULNS = ['no-check', 'wildcard', 'data-xss', 'substring', 'csrf-action'];

// The page-bound one-time token the victim page renders in its own script.
function pageNonce(text) {
  const m = text.match(/var PM_NONCE = "([0-9a-f]{32})"/);
  assert.ok(m, 'victim page must render a page-bound token');
  return m[1];
}

function secretToken(text) {
  const m = text.match(/var SECRET_TOKEN = "([0-9a-f]{32})"/);
  assert.ok(m, 'victim page must render the secret token');
  return m[1];
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
  });

  await t.test('wildcard: a guessed secret earns nothing, the broadcast secret earns the flag', async () => {
    const c = client(srv.base);
    const guess = await c.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:guessed-secret'));
    assert.equal(guess.status, 400, 'guessed secret must not award');
    const v = await c.get('/postmsg/wildcard');
    const hit = await c.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + secretToken(v.text)));
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

  await t.test('csrf-action: forged message alone earns nothing, real deletion earns the flag', async () => {
    const c = client(srv.base);
    const pre = await c.get('/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted'));
    assert.equal(pre.status, 400, 'beacon without a deletion must not award');
    const del = await c.post('/postmsg/csrf-action/delete');
    assert.equal(del.status, 200);
    assert.equal(del.body.status, 'account deleted (lab only)');
    const hit = await c.get('/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted'));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('csrf-action')));
    assert.ok((await capturedSet(c)).includes('postmsg:Privileged Action via Forged Message'));
    // The lab is replayable: resetting clears the deleted state.
    await c.get('/postmsg/csrf-action/reset');
    const after = await c.get('/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted'));
    assert.equal(after.status, 400, 'beacon after reset must not award');
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await fireTokenBeacon(c, 'no-check', 'x');
    const w = await c.get('/postmsg/wildcard');
    await c.get('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + secretToken(w.text)));
    await fireTokenBeacon(c, 'data-xss', 'x');
    await fireTokenBeacon(c, 'substring', 'x');
    await c.post('/postmsg/csrf-action/delete');
    await c.get('/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted'));
    let got = (await capturedSet(c)).filter((s) => s.startsWith('postmsg:'));
    assert.equal(got.length, 5);
    assert.equal(new Set(got).size, 5);
    // Re-capturing a lab must not duplicate its scoreboard entry.
    await fireTokenBeacon(c, 'no-check', 'x');
    got = (await capturedSet(c)).filter((s) => s.startsWith('postmsg:'));
    assert.equal(got.length, 5, 're-capture must not duplicate');
  });
});
