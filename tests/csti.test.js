'use strict';
// CSTI module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut (a bare beacon curl with no page
// load, a blocked delimiter, a wrong result, or a replayed token).
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// The page-bound one-time token, rendered into every lab page as CSTI_NONCE.
const NONCE_RE = /var CSTI_NONCE = "([0-9a-f]{32})"/;

async function pageToken(c, path) {
  const r = await c.get(path);
  assert.equal(r.status, 200, path);
  const m = r.text.match(NONCE_RE);
  assert.ok(m, 'page did not render a page-bound token: ' + path);
  return { text: r.text, token: m[1] };
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

  await t.test('constructor: manual beacon with data and the page token earns the flag', async () => {
    const c = client(srv.base);
    // No data and no token: nothing.
    assert.equal((await c.get('/csti/beacon?v=constructor')).status, 400);
    const { token } = await pageToken(c, '/csti/constructor');
    // Any non-empty data works, but the token must still be echoed.
    assert.equal((await c.get('/csti/beacon?v=constructor&d=exfiltrated-data')).status, 400);
    // The real exploit: a template reaching constructor.constructor to run code,
    // then beaconing manually with the page-bound token.
    await c.post('/csti/constructor', { tpl: '{{constructor.constructor("fetch(\'/csti/beacon?v=constructor&d=x&n=\'")()}}' });
    const hit = await c.get(`/csti/beacon?v=constructor&d=exfiltrated-data&n=${token}`);
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

  await t.test('stored: stored display name evaluates on view, beacon with the token earns the flag', async () => {
    const c = client(srv.base);
    // An empty display name is rejected, no flag.
    assert.equal((await c.post('/csti/stored/profile', { name: '' })).status, 400);
    assert.ok(!(await capturedSet(c)).some((s) => s.startsWith('csti:')));
    // The real exploit: store the template as a display name, load the page, beacon.
    await c.post('/csti/stored/profile', { name: '{{7*7}}' });
    const { token } = await pageToken(c, '/csti/stored');
    const hit = await c.get(`/csti/beacon?v=stored&d=49&n=${token}`);
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
    await capture('/csti/constructor', 'constructor', 'x');
    await capture('/csti/attr', 'attr', '49');
    await capture('/csti/stored', 'stored', '49');
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
