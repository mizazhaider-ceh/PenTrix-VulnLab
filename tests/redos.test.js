'use strict';
// ReDoS module: each challenge must award the flag on a genuine evil input
// that pushes the regex check past the threshold, and must NOT award on
// benign or merely invalid inputs.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('redos module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'redos', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/redos');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 4);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/redos/email', '/redos/username', '/redos/url', '/redos/search']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  }, { timeout: 30000 });

  await t.test('redos-email: benign email gives nothing, evil local part earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/redos/email?email=' + encodeURIComponent('test@example.com'));
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('redos-email')), 'benign email must not award');
    const evil = 'a'.repeat(30) + '!';
    const hit = await c.get('/redos/email?email=' + encodeURIComponent(evil));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('redos-email')), 'evil input must earn the flag');
    assert.ok((await capturedSet(c)).includes('redos:Catastrophic Email Regex'));
  }, { timeout: 120000 });

  await t.test('redos-username: normal username gives nothing, (a+)+ blowup earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/redos/username?username=' + encodeURIComponent('alice'));
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('redos-username')), 'benign username must not award');
    const evil = 'a'.repeat(28) + '!';
    const hit = await c.get('/redos/username?username=' + encodeURIComponent(evil));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('redos-username')), 'evil input must earn the flag');
    assert.ok((await capturedSet(c)).includes('redos:Nested Quantifier Username'));
  }, { timeout: 120000 });

  await t.test('redos-url: benign URL gives nothing, repeated path segments earn the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/redos/url?url=' + encodeURIComponent('http://example.com/'));
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('redos-url')), 'benign URL must not award');
    const evil = 'http://example.com/' + 'a/'.repeat(12) + '!';
    const hit = await c.get('/redos/url?url=' + encodeURIComponent(evil));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('redos-url')), 'evil input must earn the flag');
    assert.ok((await capturedSet(c)).includes('redos:Catastrophic URL Regex'));
  }, { timeout: 180000 });

  await t.test('redos-search: benign query gives nothing, regex atom injection earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/redos/search?q=test');
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('redos-search')), 'benign query must not award');
    const hit = await c.post('/redos/search', { q: 'a' });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('redos-search')), 'evil input must earn the flag');
    assert.ok((await capturedSet(c)).includes('redos:Regex Injection Search'));
  }, { timeout: 180000 });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.get('/redos/email?email=' + encodeURIComponent('a'.repeat(30) + '!'));
    await c.get('/redos/username?username=' + encodeURIComponent('a'.repeat(28) + '!'));
    await c.get('/redos/url?url=' + encodeURIComponent('http://example.com/' + 'a/'.repeat(12) + '!'));
    await c.post('/redos/search', { q: 'a' });
    await c.post('/redos/search', { q: 'a' });
    const got = (await capturedSet(c)).filter((s) => s.startsWith('redos:'));
    assert.equal(got.length, 4);
    assert.deepEqual(got.sort(), [
      'redos:Catastrophic Email Regex',
      'redos:Catastrophic URL Regex',
      'redos:Nested Quantifier Username',
      'redos:Regex Injection Search',
    ].sort());
  }, { timeout: 300000 });
});
