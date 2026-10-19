'use strict';
// HTTP module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('http module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'http', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/http');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 3);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/http/track', '/http/feedback', '/http/cache']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('crlf-log: benign visits earn nothing, forged line in the log viewer earns the flag', async () => {
    const c = client(srv.base);
    await c.get('/http/track?ref=homepage');
    const plain = await c.get('/http/admin/log');
    assert.equal(plain.status, 200);
    assert.ok(!plain.text.includes(flagOf('crlf-log')), 'a plain visit must not award');

    const a = client(srv.base);
    const injected = await a.get('/http/track?ref=homepage%0d%0aFORGED line by pentrix test');
    assert.equal(injected.status, 200);
    const viewer = await a.get('/http/admin/log');
    assert.equal(viewer.status, 200);
    assert.ok(viewer.text.includes(flagOf('crlf-log')), 'forged line in viewer should award');
    assert.ok((await capturedSet(a)).includes('http:CRLF Log Injection'));
  });

  await t.test('verb-tamper: POST form earns nothing, GET submission earns the flag', async () => {
    const c = client(srv.base);
    const formPage = await c.get('/http/feedback');
    assert.equal(formPage.status, 200, 'form page should render');
    const posted = await c.post('/http/feedback', { msg: 'legit feedback over post' });
    assert.equal(posted.status, 200);
    assert.ok(!posted.text.includes(flagOf('verb-tamper')), 'documented POST must not award');
    assert.equal((await c.get('/http/feedback')).status, 200);

    const hit = await c.get('/http/feedback?msg=tampered verb');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('verb-tamper')), 'GET submission should award');
    assert.ok((await capturedSet(c)).includes('http:Verb Tampering'));
  });

  await t.test('cache-deception: own cache earns nothing, reading the victim cache earns the flag', async () => {
    await client(srv.base).get('/http/cache-purge');
    const victim = client(srv.base);
    const attacker = client(srv.base);

    const first = await attacker.get('/http/account.css');
    assert.equal(first.status, 200);
    assert.equal(first.headers.get('x-cache'), 'MISS');
    assert.equal(first.headers.get('x-flag'), null, 'uncached fetch must not award');

    await client(srv.base).get('/http/cache-purge');
    await victim.get('/http/cache-login?user=alice');
    const aliceCss = await victim.get('/http/account.css');
    assert.equal(aliceCss.status, 200);
    assert.equal(aliceCss.headers.get('x-cache'), 'MISS');
    assert.equal(aliceCss.headers.get('x-flag'), null, 'caching your own stylesheet must not award');

    const own = await victim.get('/http/account.css');
    assert.equal(own.headers.get('x-cache'), 'HIT');
    assert.equal(own.headers.get('x-flag'), null, 'reading your own cached stylesheet must not award');

    const hit = await attacker.get('/http/account.css');
    assert.equal(hit.headers.get('x-cache'), 'HIT');
    assert.equal(hit.headers.get('x-flag'), flagOf('cache-deception'));
    assert.ok((await capturedSet(attacker)).includes('http:Cache Deception'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    await client(srv.base).get('/http/cache-purge');
    const a = client(srv.base);
    const victim = client(srv.base);

    await a.get('/http/track?ref=x%0d%0aforged by scoreboard test');
    await a.get('/http/admin/log');
    await a.get('/http/feedback?msg=scoreboard verb test');
    await victim.get('/http/cache-login?user=alice');
    await victim.get('/http/account.css');
    await a.get('/http/account.css');

    const got = (await capturedSet(a)).filter((s) => s.startsWith('http:')).sort();
    assert.deepEqual(got, ['http:CRLF Log Injection', 'http:Cache Deception', 'http:Verb Tampering']);
  });
});
