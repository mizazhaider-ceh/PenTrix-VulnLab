'use strict';
// Redirect module: every challenge must be solvable by the documented technique
// and must NOT be solvable by the obvious shortcut. The client helper uses
// redirect: 'manual', so these tests assert on the 302 status and Location
// header instead of following the redirect.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('redirect module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'redirect', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/redirect');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 5);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/redirect/go', '/redirect/js', '/redirect/data', '/redirect/trusted', '/redirect/polluted']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('double-slash: protocol-relative target earns the flag, plain targets do not', async () => {
    const c = client(srv.base);
    const form = await c.get('/redirect/go');
    assert.equal(form.status, 200);
    assert.ok(!form.text.includes(flagOf('redirect-double-slash')));
    const benign = await c.get('/redirect/go?next=' + encodeURIComponent('https://example.com/welcome'));
    assert.equal(benign.status, 302);
    assert.equal(benign.headers.get('location'), 'https://example.com/welcome');
    assert.ok(!benign.text.includes(flagOf('redirect-double-slash')), 'plain URL must not award');
    assert.deepEqual(await capturedSet(c), []);
    const hit = await c.get('/redirect/go?next=' + encodeURIComponent('//evil.com'));
    assert.equal(hit.status, 302);
    assert.equal(hit.headers.get('location'), '//evil.com');
    assert.ok(hit.text.includes(flagOf('redirect-double-slash')));
    assert.ok((await capturedSet(c)).includes('redirect:Protocol-Relative Redirect'));
  });

  await t.test('javascript: javascript scheme in Location earns the flag, plain URL does not', async () => {
    const c = client(srv.base);
    const benign = await c.get('/redirect/js?next=' + encodeURIComponent('https://example.com/promo'));
    assert.equal(benign.status, 302);
    assert.ok(!benign.text.includes(flagOf('redirect-javascript')), 'plain URL must not award');
    const hit = await c.get('/redirect/js?next=' + encodeURIComponent('javascript:alert(1)'));
    assert.equal(hit.status, 302);
    assert.ok(hit.headers.get('location').startsWith('javascript:'), 'Location must carry the javascript: scheme');
    assert.ok(hit.text.includes(flagOf('redirect-javascript')));
    assert.ok((await capturedSet(c)).includes('redirect:javascript: Scheme Honored'));
  });

  await t.test('data: data scheme in Location earns the flag, plain URL does not', async () => {
    const c = client(srv.base);
    const benign = await c.get('/redirect/data?next=' + encodeURIComponent('https://example.com/welcome'));
    assert.equal(benign.status, 302);
    assert.ok(!benign.text.includes(flagOf('redirect-data')), 'plain URL must not award');
    const hit = await c.get('/redirect/data?next=' + encodeURIComponent('data:text/html,<script>alert(1)</script>'));
    assert.equal(hit.status, 302);
    assert.ok(hit.headers.get('location').startsWith('data:'), 'Location must carry the data: scheme');
    assert.ok(hit.text.includes(flagOf('redirect-data')));
    assert.ok((await capturedSet(c)).includes('redirect:data: Scheme Honored'));
  });

  await t.test('backslash: blocked host stays blocked, trusted host earns nothing, backslash evil earns the flag', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/redirect/trusted?next=' + encodeURIComponent('https://evil.com'));
    assert.equal(blocked.status, 400, 'untrusted host must be blocked');
    const benign = await c.get('/redirect/trusted?next=' + encodeURIComponent('https://pentrix.lab/dashboard'));
    assert.equal(benign.status, 302);
    assert.equal(benign.headers.get('location'), 'https://pentrix.lab/dashboard');
    assert.ok(!benign.text.includes(flagOf('redirect-backslash')), 'trusted host must not award');
    const hit = await c.get('/redirect/trusted?next=' + encodeURIComponent('https:\\\\evil.com'));
    assert.equal(hit.status, 302);
    assert.ok(hit.text.includes(flagOf('redirect-backslash')));
    assert.ok((await capturedSet(c)).includes('redirect:Backslash Allowlist Bypass'));
  });

  await t.test('pollution: last value wins, single safe value earns nothing, last safe value earns nothing', async () => {
    const c = client(srv.base);
    const single = await c.get('/redirect/polluted?next=' + encodeURIComponent('https://example.com'));
    assert.equal(single.status, 302);
    assert.ok(!single.text.includes(flagOf('redirect-pollution')), 'single value must not award');
    const hit = await c.get('/redirect/polluted?next=safe&next=' + encodeURIComponent('https://evil.com'));
    assert.equal(hit.status, 302);
    assert.equal(hit.headers.get('location'), 'https://evil.com');
    assert.ok(hit.text.includes(flagOf('redirect-pollution')));
    assert.ok((await capturedSet(c)).includes('redirect:Parameter Pollution Picks Last'));
    const c2 = client(srv.base);
    const lastSafe = await c2.get('/redirect/polluted?next=' + encodeURIComponent('https://evil.com') + '&next=safe');
    assert.equal(lastSafe.status, 302);
    assert.ok(!lastSafe.text.includes(flagOf('redirect-pollution')), 'last value safe must not award');
    assert.deepEqual(await capturedSet(c2), []);
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.get('/redirect/go?next=' + encodeURIComponent('//evil.com'));
    await c.get('/redirect/go?next=' + encodeURIComponent('//evil.com'));
    await c.get('/redirect/js?next=' + encodeURIComponent('javascript:alert(1)'));
    await c.get('/redirect/data?next=' + encodeURIComponent('data:text/html,<h1>x</h1>'));
    await c.get('/redirect/trusted?next=' + encodeURIComponent('https:\\\\evil.com'));
    await c.get('/redirect/polluted?next=safe&next=' + encodeURIComponent('https://evil.com'));
    const got = (await capturedSet(c)).filter((s) => s.startsWith('redirect:'));
    assert.equal(got.length, 5);
  });
});
