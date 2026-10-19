'use strict';
// API module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('api module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'api', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/api');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 5);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/api/login/alice', '/api/users/view', '/api/me']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('mass-assignment: needs login, benign edits give nothing, role=admin earns the flag', async () => {
    const c = client(srv.base);
    assert.equal((await c.patchJson('/api/me', { role: 'admin' })).status, 401);
    await c.get('/api/login/alice');
    const benign = await c.patchJson('/api/me', { email: 'alice+new@pentrix.lab' });
    assert.equal(benign.body.flag, null);
    const hit = await c.patchJson('/api/me', { role: 'admin' });
    assert.equal(hit.body.flag, flagOf('mass-assignment'));
    assert.ok((await capturedSet(c)).includes('api:Mass Assignment'));
  });

  await t.test('exposure: leaking endpoint reveals the flag in header, browser view agrees', async () => {
    const c = client(srv.base);
    assert.deepEqual(await capturedSet(c), []);
    const r = await c.get('/api/users');
    assert.equal(r.headers.get('x-pentrix-flag'), flagOf('exposure'));
    assert.ok(r.body.some((u) => 'password' in u));
    assert.ok((await capturedSet(c)).includes('api:Excessive Data Exposure'));
    const v = await c.get('/api/users/view');
    assert.ok(v.text.includes(flagOf('exposure')));
  });

  await t.test('rate-limit: correct password alone is not enough, 14 failures then success is', async () => {
    const c = client(srv.base);
    const first = await c.postJson('/api/login', { username: 'alice', password: 'alice123' });
    assert.equal(first.body.ok, true);
    assert.equal(first.body.flag, null, 'a single correct login must not award');
    for (let i = 0; i < 13; i++) {
      const r = await c.postJson('/api/login', { username: 'alice', password: `wrong${i}` });
      assert.equal(r.body.ok, false);
      assert.equal(r.body.flag, null);
    }
    const hit = await c.postJson('/api/login', { username: 'alice', password: 'alice123' });
    assert.equal(hit.body.attempts, 15);
    assert.equal(hit.body.flag, flagOf('rate-limit'));
  });

  await t.test('ratelimit-xff: spoofed header alone is not enough, lockout then spoof is', async () => {
    const c = client(srv.base);
    const cred = { username: 'alice', password: 'alice123' };
    const early = await c.postJson('/api/v1/login', cred, { 'x-forwarded-for': '9.9.9.9' });
    assert.equal(early.body.flag, null, 'spoofing without a lockout must not award');
    let last;
    for (let i = 0; i < 4; i++) last = await c.postJson('/api/v1/login', { username: 'alice', password: `bad${i}` });
    assert.equal(last.status, 429, 'real IP should be locked out');
    const locked = await c.postJson('/api/v1/login', cred);
    assert.equal(locked.status, 429);
    assert.equal(locked.body.flag, undefined);
    const hit = await c.postJson('/api/v1/login', cred, { 'x-forwarded-for': '10.0.0.77' });
    assert.equal(hit.body.ok, true);
    assert.equal(hit.body.flag, flagOf('ratelimit-xff'));
  });

  await t.test('api-version-bypass: v1 enforces ownership, v2 leaks other users', async () => {
    const c = client(srv.base);
    assert.equal((await c.get('/api/v2/users/3')).status, 401);
    await c.get('/api/login/alice');
    const v1 = await c.get('/api/v1/users/3');
    assert.equal(v1.status, 403);
    assert.equal(v1.body.flag, undefined);
    const own = await c.get('/api/v2/users/2');
    assert.equal(own.body.flag, null, 'reading your own record is not the exploit');
    const hit = await c.get('/api/v2/users/3');
    assert.equal(hit.body.flag, flagOf('api-version-bypass'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.get('/api/login/alice');
    await c.patchJson('/api/me', { role: 'admin' });
    await c.get('/api/users');
    await c.get('/api/v2/users/3');
    await c.get('/api/v2/users/3');
    const got = (await capturedSet(c)).filter((s) => s.startsWith('api:'));
    assert.equal(got.length, 3);
  });
});
