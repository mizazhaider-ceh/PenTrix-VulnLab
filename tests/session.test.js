'use strict';
// Session module: every challenge must be solvable by the documented technique
// and must NOT be solvable by the obvious shortcut or benign action.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// Swap the lab_sid cookie while keeping the rest of the jar (the app session
// cookie holds the captured-flag set, so it must survive).
function setLabSid(c, sid) {
  const rest = c.cookie().split('; ').filter((p) => p && !p.startsWith('lab_sid='));
  rest.push('lab_sid=' + sid);
  c.setCookie(rest.join('; '));
}

test('session module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'session', id);

  await t.test('module page renders, links resolve, no em dash, no flag leaks', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/session');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 6);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/session/fixation',
      '/session/fixation/preset',
      '/session/logoutdemo',
      '/session/predictable',
      '/session/urldemo',
      '/session/urldemo/proxy-log',
      '/session/neverexpires',
      '/session/legacy-archive',
      '/session/logleak',
      '/session/debug-log',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('fixation: plain login gives nothing, fixated sid then login earns the flag', async () => {
    const c = client(srv.base);
    const plain = await c.post('/session/fixation/login', { username: 'admin', password: 'admin123' });
    assert.equal(plain.status, 200);
    assert.equal((plain.text.match(FLAG_RE) || []).length, 0, 'plain login must not award');
    assert.ok(!(await capturedSet(c)).includes('session:Session Fixation'));
    await c.get('/session/fixation/preset');
    assert.ok(c.cookie().includes('lab_sid=attacker123'), 'preset must set the fixated cookie');
    const hit = await c.post('/session/fixation/login', { username: 'admin', password: 'admin123' });
    assert.ok(hit.text.includes(flagOf('fixation')));
    assert.ok((await capturedSet(c)).includes('session:Session Fixation'));
  });

  await t.test('logout: non-admin replay gives nothing, logout then replay earns the flag', async () => {
    const c = client(srv.base);
    await c.post('/session/logoutdemo/login', { username: 'alice', password: 'alice123' });
    await c.get('/session/logoutdemo/logout');
    const denied = await c.get('/session/logoutdemo/secret');
    assert.equal(denied.status, 403, 'a non-admin must never reach the secret page');
    const admin = client(srv.base);
    await admin.post('/session/logoutdemo/login', { username: 'admin', password: 'admin123' });
    const live = await admin.get('/session/logoutdemo/secret');
    assert.equal(live.status, 200);
    assert.equal((live.text.match(FLAG_RE) || []).length, 0, 'a live session must not award');
    await admin.get('/session/logoutdemo/logout');
    const hit = await admin.get('/session/logoutdemo/secret');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('logout')));
    assert.ok((await capturedSet(admin)).includes('session:Logout Does Not Destroy the Session'));
  });

  await t.test('predictable: guest session gives nothing, computed admin sid replay earns the flag', async () => {
    const c = client(srv.base);
    const page1 = await c.get('/session/predictable');
    assert.equal(page1.status, 200);
    const denied = await c.get('/session/predictable/admin');
    assert.equal(denied.status, 403, 'a guest session must not reach the admin panel');
    // The giveaway is gone (P3-7): the admin sid is never printed; only your
    // own sid is. The taught analysis: sequential ids, admin signed in right
    // after you, so admin sid = yours + 1.
    assert.ok(!/Their session id: <code>\d+<\/code>/.test(page1.text), 'the admin sid must not be printed on the demo page');
    const m = page1.text.match(/Your session id: <code>(\d+)<\/code>/);
    assert.ok(m, 'your own sid must be readable on the demo page');
    c.setCookie('lab_sid=' + String(Number(m[1]) + 1));
    const hit = await c.get('/session/predictable/admin');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('predictable')));
    assert.ok((await capturedSet(c)).includes('session:Predictable Session IDs'));
  });

  await t.test('url: own sid gives nothing, proxy-log sid replay earns the flag', async () => {
    const c = client(srv.base);
    await c.get('/session/urldemo');
    const login = await c.post('/session/urldemo/login', { username: 'admin', password: 'admin123' });
    assert.equal(login.status, 302);
    const loc = login.headers.get('location') || '';
    const own = await c.get(loc.replace(/^https?:\/\/[^/]+/, ''));
    assert.equal((own.text.match(FLAG_RE) || []).length, 0, 'your own sid must not award');
    const log = await c.get('/session/urldemo/proxy-log');
    const m = log.text.match(/home\?sid=([0-9a-f]{32})/);
    assert.ok(m, 'admin sid must be visible in the proxy log');
    const hit = await c.get('/session/urldemo/home?sid=' + m[1]);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('url')));
    assert.ok((await capturedSet(c)).includes('session:Session ID in the URL'));
  });

  await t.test('never-expires: no cookie gives nothing, archived sid replay earns the flag', async () => {
    const c = client(srv.base);
    assert.equal((await c.get('/session/legacy-admin')).status, 403);
    const archive = await c.get('/session/legacy-archive');
    const m = archive.text.match(/<code>([0-9a-f]{32})<\/code>/);
    assert.ok(m, 'archived admin sid must be shown in the archive');
    c.setCookie('lab_sid=' + m[1]);
    const hit = await c.get('/session/legacy-admin');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('never-expires')));
    assert.ok((await capturedSet(c)).includes('session:Sessions Never Expire'));
  });

  await t.test('log-leak: no cookie gives nothing, debug-log sid replay earns the flag', async () => {
    const c = client(srv.base);
    assert.equal((await c.get('/session/leak-admin')).status, 403);
    const log = await c.get('/session/debug-log');
    const m = log.text.match(/admin session started sid=([0-9a-f]{32})/);
    assert.ok(m, 'admin sid must be visible in the debug log');
    c.setCookie('lab_sid=' + m[1]);
    const hit = await c.get('/session/leak-admin');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('log-leak')));
    assert.ok((await capturedSet(c)).includes('session:Session ID in Debug Log'));
  });

  await t.test('scoreboard counts each captured challenge exactly once', async () => {
    const c = client(srv.base);
    await c.get('/session/fixation/preset');
    await c.post('/session/fixation/login', { username: 'admin', password: 'admin123' });
    await c.post('/session/logoutdemo/login', { username: 'admin', password: 'admin123' });
    await c.get('/session/logoutdemo/logout');
    await c.get('/session/logoutdemo/secret');
    await c.get('/session/logoutdemo/secret');
    const p = await c.get('/session/predictable');
    const pm = p.text.match(/Your session id: <code>(\d+)<\/code>/);
    assert.ok(pm, 'own sid readable');
    setLabSid(c, String(Number(pm[1]) + 1));
    await c.get('/session/predictable/admin');
    await c.get('/session/urldemo');
    const log = await c.get('/session/urldemo/proxy-log');
    const um = log.text.match(/home\?sid=([0-9a-f]{32})/);
    await c.get('/session/urldemo/home?sid=' + um[1]);
    const archive = await c.get('/session/legacy-archive');
    const nm = archive.text.match(/<code>([0-9a-f]{32})<\/code>/);
    setLabSid(c, nm[1]);
    await c.get('/session/legacy-admin');
    const dbg = await c.get('/session/debug-log');
    const lm = dbg.text.match(/admin session started sid=([0-9a-f]{32})/);
    setLabSid(c, lm[1]);
    await c.get('/session/leak-admin');
    await c.get('/session/leak-admin');
    const got = (await capturedSet(c)).filter((s) => s.startsWith('session:'));
    assert.equal(got.length, 6);
    assert.equal(new Set(got).size, 6);
  });
});
