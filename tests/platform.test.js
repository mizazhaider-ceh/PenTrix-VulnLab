'use strict';
// Platform regression suite. Boots the real app as a child process against a
// throwaway database and checks inventory, flag integrity and the
// exploit -> flag -> scoreboard journey. Run with: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ROOT, FLAG_RE, EXPECTED_MODULES, EXPECTED_CHALLENGES, startServer, client, scoreOf } = require('./helpers');


test('platform', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentrix-test-'));
  let srv = await startServer(dataDir);
  t.after(async () => {
    await srv.stop();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  await t.test('inventory: 29 modules, 201 challenges, all mounted', async () => {
    const mounted = [...srv.log().matchAll(/\[ok\] mounted \/(\w+) \((\d+) vulns\)/g)];
    assert.equal(mounted.length, EXPECTED_MODULES);
    assert.equal(mounted.reduce((n, m) => n + Number(m[2]), 0), EXPECTED_CHALLENGES);
    assert.doesNotMatch(srv.log(), /\[err\]|skipping/);
    const c = client(srv.base);
    assert.deepEqual(await scoreOf(c), { got: 0, total: EXPECTED_CHALLENGES });
  });

  await t.test('flags: 201 unique per-deployment flags in the documented format', () => {
    const Database = require('better-sqlite3');
    const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
    const rows = db.prepare("SELECT module_id, vuln_id, flag FROM flags WHERE module_id <> 'scenario'").all();
    db.close();
    assert.equal(rows.length, EXPECTED_CHALLENGES);
    assert.equal(new Set(rows.map((r) => r.flag)).size, EXPECTED_CHALLENGES);
    for (const r of rows) assert.match(r.flag, /^PENTRIX\{[0-9a-f]{32}\}$/);
  });

  // M12: the three scenario completion flags also live in the flags table
  // (module_id 'scenario'), seeded by ensureFlags alongside the challenges.
  await t.test('flags: 3 scenario flags seeded with module_id scenario', () => {
    const Database = require('better-sqlite3');
    const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
    const rows = db.prepare("SELECT module_id, vuln_id, flag FROM flags WHERE module_id = 'scenario'").all();
    db.close();
    assert.deepEqual(rows.map((r) => r.vuln_id).sort(),
      ['api-heist', 'ghost-in-the-cms', 'shop-takeover']);
    assert.equal(new Set(rows.map((r) => r.flag)).size, 3);
    for (const r of rows) assert.match(r.flag, /^PENTRIX\{[0-9a-f]{32}\}$/);
  });

  await t.test('source: no flag-shaped literal is committed', () => {
    const files = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (['node_modules', '.git', 'data', 'uploads'].includes(e.name)) continue;
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(js|html|css|md|txt|conf|sql|svg)$/.test(e.name)) files.push(p);
      }
    };
    walk(ROOT);
    const hits = files.filter((f) => /PENTRIX\{[0-9a-f]{32}\}/.test(fs.readFileSync(f, 'utf8')));
    assert.deepEqual(hits, []);
  });

  await t.test('source: every module can award flags (award() is referenced)', () => {
    const modsDir = path.join(ROOT, 'modules');
    const none = fs.readdirSync(modsDir).filter((dir) => {
      const files = [];
      const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p); else if (e.name.endsWith('.js')) files.push(p);
      });
      walk(path.join(modsDir, dir));
      return !files.some((f) => /\baward\(/.test(fs.readFileSync(f, 'utf8')));
    });
    assert.deepEqual(none, []);
  });
  await t.test('no flag appears on any normal page view', async () => {
    const c = client(srv.base);
    const mods = [...srv.log().matchAll(/mounted \/(\w+)/g)].map((m) => m[1]);
    for (const url of ['/', '/scoreboard', '/about', ...mods.map((m) => `/${m}`)]) {
      const { status, text } = await c.get(url);
      assert.equal(status, 200, url);
      assert.equal((text.match(FLAG_RE) || []).length, 0, `flag leaked on ${url}`);
    }
  });

  await t.test('journey: failed attempt gives nothing, SQLi login bypass awards once', async () => {
    const c = client(srv.base);
    const bad = await c.post('/sqli/login', { username: 'admin', password: 'wrong-password' });
    assert.equal((bad.text.match(FLAG_RE) || []).length, 0);
    assert.deepEqual(await scoreOf(c), { got: 0, total: EXPECTED_CHALLENGES });

    const hit = await c.post('/sqli/login', { username: "admin'--", password: 'x' });
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1, 'exploit should reveal exactly one flag');

    const Database = require('better-sqlite3');
    const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
    const expected = db.prepare("SELECT flag FROM flags WHERE module_id='sqli' AND vuln_id='login-bypass'").get().flag;
    db.close();
    assert.equal(flags[0], expected);

    assert.deepEqual(await scoreOf(c), { got: 1, total: EXPECTED_CHALLENGES });
    await c.post('/sqli/login', { username: "admin'--", password: 'x' });
    assert.deepEqual(await scoreOf(c), { got: 1, total: EXPECTED_CHALLENGES }, 'repeat must not double count');
  });

  await t.test('students are isolated: a fresh session sees no captured flags', async () => {
    const other = client(srv.base);
    assert.deepEqual(await scoreOf(other), { got: 0, total: EXPECTED_CHALLENGES });
  });

  await t.test('forged session cookie does not grant progress', async () => {
    const c = client(srv.base);
    c.setCookie('connect.sid=s%3Aforged.forged');
    assert.deepEqual(await scoreOf(c), { got: 0, total: EXPECTED_CHALLENGES });
  });

  await t.test('progress survives a server restart', async () => {
    const c = client(srv.base);
    await c.post('/sqli/login', { username: "admin'--", password: 'x' });
    assert.equal((await scoreOf(c)).got, 1);
    const cookie = c.cookie();
    await srv.stop();
    srv = await startServer(dataDir);
    const again = client(srv.base);
    again.setCookie(cookie);
    assert.equal((await scoreOf(again)).got, 1, 'captured flag lost after restart');
  });
});
