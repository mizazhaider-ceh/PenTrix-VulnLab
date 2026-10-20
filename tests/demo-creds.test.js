'use strict';
// P1-8 demo-credential smoke test: every advertised demo credential must
// authenticate on the surface that advertises it, and a reboot must heal a
// database whose passwords drifted from the advertised seeds (the shipped
// data/vulnlab.db once held admin/hacked123, which broke fixation,
// host-header, and sqli logins on live instances).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { client, startServer, FLAG_RE } = require('./helpers');
const { DEMO_CREDS } = require('../lib/db');

const EXPECTED = { admin: 'admin123', alice: 'alice123', bob: 'bob123' };

test('demo credentials', async (t) => {
  // The advertised list must be exactly these three, so the smoke test and
  // the boot repair in lib/db.js cannot drift apart silently.
  assert.deepEqual(
    Object.fromEntries(DEMO_CREDS.map((c) => [c.username, c.password])),
    EXPECTED,
    'DEMO_CREDS must match the advertised demo credentials'
  );

  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentrix-demo-creds-'));
  let srv = await startServer(dataDir);
  t.after(async () => {
    await srv.stop();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  async function assertAllWork(why) {
    // admin/admin123 on the fixation login (the page placeholder advertises it).
    let c = client(srv.base);
    let r = await c.post('/session/fixation/login', { username: 'admin', password: 'admin123' });
    assert.equal(r.status, 200, `admin/admin123 must log in at /session/fixation/login (${why})`);
    assert.ok(r.text.includes('Welcome, admin'), `fixation login must welcome admin (${why})`);
    assert.ok(!r.text.includes('Bad username or password'), `fixation login must not reject admin (${why})`);
    // alice/alice123 and bob/bob123 on the host-header login (advertised there).
    for (const u of ['alice', 'bob']) {
      c = client(srv.base);
      r = await c.post('/hostheader/login', { username: u, password: EXPECTED[u] });
      assert.equal(r.status, 302, `${u} must log in at /hostheader/login (${why})`);
    }
    // admin/admin123 on the sqli login: must sign in (no flag, no "Invalid").
    c = client(srv.base);
    r = await c.post('/sqli/login', { username: 'admin', password: 'admin123' });
    assert.equal(r.status, 200, `admin/admin123 must log in at /sqli/login (${why})`);
    assert.ok(r.text.includes('Signed in'), `sqli login must render a signed-in page (${why})`);
    assert.ok(!r.text.includes('Invalid username or password'), 'a correct credential login must not read Invalid');
    assert.equal((r.text.match(FLAG_RE) || []).length, 0, 'a correct credential login must earn no flag');
  }

  await t.test('every advertised demo credential authenticates on a fresh boot', async () => {
    await assertAllWork('fresh boot');
  });

  await t.test('a reboot heals a database whose passwords drifted', async () => {
    // Simulate the pre-fix drift: older app versions (or a raw DB edit) wrote
    // a password into the shared users table. Direct table write, same shape
    // as the old bug.
    const Database = require('better-sqlite3');
    const db = new Database(path.join(dataDir, 'vulnlab.db'));
    db.prepare("UPDATE users SET password = ? WHERE username = 'admin'").run('hacked123');
    db.close();
    const drifted = await client(srv.base).post('/session/fixation/login', { username: 'admin', password: 'admin123' });
    assert.equal(drifted.status, 403, 'the drift must be visible before the reboot');
    // Reboot against the SAME data dir: the boot repair in lib/db.js restores
    // the advertised passwords.
    await srv.stop();
    srv = await startServer(dataDir);
    await assertAllWork('after reboot');
  });
});
