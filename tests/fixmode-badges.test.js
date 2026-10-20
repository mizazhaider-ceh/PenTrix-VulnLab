'use strict';
// M11 break-then-fix: fix badge tests.
//
// Covers lib/fixbadges.js (awardFixBadge, hasFixBadge, fixBadgeList,
// fixBadgeCount) and the sandboxed fix checker in lib/fixmode.js (testFix).
//
// NOTE (2026-10-19): the HTTP fix routes (GET /fix/:module/:vuln and
// POST /fix/:module/:vuln/test) were wired into app.js while these tests
// were being written, so the integration subtest below hits the real
// routes end to end: it POSTs code, parses the HTML result page, and
// verifies the badge row in the server's own database under the client's
// session id. The lib-level subtests cover the same logic plus edge cases
// (broken-legit fixes, missing challenges) through the exact library
// functions the routes call.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { unsign } = require('cookie-signature');

const { client, bootLab, startServer } = require('./helpers');

// Scratch database for the in-process lib calls. Kept separate from the
// booted server's database so the test process and the server never
// contend on one SQLite file. The badge table is self-contained; it does
// not need the flags or users tables.
const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentrix-fixbadge-test-'));
const SCRATCH_DB = path.join(scratchDir, 'badges.db');
process.env.DB_PATH = SCRATCH_DB;

const fixmode = require('../lib/fixmode');
let fixbadges = require('../lib/fixbadges');

const MOD = 'sqli';
const VULN = 'login-bypass';

// The badge lib keys users off req.sessionID, the same express session the
// flag system uses. A plain object with a sessionID is all it reads.
const fakeReq = (sessionID) => ({ sessionID });

// Re-require the badge lib (and its db handle) against a different database
// file. Simulates a fresh server process booting against an existing DB.
function badgeLibFor(dbPath) {
  process.env.DB_PATH = dbPath;
  for (const key of Object.keys(require.cache)) {
    if (key.endsWith(`${path.sep}lib${path.sep}db.js`) || key.endsWith(`${path.sep}lib${path.sep}fixbadges.js`)) {
      delete require.cache[key];
    }
  }
  return require('../lib/fixbadges');
}

// Mirrors the intended POST /fix/:module/:vuln/test route logic:
// check the fix in the sandbox, award a badge only when it passes.
async function awardIfVerified(req, module, vulnId, studentCode) {
  const result = await fixmode.testFix(module, vulnId, studentCode);
  if (!result.ok) return { ok: false, error: result.error, badge: null };
  const badge = fixbadges.awardFixBadge(req, module, vulnId);
  return { ok: true, error: null, badge, alreadyHad: badge === null };
}

// The badge lib keys users off the express session id. Pull it out of the
// client's cookie jar by unsigning the session cookie (the test server
// signs with SESSION_SECRET=test-only-secret, see tests/helpers.js).
// Note: express-session signs the bare session id and prepends 's:'
// (setcookie does 's:' + sign(id)), so strip the prefix before unsigning.
function sessionIdOf(c) {
  const jar = c.cookie();
  for (const part of jar.split('; ')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const val = decodeURIComponent(part.slice(eq + 1));
    if (val.startsWith('s:')) {
      const unsigned = unsign(val.slice(2), 'test-only-secret');
      if (unsigned) return unsigned;
    }
  }
  return null;
}

// Read the server's own database (what the HTTP routes write to).
function badgeRowFor(dataDir, sessionID, module, vulnId) {
  const Database = require('better-sqlite3');
  const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
  try {
    return db.prepare('SELECT * FROM fix_badges WHERE user_key = ? AND module = ? AND vuln_id = ?')
      .get(sessionID, module, vulnId);
  } finally {
    db.close();
  }
}

function badgeCountFor(dataDir, sessionID) {
  const Database = require('better-sqlite3');
  const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
  try {
    return db.prepare('SELECT COUNT(*) AS c FROM fix_badges WHERE user_key = ?').get(sessionID).c;
  } finally {
    db.close();
  }
}

test('fix badges (M11 break-then-fix)', async (t) => {
  const { srv, dataDir } = await bootLab(t);

  await t.test('app boots (sanity)', async () => {
    const c = client(srv.base);
    const { status } = await c.get('/');
    assert.equal(status, 200);
  });

  await t.test('fix blocks are discoverable and the reference block is valid', async () => {
    const blocks = fixmode.listFixBlocks();
    assert.ok(blocks.some((b) => b.module === MOD && b.vulnId === VULN), 'sqli/login-bypass block must be listed');
    const block = fixmode.getFixBlock(MOD, VULN);
    assert.ok(block, 'fix block must load');
    const validation = await fixmode.validateBlock(block);
    assert.equal(validation.valid, true, validation.error);
  });

  await t.test('badge flow: verified fix earns exactly one badge', async () => {
    const req = fakeReq('fixbadge-user-flow');
    assert.equal(fixbadges.hasFixBadge(req, MOD, VULN), false);
    assert.equal(fixbadges.fixBadgeCount(req), 0);

    const block = fixmode.getFixBlock(MOD, VULN);
    const check = await fixmode.testFix(MOD, VULN, block.fixedCode);
    assert.equal(check.ok, true, check.error);
    assert.equal(check.exploitBlocked, true);
    assert.equal(check.legitWorks, true);

    const awarded = await awardIfVerified(req, MOD, VULN, block.fixedCode);
    assert.equal(awarded.ok, true);
    assert.ok(awarded.badge, 'first verified fix must return a badge record');
    assert.equal(awarded.badge.module, MOD);
    assert.equal(awarded.badge.vulnId, VULN);
    assert.equal(typeof awarded.badge.awarded_at, 'number');

    assert.equal(fixbadges.hasFixBadge(req, MOD, VULN), true);
    assert.equal(fixbadges.fixBadgeCount(req), 1);

    const list = fixbadges.fixBadgeList(req);
    assert.equal(list.length, 1);
    assert.equal(list[0].module, MOD);
    assert.equal(list[0].vulnId, VULN);
  });

  await t.test('no double award: second award keeps the count at one', async () => {
    const req = fakeReq('fixbadge-user-double');
    const first = fixbadges.awardFixBadge(req, MOD, VULN);
    assert.ok(first, 'first award must return the badge record');
    assert.equal(fixbadges.fixBadgeCount(req), 1);

    const again = fixbadges.awardFixBadge(req, MOD, VULN);
    assert.equal(again, null, 're-award must return null');
    assert.equal(fixbadges.fixBadgeCount(req), 1);
    assert.equal(fixbadges.fixBadgeList(req).length, 1);

    const viaRoute = await awardIfVerified(req, MOD, VULN, fixmode.getFixBlock(MOD, VULN).fixedCode);
    assert.equal(viaRoute.ok, true);
    assert.equal(viaRoute.alreadyHad, true, 'verified re-submit reports alreadyHad');
    assert.equal(fixbadges.fixBadgeCount(req), 1);
  });

  await t.test('badges are per-user: a fresh session has none', async () => {
    const userA = fakeReq('fixbadge-user-per-a');
    const userB = fakeReq('fixbadge-user-per-b');

    fixbadges.awardFixBadge(userA, MOD, VULN);
    assert.equal(fixbadges.fixBadgeCount(userA), 1);

    assert.equal(fixbadges.hasFixBadge(userB, MOD, VULN), false);
    assert.equal(fixbadges.fixBadgeCount(userB), 0);
    assert.deepEqual(fixbadges.fixBadgeList(userB), []);

    fixbadges.awardFixBadge(userB, MOD, VULN);
    assert.equal(fixbadges.fixBadgeCount(userB), 1);
    assert.equal(fixbadges.fixBadgeCount(userA), 1, 'user A untouched by user B award');
  });

  await t.test('badges persist: same DB file, fresh process handle, same session id', async () => {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pentrix-fixpersist-'));
    const dbFile = path.join(dataDir, 'vulnlab.db');
    const servers = [];
    t.after(async () => {
      for (const s of servers) { try { await s.stop(); } catch { /* already stopped */ } }
      fs.rmSync(dataDir, { recursive: true, force: true });
      fixbadges = badgeLibFor(SCRATCH_DB); // back to the scratch DB
    });

    const s1 = await startServer(dataDir);
    servers.push(s1);

    // Badge lib pointed at the server's own database file.
    fixbadges = badgeLibFor(dbFile);
    const req = fakeReq('fixbadge-persistent-user');
    const block = fixmode.getFixBlock(MOD, VULN);
    const awarded = await awardIfVerified(req, MOD, VULN, block.fixedCode);
    assert.equal(awarded.ok, true);
    assert.ok(awarded.badge);
    assert.equal(fixbadges.fixBadgeCount(req), 1);

    await s1.stop(); // full server shutdown, like a restart
    servers.splice(servers.indexOf(s1), 1); // already stopped: t.after must not stop it twice

    // Fresh lib handle = fresh process reading the same DB file.
    fixbadges = badgeLibFor(dbFile);
    assert.equal(fixbadges.hasFixBadge(req, MOD, VULN), true, 'badge must survive a fresh process handle');
    assert.equal(fixbadges.fixBadgeCount(req), 1);

    // New boot against the same DB_PATH, like a second bootLab on one dir.
    const s2 = await startServer(dataDir);
    servers.push(s2);
    const c = client(s2.base);
    assert.equal((await c.get('/')).status, 200);
    assert.equal(fixbadges.hasFixBadge(fakeReq('fixbadge-persistent-user'), MOD, VULN), true);
    assert.equal(fixbadges.fixBadgeCount(fakeReq('fixbadge-persistent-user')), 1);
  });

  await t.test('integration (lib level): good code ok true + badge, bad code ok false + no badge', async () => {
    const block = fixmode.getFixBlock(MOD, VULN);

    // Reference fixedCode: passes, earns a badge.
    const req = fakeReq('fixbadge-user-good');
    const good = await awardIfVerified(req, MOD, VULN, block.fixedCode);
    assert.equal(good.ok, true, good.error);
    assert.ok(good.badge);
    assert.equal(fixbadges.fixBadgeCount(req), 1);

    // Still-vulnerable code: exploit works, rejected, no badge.
    const req2 = fakeReq('fixbadge-user-bad');
    const bad = await awardIfVerified(req2, MOD, VULN, block.vulnerableCode);
    assert.equal(bad.ok, false);
    assert.ok(/exploit still works/i.test(bad.error), 'error should say the exploit still works');
    assert.equal(bad.badge, null);
    assert.equal(fixbadges.hasFixBadge(req2, MOD, VULN), false);
    assert.equal(fixbadges.fixBadgeCount(req2), 0);

    // Fix that blocks the exploit but breaks legit use: rejected, no badge.
    const req3 = fakeReq('fixbadge-user-broken');
    const broken = await awardIfVerified(req3, MOD, VULN, 'function vulnFn(username, password) { return null; }');
    assert.equal(broken.ok, false);
    assert.ok(/normal use is broken/i.test(broken.error));
    assert.equal(broken.badge, null);
    assert.equal(fixbadges.fixBadgeCount(req3), 0);

    // Missing challenge: clean failure, no badge.
    const missing = await awardIfVerified(req3, MOD, 'no-such-challenge');
    assert.equal(missing.ok, false);
    assert.equal(missing.badge, null);
    assert.equal(fixbadges.fixBadgeCount(req3), 0);
  });

  await t.test('badge lib requires a session (documents the user-key contract)', async () => {
    assert.throws(() => fixbadges.awardFixBadge({}, MOD, VULN), /session/);
    assert.throws(() => fixbadges.hasFixBadge({}, MOD, VULN), /session/);
    assert.throws(() => fixbadges.fixBadgeList({}), /session/);
    assert.throws(() => fixbadges.fixBadgeCount({}), /session/);
  });

  await t.test('HTTP integration: POST fixedCode -> Fix accepted + badge row, POST bad code -> rejected, no badge', async () => {
    const block = fixmode.getFixBlock(MOD, VULN);

    // Editor page renders for a known challenge.
    const c = client(srv.base);
    // P1-9: app.js runs with saveUninitialized: false, so a client that
    // stores nothing gets no session cookie and sessionIdOf() returns null.
    // Establish a stored session first by loading a page that writes session
    // state (the XSS search page issues the page-bound nonce into the
    // session), so the client holds a session cookie for the badge lookup.
    const seed = await c.get('/xss/search');
    assert.equal(seed.status, 200, 'session-seeding page must load');
    assert.ok(sessionIdOf(c), 'seeding request must issue a session cookie');
    const editor = await c.get(`/fix/${MOD}/${VULN}`);
    assert.equal(editor.status, 200);
    assert.ok(editor.text.includes('id="fix-form"'), 'editor page must contain the fix form');
    assert.ok(editor.text.includes('Test my fix'));

    // Reference fixedCode: accepted, badge mentioned, row lands in the server DB.
    const good = await c.postJson(`/fix/${MOD}/${VULN}/test`, { code: block.fixedCode });
    assert.equal(good.status, 200);
    assert.ok(good.text.includes('Fix accepted'), 'result page must say Fix accepted');
    assert.ok(good.text.includes('Badge earned'), 'result page must mention the badge');
    const sid = sessionIdOf(c);
    assert.ok(sid, 'must recover the session id from the cookie jar');
    const row = badgeRowFor(dataDir, sid, MOD, VULN);
    assert.ok(row, 'fix_badges row must exist in the server DB for this session');
    assert.equal(row.module, MOD);
    assert.equal(row.vuln_id, VULN);

    // Same fix again: still exactly one badge (no double award over HTTP).
    const again = await c.postJson(`/fix/${MOD}/${VULN}/test`, { code: block.fixedCode });
    assert.ok(again.text.includes('Fix accepted'));
    assert.equal(badgeCountFor(dataDir, sid), 1);

    // Still-vulnerable code from a fresh client: rejected, no badge row.
    // Same saveUninitialized handling as above: seed a stored session first
    // so this fresh client also holds a cookie and its own distinct id.
    const c2 = client(srv.base);
    const seed2 = await c2.get('/xss/search');
    assert.equal(seed2.status, 200, 'session-seeding page must load for the fresh client');
    assert.ok(sessionIdOf(c2), 'seeding request must issue a session cookie for the fresh client');
    const bad = await c2.postJson(`/fix/${MOD}/${VULN}/test`, { code: block.vulnerableCode });
    assert.equal(bad.status, 200);
    assert.ok(bad.text.includes('Fix not passing yet'), 'result page must say Fix not passing yet');
    const sid2 = sessionIdOf(c2);
    assert.ok(sid2, 'fresh client must have its own session');
    assert.notEqual(sid2, sid, 'fresh client must be a different user');
    assert.equal(badgeRowFor(dataDir, sid2, MOD, VULN), undefined, 'bad code must not award a badge');
    assert.equal(badgeCountFor(dataDir, sid2), 0);

    // Fix that blocks the exploit but breaks legit use: rejected, no badge.
    const broken = await c2.postJson(`/fix/${MOD}/${VULN}/test`, {
      code: 'function vulnFn(username, password) { return null; }',
    });
    assert.ok(broken.text.includes('Fix not passing yet'));
    assert.equal(badgeCountFor(dataDir, sid2), 0);

    // Unknown challenge: 404 on both routes.
    assert.equal((await c.get('/fix/sqli/no-such-challenge')).status, 404);
    assert.equal((await c.postJson('/fix/sqli/no-such-challenge/test', { code: 'x' })).status, 404);
    assert.equal((await c.get('/fix/nosuchmod/login-bypass')).status, 404);
  });
});
