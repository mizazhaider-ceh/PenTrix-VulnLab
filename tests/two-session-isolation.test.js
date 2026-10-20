'use strict';
// Two-session interference tests (P1-1, P1-2, P1-9).
//
// A shared instance must behave like N private instances: session A attacks,
// pollutes, promotes, resets and poisons in every way the lab allows, and
// session B's challenges must still be in their pristine, solvable state.
// These are the regression guards for the per-session isolation pass.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { client, bootLab, flagFromDb } = require('./helpers');

// GET with a spoofed Host header, sharing the client's cookie jar (undici
// forbids setting Host directly, so this goes through node:http).
function spoofedGet(c, base, host, urlPath) {
  return new Promise((resolve, reject) => {
    const u = new URL(base);
    const req = http.request({
      hostname: '127.0.0.1', port: u.port, path: urlPath, method: 'GET',
      headers: { host, ...(c.cookie() ? { cookie: c.cookie() } : {}) },
    }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode, text: body }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function burst(c, url, n) {
  const jobs = [];
  for (let i = 0; i < n; i++) jobs.push(c.post(url));
  const resps = await Promise.all(jobs);
  return resps.map((r) => r.text).join('\n');
}

test('two-session isolation: A pollutes, promotes, resets; B stays pristine', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (mod, id) => flagFromDb(dataDir, mod, id);
  const A = client(srv.base);
  const B = client(srv.base);

  await t.test('proto: A\'s pollution earns A the flags, B is still clean', async () => {
    const merge = await A.get('/proto/query?__proto__[role]=admin');
    assert.equal(merge.status, 200);
    const adminA = await A.get('/proto/query/admin');
    assert.ok(adminA.text.includes(flagOf('proto', 'proto-query')), 'A solved proto-query');
    const adminB = await B.get('/proto/query/admin');
    assert.ok(!adminB.text.includes(flagOf('proto', 'proto-query')), 'B must not inherit A\'s pollution');
    assert.ok(adminB.text.includes('Access denied'), 'B sees a clean admin check');
    // JSON vector: A pollutes, B unaffected, then B solves it independently.
    await A.postJson('/proto/json/merge', JSON.parse('{"__proto__": {"role": "admin"}}'));
    const jsonB = await B.get('/proto/json/admin');
    assert.ok(!jsonB.text.includes(flagOf('proto', 'proto-json')), 'B clean after A\'s JSON pollution');
    await B.postJson('/proto/json/merge', JSON.parse('{"__proto__": {"role": "admin"}}'));
    const jsonB2 = await B.get('/proto/json/admin');
    assert.ok(jsonB2.text.includes(flagOf('proto', 'proto-json')), 'B can still solve proto-json');
  });

  await t.test('mass-assignment: A\'s promotion stays in A\'s session, B\'s IDORs survive', async () => {
    await A.get('/api/login/alice');
    const promoted = await A.patchJson('/api/me', { role: 'admin' });
    assert.equal(promoted.body.flag, flagOf('api', 'mass-assignment'), 'A earned the flag');
    assert.equal(promoted.body.user.role, 'admin', 'A sees their own promotion');

    await B.get('/api/login/alice');
    const meB = await B.get('/api/me');
    assert.equal(meB.body.user.role, 'user', 'B\'s alice is still a plain user');

    // The six IDOR challenges would be nullified if alice were admin for B:
    // B signs in as alice and the role badge must say user, and the profile
    // IDOR (which does not award admins) must still award.
    await B.get('/idor/login/alice');
    const idx = await B.get('/idor');
    assert.ok(idx.text.includes('role <code>user</code>'), 'B\'s idor alice has the user role');
    const other = await B.get('/idor/users/1');
    assert.ok(other.text.includes(flagOf('idor', 'profile')), 'B can still solve the profile IDOR');
  });

  await t.test('passwords: A\'s password change never touches B\'s brute-force lab', async () => {
    // A signs in as alice and changes her password without the old one.
    await A.post('/auth/login', { username: 'alice', password: 'alice123' });
    const changed = await A.post('/auth/change-password', { newPassword: 'hacked-by-A' });
    assert.ok(changed.text.includes(flagOf('auth', 'change-pass-noverify')), 'A earned the flag');

    // B still brute-forces the seeded password.
    let hit = null;
    for (let i = 0; i < 6; i++) await B.post('/auth/login', { username: 'alice', password: `wrong${i}` });
    hit = await B.post('/auth/login', { username: 'alice', password: 'alice123' });
    assert.ok(hit.text.includes('Welcome back'), 'B signs in with the seeded password');
    assert.ok(hit.text.includes(flagOf('auth', 'brute-force')), 'B earns the brute-force flag');

    // In A's session the new password is the one that works.
    await A.post('/auth/login', { username: 'alice', password: 'alice123' });
    const aNew = await A.post('/auth/login', { username: 'alice', password: 'hacked-by-A' });
    assert.ok(aNew.text.includes('Welcome back'), 'A signs in with the password A set');
  });

  await t.test('race: A\'s burst and reset leave B\'s race untouched (P1-1, P1-2)', async () => {
    const textsA = await burst(A, '/race/coupon/redeem', 20);
    assert.ok(textsA.includes(flagOf('race', 'race-coupon')), 'A double-redeems and wins');

    // B has not redeemed yet: a single sequential redeem for B is benign,
    // and A's win did not spend B's coupon.
    const soloB = await B.post('/race/coupon/redeem');
    assert.ok(!soloB.text.includes(flagOf('race', 'race-coupon')), 'one redeem earns B nothing');

    // A resets: only A's state is wiped, B's single redeem stays spent.
    const reset = await A.post('/race/reset');
    assert.equal(reset.status, 200);
    const againB = await B.post('/race/coupon/redeem');
    assert.ok(againB.text.includes('Already redeemed'), 'A\'s reset did not restore B\'s coupon');

    // And B can still win the race with a fresh burst after their own reset.
    await B.post('/race/reset');
    const textsB = await burst(B, '/race/coupon/redeem', 20);
    assert.ok(textsB.includes(flagOf('race', 'race-coupon')), 'B double-redeems and wins');
  });

  await t.test('formula: A\'s planted payload earns B nothing on B\'s export', async () => {
    await A.post('/formula/add', { name: "=cmd|' /C calc'!A0", note: 'planted by A' });
    const exportB = await B.get('/formula/export.csv');
    assert.ok(!(exportB.headers.get('x-flags') || '').includes(flagOf('formula', 'formula-csv')), 'B must not earn A\'s formula flag');
    // B plants their own and exports: the flag is theirs.
    await B.post('/formula/add', { name: "=cmd|' /C calc'!A0", note: 'planted by B' });
    const exportB2 = await B.get('/formula/export.csv');
    assert.ok((exportB2.headers.get('x-flags') || '').includes(flagOf('formula', 'formula-csv')), 'B earns the flag for their own payload');
  });

  await t.test('cache poison: A\'s poisoned page is never served to B', async () => {
    const poison = await spoofedGet(A, srv.base, 'evil.com', '/hostheader/app');
    assert.equal(poison.status, 200);
    const hitA = await A.get('/hostheader/app');
    assert.ok(hitA.text.includes(flagOf('hostheader', 'host-cache-poison')), 'A completes the attack in their own session');
    const freshB = await B.get('/hostheader/app');
    assert.ok(!freshB.text.includes('http://evil.com/hostheader/forgot'), 'B is served a clean page');
    assert.ok(!freshB.text.includes(flagOf('hostheader', 'host-cache-poison')), 'B earns nothing from A\'s poison');
  });

  await t.test('hosted DTD: each session keeps its own DTD slot', async () => {
    const dtdA = '<!ENTITY aaa "hosted by session A">';
    const dtdB = '<!ENTITY bbb "hosted by session B">';
    await A.post('/xxe/collector/dtd', { dtd: dtdA });
    await B.post('/xxe/collector/dtd', { dtd: dtdB });
    const gotA = await A.get('/xxe/collector/dtd');
    const gotB = await B.get('/xxe/collector/dtd');
    assert.ok(gotA.text.includes('hosted by session A'), 'A reads back A\'s DTD');
    assert.ok(gotB.text.includes('hosted by session B'), 'B reads back B\'s DTD');
    // The per-session URLs the collector page hands out resolve correctly.
    const pageA = await A.get('/xxe/collector');
    const m = pageA.text.match(/\/xxe\/collector\/dtd\/([A-Za-z0-9._~-]+)/);
    assert.ok(m, 'collector page shows a per-session DTD URL');
    const fetched = await client(srv.base).get(`/xxe/collector/dtd/${m[1]}`);
    assert.ok(fetched.text.includes('hosted by session A'), 'the per-session URL serves A\'s DTD');
  });

  await t.test('session hygiene (P1-9): a persistent secret file is generated at boot', async () => {
    // The bundled test helpers always pass SESSION_SECRET to the lab, which
    // suppresses generation by design, so this subtest boots its own
    // instance without the variable.
    const { spawn } = require('node:child_process');
    const tmpDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'pentrix-secret-'));
    const free = await new Promise((resolve, reject) => {
      const srv = require('node:net').createServer();
      srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(() => resolve(p)); });
      srv.on('error', reject);
    });
    const env = { ...process.env, PORT: String(free), DB_PATH: path.join(tmpDir, 'vulnlab.db') };
    delete env.SESSION_SECRET;
    const child = spawn(process.execPath, ['app.js'], { cwd: require('node:path').join(__dirname, '..'), env, stdio: ['ignore', 'pipe', 'pipe'] });
    const base = `http://127.0.0.1:${free}`;
    for (let i = 0; i < 100; i++) {
      if (child.exitCode !== null) throw new Error('lab exited before boot');
      try { await fetch(base + '/'); break; } catch { await new Promise((r) => setTimeout(r, 100)); }
    }
    child.kill();
    await new Promise((r) => child.once('exit', r));
    const secretPath = path.join(tmpDir, '.session-secret');
    assert.ok(fs.existsSync(secretPath), 'secret file exists next to the database');
    const secret = fs.readFileSync(secretPath, 'utf8').trim();
    assert.ok(secret.length >= 32, 'secret is random and long enough');
    assert.notEqual(secret, 'pentrix-vulnlab-insecure-dev-secret', 'the public fallback is not in use');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
