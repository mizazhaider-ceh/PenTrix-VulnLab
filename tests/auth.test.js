'use strict';
// Broken Authentication module: every challenge must be solvable by the
// documented technique and must NOT be solvable by the obvious shortcut.
// Tests restore any password they change so later tests see the seeded users.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const NAMES = {
  'brute-force': 'No Rate Limiting (Brute-Force Login)',
  reset: 'Predictable Password Reset Tokens',
  'user-enum': 'Username Enumeration',
  'otp-bruteforce': 'Brute-Forcing a 4-Digit OTP',
  'reset-predictable': 'SHA-256 Predictable Reset Token',
  'security-question': 'Guessable Security Question',
  'change-pass-noverify': 'Password Change Without Current Password',
  'support-impersonate': 'Support Ticket Impersonation',
};

const flagsIn = (text) => text.match(FLAG_RE) || [];

// Controls that are not clay-styled, bare tables, inline styles.
function styleProblems(html) {
  const problems = [];
  if (/<input(?![^>]*class="[^"]*clay-)[^>]*>/.test(html)) problems.push('unstyled <input>');
  if (/<select(?![^>]*class="[^"]*clay-)[^>]*>/.test(html)) problems.push('unstyled <select>');
  if (/<textarea(?![^>]*class="[^"]*clay-)[^>]*>/.test(html)) problems.push('unstyled <textarea>');
  if (/<button(?![^>]*class="[^"]*(clay-|copy-btn))[^>]*>/.test(html)) problems.push('unstyled <button>');
  if (/<table(?![^>]*class=)[^>]*>/.test(html)) problems.push('bare <table>');
  if (/\sstyle=/.test(html)) problems.push('inline style=');
  if (/<style[\s>]/.test(html)) problems.push('<style> block');
  return problems;
}

test('auth module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'auth', id);
  const captures = async (c) => (await capturedSet(c)).filter((s) => s.startsWith('auth:'));

  async function login(c, username, password) {
    return c.post('/auth/login', { username, password });
  }

  await t.test('module index renders, lists all challenges, no flag, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/auth');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal(flagsIn(text).length, 0);
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    for (const id of Object.keys(NAMES)) {
      assert.ok(text.includes(`id="${id}"`), `card for ${id}`);
    }
    for (const href of ['/auth/login', '/auth/reset', '/auth/enum-login', '/auth/otp-reset',
      '/auth/sha-reset', '/auth/question-reset', '/auth/change-password', '/auth/support']) {
      assert.ok(text.includes(`href="${href}"`), `index links to ${href}`);
    }
    assert.deepEqual(styleProblems(text), []);
  });

  await t.test('every page: 200, styled, no flag, no em dash, links and form actions resolve', async () => {
    const anon = client(srv.base);
    const member = client(srv.base);
    await login(member, 'bob', 'bob123');
    const pages = [
      [anon, '/auth'],
      [anon, '/auth/login'],
      [anon, '/auth/reset'],
      [anon, '/auth/reset?user=alice'],
      [anon, '/auth/reset?user=nobody-here'],
      [anon, '/auth/reset/confirm?token=abc'],
      [anon, '/auth/enum-login'],
      [anon, '/auth/enum-submit'],
      [anon, '/auth/otp-reset'],
      [anon, '/auth/sha-reset'],
      [anon, '/auth/sha-reset?user=alice'],
      [anon, '/auth/sha-reset/confirm?token=abc'],
      [anon, '/auth/question-reset'],
      [anon, '/auth/bio/alice'],
      [anon, '/auth/bio/bob'],
      [anon, '/auth/bio/admin'],
      [anon, '/auth/change-password'],
      [member, '/auth/change-password'],
      [anon, '/auth/support'],
      [anon, '/auth/support/login?ticket=1001'],
      [anon, '/auth/support/login?ticket=nope'],
      [anon, '/auth/settings'],
      [member, '/auth/settings'],
    ];
    const seen = new Set();
    for (const [c, url] of pages) {
      const r = await c.get(url);
      assert.equal(r.status, 200, url);
      assert.ok(!r.text.includes('\u2014'), `em dash on ${url}`);
      assert.equal(flagsIn(r.text).length, 0, `flag on ${url}`);
      assert.deepEqual(styleProblems(r.text), [], url);
      assert.ok(!/TODO|lorem|coming soon/i.test(r.text), `placeholder on ${url}`);
      for (const m of r.text.matchAll(/href="(\/[^"]*)"/g)) {
        const href = m[1].replace(/&amp;/g, '&');
        if (/^\/(style\.css|app\.js)/.test(href) || seen.has(href)) continue;
        seen.add(href);
        const l = await anon.get(href);
        assert.notEqual(l.status, 404, `${href} (linked from ${url})`);
      }
      for (const m of r.text.matchAll(/<form([^>]*)>/g)) {
        const method = ((m[1].match(/method="(\w+)"/i) || [])[1] || 'GET').toUpperCase();
        const action = (m[1].match(/action="([^"]*)"/) || [])[1];
        assert.ok(action && action.startsWith('/'), `form action on ${url}`);
        const fresh = client(srv.base);
        const res = method === 'POST' ? await fresh.post(action, {}) : await fresh.get(action);
        assert.notEqual(res.status, 404, `${method} ${action} (form on ${url})`);
      }
    }
    const missing = await anon.get('/auth/bio/nobody');
    assert.equal(missing.status, 404);
    assert.deepEqual(styleProblems(missing.text), []);
  });

  await t.test('brute-force: lucky first try, 4 failures, or wrong account earn nothing; 5 failures then alice does', async () => {
    const lucky = client(srv.base);
    const r0 = await login(lucky, 'alice', 'alice123');
    assert.equal(flagsIn(r0.text).length, 0, 'a single correct login must not award');

    const four = client(srv.base);
    for (let i = 0; i < 4; i++) await login(four, 'alice', `wrong${i}`);
    const r4 = await login(four, 'alice', 'alice123');
    assert.ok(r4.text.includes('4</b> failed'), 'counter reported');
    assert.equal(flagsIn(r4.text).length, 0, 'only 4 failures');

    const other = client(srv.base);
    for (let i = 0; i < 6; i++) await login(other, 'alice', `wrong${i}`);
    const rb = await login(other, 'bob', 'bob123');
    assert.equal(flagsIn(rb.text).length, 0, 'logging in as bob must not award');

    const noJar = client(srv.base);
    for (let i = 0; i < 8; i++) {
      // fresh session every time: the counter never accumulates
      await client(srv.base).post('/auth/login', { username: 'alice', password: `wrong${i}` });
    }
    const rn = await login(noJar, 'alice', 'alice123');
    assert.equal(flagsIn(rn.text).length, 0, 'failures in other sessions do not count');
    assert.deepEqual(await captures(noJar), []);

    const real = client(srv.base);
    const passwords = ['123456', 'password', 'letmein', 'qwerty', 'alice', 'alice1', 'alice123'];
    let hit;
    for (const p of passwords) {
      hit = await login(real, 'alice', p);
      if (hit.text.includes('Welcome back')) break;
    }
    assert.ok(hit.text.includes(flagOf('brute-force')));
    assert.deepEqual(await captures(real), [`auth:${NAMES['brute-force']}`]);
    for (let i = 0; i < 6; i++) await login(real, 'alice', `again${i}`);
    const again = await login(real, 'alice', 'alice123');
    assert.ok(again.text.includes(flagOf('brute-force')));
    assert.equal((await captures(real)).length, 1, 'repeat does not double count');
  });

  await t.test('reset: legit issued token and junk tokens earn nothing; forged base64(admin) does', async () => {
    const legit = client(srv.base);
    const page = await legit.get('/auth/reset?user=bob');
    const token = page.text.match(/<pre class="token">([^<]+)<\/pre>/)[1];
    assert.equal(token, Buffer.from('bob').toString('base64'));
    const used = await legit.post('/auth/reset/confirm', { token, newPassword: 'bob123' });
    assert.ok(used.text.includes('Password changed'));
    assert.equal(flagsIn(used.text).length, 0, 'a token the app issued to this session is legitimate');

    const junk = client(srv.base);
    for (const bad of ['notatoken', Buffer.from('no-such-user').toString('base64'), '']) {
      const r = await junk.post('/auth/reset/confirm', { token: bad, newPassword: 'x' });
      assert.equal(flagsIn(r.text).length, 0);
      assert.ok(r.text.includes('Reset failed'));
    }
    assert.deepEqual(await captures(junk), []);

    const att = client(srv.base);
    const alicePage = await att.get('/auth/reset?user=alice'); // learns the pattern
    assert.ok(alicePage.text.includes(Buffer.from('alice').toString('base64')));
    const forged = Buffer.from('admin').toString('base64');
    const hit = await att.post('/auth/reset/confirm', { token: forged, newPassword: 'admin123' });
    assert.ok(hit.text.includes(flagOf('reset')));
    assert.deepEqual(await captures(att), [`auth:${NAMES.reset}`]);
    await att.post('/auth/reset/confirm', { token: forged, newPassword: 'admin123' });
    assert.equal((await captures(att)).length, 1);
  });

  await t.test('user-enum: submitting a guess earns nothing, a username confirmed by the oracle does', async () => {
    const c = client(srv.base);
    const blind = await c.post('/auth/enum-submit', { username: 'alice' });
    assert.equal(flagsIn(blind.text).length, 0, 'unprobed guess');
    const nf = await c.post('/auth/enum-login', { username: 'nosuchuser', password: 'x' });
    assert.ok(nf.text.includes('not found'));
    const fakeSubmit = await c.post('/auth/enum-submit', { username: 'nosuchuser' });
    assert.equal(flagsIn(fakeSubmit.text).length, 0);
    const wp = await c.post('/auth/enum-login', { username: 'alice', password: 'definitely-wrong' });
    assert.ok(wp.text.includes('Wrong password for user'));
    assert.ok(!nf.text.includes('Wrong password'), 'unknown users get a different message');
    const other = client(srv.base);
    const stolen = await other.post('/auth/enum-submit', { username: 'alice' });
    assert.equal(flagsIn(stolen.text).length, 0, 'another session did not enumerate');
    const hit = await c.post('/auth/enum-submit', { username: 'alice' });
    assert.ok(hit.text.includes(flagOf('user-enum')));
    await c.post('/auth/enum-submit', { username: 'alice' });
    assert.deepEqual(await captures(c), [`auth:${NAMES['user-enum']}`]);

    const correct = client(srv.base);
    await correct.post('/auth/enum-login', { username: 'bob', password: 'bob123' });
    const viaLogin = await correct.post('/auth/enum-submit', { username: 'bob' });
    assert.equal(flagsIn(viaLogin.text).length, 0, 'a correct login is not an enumeration');
  });

  await t.test('otp-bruteforce: unknown token and wrong codes earn nothing; trying all codes does', async () => {
    const c = client(srv.base);
    const page = await c.get('/auth/otp-reset');
    const token = page.text.match(/<pre class="token">([0-9a-f]+)<\/pre>/)[1];

    const unknown = await c.post('/auth/otp-reset/verify', { token: 'f'.repeat(32), otp: '0000', newPassword: 'x' });
    assert.equal(flagsIn(unknown.text).length, 0);
    assert.ok(unknown.text.includes('Unknown recovery token'));
    const empty = await c.post('/auth/otp-reset/verify', { token, otp: '', newPassword: 'x' });
    assert.equal(flagsIn(empty.text).length, 0, 'token alone is not enough');

    // pick a code known to be wrong without revealing it through the app
    const Database = require('better-sqlite3');
    const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
    const real = db.prepare('SELECT otp FROM auth_otp WHERE token = ?').get(token).otp;
    db.close();
    const wrong = real === '0000' ? '0001' : '0000';
    const miss = await c.post('/auth/otp-reset/verify', { token, otp: wrong, newPassword: 'x' });
    assert.equal(flagsIn(miss.text).length, 0);
    assert.ok(miss.text.includes('Wrong code'));

    let found = null;
    for (let start = 0; start < 10000 && !found; start += 100) {
      const batch = [];
      for (let i = start; i < start + 100; i++) {
        batch.push(c.post('/auth/otp-reset/verify', { token, otp: String(i).padStart(4, '0'), newPassword: 'admin123' }));
      }
      const res = await Promise.all(batch);
      found = res.find((r) => r.text.includes('Password changed')) || null;
    }
    assert.ok(found, 'brute force found the code');
    assert.ok(found.text.includes(flagOf('otp-bruteforce')));
    assert.deepEqual(await captures(c), [`auth:${NAMES['otp-bruteforce']}`]);

    const replay = await c.post('/auth/otp-reset/verify', { token, otp: real, newPassword: 'admin123' });
    assert.equal(flagsIn(replay.text).length, 0, 'a used token cannot be replayed');
    assert.equal((await captures(c)).length, 1);
    const adminLogin = await login(client(srv.base), 'admin', 'admin123');
    assert.ok(adminLogin.text.includes('Welcome back'), 'admin password restored by the test');
  });

  await t.test('reset-predictable: requesting the real admin link or forging for others earns nothing; forged admin hash does', async () => {
    const hash = (u) => crypto.createHash('sha256').update(u + 'reset-salt').digest('hex');

    const legit = client(srv.base);
    const page = await legit.get('/auth/sha-reset?user=admin');
    const issued = page.text.match(/<pre class="token">([0-9a-f]+)<\/pre>/)[1];
    assert.equal(issued, hash('admin'));
    const used = await legit.post('/auth/sha-reset/confirm', { token: issued, newPassword: 'admin123' });
    assert.ok(used.text.includes('Password changed'));
    assert.equal(flagsIn(used.text).length, 0, 'an admin reset this session requested is not a forgery');

    const wrong = client(srv.base);
    for (const bad of [crypto.createHash('sha256').update('admin').digest('hex'), 'a'.repeat(64), 'YWRtaW4=']) {
      const r = await wrong.post('/auth/sha-reset/confirm', { token: bad, newPassword: 'x' });
      assert.equal(flagsIn(r.text).length, 0);
      assert.ok(r.text.includes('does not map to an account'));
    }
    const aliceOnly = await wrong.post('/auth/sha-reset/confirm', { token: hash('alice'), newPassword: 'alice123' });
    assert.ok(aliceOnly.text.includes('Password changed'));
    assert.equal(flagsIn(aliceOnly.text).length, 0, 'forging for alice is not the goal');
    assert.deepEqual(await captures(wrong), []);

    const att = client(srv.base);
    await att.get('/auth/sha-reset?user=alice');
    const hit = await att.post('/auth/sha-reset/confirm', { token: hash('admin'), newPassword: 'admin123' });
    assert.ok(hit.text.includes(flagOf('reset-predictable')));
    await att.post('/auth/sha-reset/confirm', { token: hash('admin'), newPassword: 'admin123' });
    assert.deepEqual(await captures(att), [`auth:${NAMES['reset-predictable']}`]);
  });

  await t.test('security-question: wrong answers and cross-account answers earn nothing; the public bio answer does', async () => {
    const c = client(srv.base);
    const wrong = await c.post('/auth/question-reset', { username: 'alice', answer: 'Johnson', newPassword: 'x' });
    assert.equal(flagsIn(wrong.text).length, 0);
    assert.ok(wrong.text.includes('Wrong answer'));
    const crossed = await c.post('/auth/question-reset', { username: 'bob', answer: 'Smith', newPassword: 'x' });
    assert.equal(flagsIn(crossed.text).length, 0, "alice's answer does not work for bob");
    const noPass = await c.post('/auth/question-reset', { username: 'alice', answer: 'Smith', newPassword: '' });
    assert.equal(flagsIn(noPass.text).length, 0, 'no new password, no reset');
    assert.deepEqual(await captures(c), []);

    const bio = await c.get('/auth/bio/alice');
    assert.equal(bio.status, 200);
    const answer = bio.text.match(/maiden name is (\w+)/)[1];
    const hit = await c.post('/auth/question-reset', { username: 'Alice', answer: answer.toUpperCase(), newPassword: 'alice123' });
    assert.ok(hit.text.includes(flagOf('security-question')));
    await c.post('/auth/question-reset', { username: 'alice', answer, newPassword: 'alice123' });
    assert.deepEqual(await captures(c), [`auth:${NAMES['security-question']}`]);
    const relog = await login(client(srv.base), 'alice', 'alice123');
    assert.ok(relog.text.includes('Welcome back'));
  });

  await t.test('change-pass-noverify: anonymous and empty changes earn nothing; a signed-in change without the old password does', async () => {
    const anon = client(srv.base);
    const denied = await anon.post('/auth/change-password', { newPassword: 'x' });
    assert.equal(denied.status, 401);
    assert.equal(flagsIn(denied.text).length, 0);
    const prompt = await anon.get('/auth/change-password');
    assert.ok(prompt.text.includes('Sign in first'));
    assert.ok(!prompt.text.includes('name="newPassword"'));

    const c = client(srv.base);
    await login(c, 'bob', 'bob123');
    const form = await c.get('/auth/change-password');
    assert.ok(form.text.includes('name="newPassword"'));
    assert.ok(!/name="(current|old)/i.test(form.text), 'the form never asks for the current password');
    const empty = await c.post('/auth/change-password', { newPassword: '' });
    assert.equal(flagsIn(empty.text).length, 0);
    assert.deepEqual(await captures(c), []);
    const hit = await c.post('/auth/change-password', { newPassword: 'bob123' });
    assert.ok(hit.text.includes(flagOf('change-pass-noverify')));
    await c.post('/auth/change-password', { newPassword: 'bob123' });
    assert.deepEqual(await captures(c), [`auth:${NAMES['change-pass-noverify']}`]);
    const relog = await login(client(srv.base), 'bob', 'bob123');
    assert.ok(relog.text.includes('Welcome back'));
  });

  await t.test('support-impersonate: customer and unknown tickets earn nothing; walking to the admin ticket does', async () => {
    const c = client(srv.base);
    for (const n of ['1001', '1002', '1003', '1004', '9999', 'abc', '-1']) {
      const r = await c.get(`/auth/support/login?ticket=${n}`);
      assert.equal(flagsIn(r.text).length, 0, `ticket ${n}`);
    }
    const asBob = await c.get('/auth/settings');
    assert.ok(asBob.text.includes('bob@pentrix.lab'));
    assert.deepEqual(await captures(c), []);

    const hit = await c.get('/auth/support/login?ticket=1005');
    assert.ok(hit.text.includes('Acting as admin'));
    assert.ok(hit.text.includes(flagOf('support-impersonate')));
    const settings = await c.get('/auth/settings');
    assert.ok(settings.text.includes('admin@pentrix.lab'));
    assert.equal(flagsIn(settings.text).length, 0, 'settings page never shows a flag');
    await c.get('/auth/support/login?ticket=1005');
    assert.deepEqual(await captures(c), [`auth:${NAMES['support-impersonate']}`]);
  });

  await t.test('module index shows captures for the student who earned them and fixes only then', async () => {
    const c = client(srv.base);
    await c.get('/auth/support/login?ticket=1005');
    const idx = await c.get('/auth');
    assert.ok(idx.text.includes(flagOf('support-impersonate')));
    assert.equal(flagsIn(idx.text).length, 1, 'only the captured flag is shown');
    const fresh = await client(srv.base).get('/auth');
    assert.equal(flagsIn(fresh.text).length, 0);
  });
});
