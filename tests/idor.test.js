'use strict';
// IDOR module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut. Tests share one booted server,
// so each test uses fresh clients and the order below matters for shared rows.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const MOD = 'idor';

async function login(c, who) {
  const r = await c.get(`/idor/login/${who}`);
  assert.equal(r.status, 302, `login as ${who}`);
  return c;
}

async function asUser(base, who) {
  return login(client(base), who);
}

const idorCaptured = async (c) => (await capturedSet(c)).filter((s) => s.startsWith('idor:'));

// The admin user's random per-deployment secret (the SQL injection lab's target).
function adminSecretFromDb(dataDir) {
  const Database = require('better-sqlite3');
  const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
  const row = db.prepare("SELECT secret FROM users WHERE username = 'admin'").get();
  db.close();
  return row.secret;
}

function assertNoFlag(text, label) {
  assert.equal((text.match(FLAG_RE) || []).length, 0, `flag leaked on ${label}`);
}

// Every control on the page must carry a clay-* class (hidden inputs and the
// copy buttons of payload blocks are the only exceptions).
function assertStyled(html, label) {
  assert.ok(!html.includes('\u2014'), `em dash on ${label}`);
  assert.ok(!/\sstyle=/.test(html), `inline style on ${label}`);
  assert.ok(!/<style[\s>]/.test(html), `style block on ${label}`);
  assert.ok(!/<table(?![^>]*class=)/.test(html), `bare table on ${label}`);
  for (const m of html.matchAll(/<input\b[^>]*>/g)) {
    assert.ok(/type="hidden"/.test(m[0]) || /class="[^"]*clay-input/.test(m[0]), `unstyled ${m[0]} on ${label}`);
  }
  for (const m of html.matchAll(/<select\b[^>]*>/g)) assert.ok(/class="[^"]*clay-select/.test(m[0]), `unstyled ${m[0]}`);
  for (const m of html.matchAll(/<textarea\b[^>]*>/g)) assert.ok(/class="[^"]*clay-input/.test(m[0]), `unstyled ${m[0]}`);
  for (const m of html.matchAll(/<button\b[^>]*>/g)) {
    assert.ok(/class="[^"]*(clay-btn|copy-btn)/.test(m[0]), `unstyled ${m[0]} on ${label}`);
  }
}

// Internal hrefs and form actions found on a page.
function internalTargets(html) {
  const links = new Set();
  for (const m of html.matchAll(/\bhref="(\/[^"]*)"/g)) {
    const href = m[1].replace(/&amp;/g, '&').split('#')[0];
    if (href && !href.startsWith('//')) links.add(href);
  }
  const forms = [];
  for (const m of html.matchAll(/<form\b[^>]*>/g)) {
    const action = (m[0].match(/action="([^"]*)"/) || [])[1];
    const method = ((m[0].match(/method="([^"]*)"/) || [])[1] || 'GET').toUpperCase();
    if (action) forms.push({ action, method });
  }
  return { links: [...links], forms };
}

async function assertTargetsResolve(base, html, label) {
  const probe = client(base);
  const { links, forms } = internalTargets(html);
  for (const href of links) {
    if (href === '/idor/logout') continue;
    const r = await probe.get(href);
    assert.notEqual(r.status, 404, `${label}: dead link ${href}`);
  }
  for (const f of forms) {
    const r = f.method === 'POST' ? await probe.post(f.action, {}) : await probe.get(f.action);
    assert.notEqual(r.status, 404, `${label}: dead form action ${f.method} ${f.action}`);
  }
}

test('idor module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, MOD, id);

  await t.test('module index renders, 7 challenges, every challenge reachable, no em dash, no flag', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/idor');
    assert.equal(status, 200);
    assertStyled(text, '/idor');
    assertNoFlag(text, '/idor');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 7);
    for (const id of ['profile', 'admin', 'idor-download', 'idor-email-change', 'idor-apikey-regen', 'function-browse', 'idor-comment-delete']) {
      assert.ok(text.includes(`id="${id}"`), `card ${id}`);
    }
    // each card must have three hint levels
    assert.equal((text.match(/Hint \d: (Nudge|Technique|Explicit)/g) || []).length, 21);
    await assertTargetsResolve(srv.base, text, '/idor');
    assert.equal((await c.get('/idor/login/nobody')).status, 404);
    assert.equal((await c.get('/idor/logout')).status, 302);
  });

  await t.test('normal views of your own resources are styled, link-clean and flag-free', async () => {
    const c = await asUser(srv.base, 'alice');
    for (const path of ['/idor', '/idor/users/2', '/idor/invoice/1', '/idor/account', '/idor/apikey', '/idor/comments']) {
      const r = await c.get(path);
      assert.equal(r.status, 200, path);
      assertStyled(r.text, path);
      assertNoFlag(r.text, path);
      await assertTargetsResolve(srv.base, r.text, path);
    }
    assert.equal((await c.get('/idor/users/abc')).status, 400);
    assert.equal((await c.get('/idor/users/999')).status, 404);
    assert.equal((await c.get('/idor/invoice/abc')).status, 400);
    assert.equal((await c.get('/idor/invoice/999')).status, 404);
    assert.deepEqual(await idorCaptured(c), []);
  });

  await t.test('profile: your own and a guest view earn nothing, another member earns the flag', async () => {
    const guest = client(srv.base);
    const g = await guest.get('/idor/users/1');
    assert.equal(g.status, 200);
    assertNoFlag(g.text, 'guest profile');
    const adminSecret = adminSecretFromDb(dataDir);
    assert.ok(adminSecret && !g.text.includes(adminSecret), 'guest must not see the admin secret');

    const c = await asUser(srv.base, 'alice');
    const own = await c.get('/idor/users/2');
    assertNoFlag(own.text, 'own profile');
    assert.deepEqual(await idorCaptured(c), []);

    const hit = await c.get('/idor/users/1');
    assert.ok(hit.text.includes(flagOf('profile')));
    assert.ok(hit.text.includes('The fix'));
    assert.ok(!hit.text.includes(adminSecret), 'admin secret (sqli target) must not leak through the profile page');
    const bobView = await c.get('/idor/users/3');
    assert.ok(bobView.text.includes('bob-secret-note-2'), 'other members\' secret notes are the leaked data');
    assert.deepEqual(await idorCaptured(c), ['idor:Profile IDOR']);
    await c.get('/idor/users/3');
    await c.get('/idor/users/1');
    assert.deepEqual(await idorCaptured(c), ['idor:Profile IDOR'], 'no double count');

    const admin = await asUser(srv.base, 'admin');
    assertNoFlag((await admin.get('/idor/users/2')).text, 'admin reading a profile is legitimate');
    assert.deepEqual(await idorCaptured(admin), []);
  });

  await t.test('admin: guest gets 401, admin earns nothing, a normal member earns the flag', async () => {
    const guest = client(srv.base);
    const g = await guest.get('/idor/admin');
    assert.equal(g.status, 401);
    assertNoFlag(g.text, 'guest admin');

    const admin = await asUser(srv.base, 'admin');
    const a = await admin.get('/idor/admin');
    assert.equal(a.status, 200);
    assertStyled(a.text, '/idor/admin as admin');
    assertNoFlag(a.text, 'admin panel as admin');
    assert.deepEqual(await idorCaptured(admin), []);

    const c = await asUser(srv.base, 'bob');
    const own = await c.get('/idor/users/3');
    assert.ok(!own.text.includes('href="/idor/admin"'), 'admin link is hidden from normal members');
    assert.deepEqual(await idorCaptured(c), []);
    const hit = await c.get('/idor/admin');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('admin')));
    assertStyled(hit.text, '/idor/admin as bob');
    await assertTargetsResolve(srv.base, hit.text, '/idor/admin');
    await c.get('/idor/admin');
    assert.deepEqual(await idorCaptured(c), ['idor:Unprotected Admin Panel']);
  });

  await t.test('idor-download: own invoice and a guest earn nothing, someone else\'s invoice earns the flag', async () => {
    assert.equal((await client(srv.base).get('/idor/invoice/2')).status, 401);
    const c = await asUser(srv.base, 'alice');
    const own = await c.get('/idor/invoice/1');
    assert.ok(own.text.includes('INV-2026-001'));
    assertNoFlag(own.text, 'own invoice');
    assert.deepEqual(await idorCaptured(c), []);

    const admin = await asUser(srv.base, 'admin');
    assertNoFlag((await admin.get('/idor/invoice/2')).text, 'admin reading an invoice is legitimate');
    assert.deepEqual(await idorCaptured(admin), []);

    const hit = await c.get('/idor/invoice/2');
    assert.ok(hit.text.includes('INV-2026-002'));
    assert.ok(hit.text.includes(flagOf('idor-download')));
    await c.get('/idor/invoice/3');
    await c.get('/idor/invoice/2');
    assert.deepEqual(await idorCaptured(c), ['idor:Invoice Download IDOR']);
  });

  await t.test('idor-email-change: own email edits earn nothing, a forged user_id earns the flag', async () => {
    assert.equal((await client(srv.base).post('/idor/account/email', { user_id: '1', email: 'x@evil.lab' })).status, 401);
    const c = await asUser(srv.base, 'alice');
    const form = await c.get('/idor/account');
    assert.ok(/<input type="hidden" name="user_id" value="2">/.test(form.text), 'form carries the caller id');
    assertStyled(form.text, '/idor/account');

    const bad = await c.post('/idor/account/email', { user_id: '999', email: 'x@evil.lab' });
    assert.equal(bad.status, 400);
    const empty = await c.post('/idor/account/email', { user_id: '2', email: '' });
    assert.equal(empty.status, 400);

    const own = await c.post('/idor/account/email', { user_id: '2', email: 'alice.new@pentrix.lab' });
    assert.equal(own.status, 200);
    assertNoFlag(own.text, 'own email change');
    assert.deepEqual(await idorCaptured(c), []);

    // An admin changing someone else's email is a legitimate action.
    const admin = await asUser(srv.base, 'admin');
    assertNoFlag((await admin.post('/idor/account/email', { user_id: '3', email: 'bob.managed@pentrix.lab' })).text, 'admin edit');
    assert.deepEqual(await idorCaptured(admin), []);

    const hit = await c.post('/idor/account/email', { user_id: '1', email: 'pwned@evil.lab' });
    assert.ok(hit.text.includes(flagOf('idor-email-change')));
    // P1-1 update: the email change is visible to the session that performed
    // it only, so the directory check runs with the same client (c), not
    // the admin session, which still sees the pristine address.
    const dir = await c.get('/idor/admin/users');
    assert.ok(dir.text.includes('pwned@evil.lab'), 'the admin email was really changed');
    const adminView = await admin.get('/idor/admin/users');
    assert.ok(!adminView.text.includes('pwned@evil.lab'), 'another session must not see this session\'s email change');
    await c.post('/idor/account/email', { user_id: '1', email: 'pwned2@evil.lab' });
    // Visiting the admin directory as a plain member also earns the
    // function-browse flag for c, so the final capture list carries both
    // challenge names, exactly once each.
    assert.deepEqual(await idorCaptured(c), ['idor:Email Change IDOR', 'idor:Forced Browsing to Admin Function']);
  });

  await t.test('idor-apikey-regen: reusing shown or seeded keys earns nothing, regenerating another key and using it does', async () => {
    assert.equal((await client(srv.base).post('/idor/apikey/regen', { user_id: '1' })).status, 401);
    assert.equal((await client(srv.base).get('/idor/apikey/use?key=x')).status, 401);

    const c = await asUser(srv.base, 'alice');
    const page = await c.get('/idor/apikey');
    assertStyled(page.text, '/idor/apikey');
    const mine = (page.text.match(/idor_[0-9a-z_]+/) || [])[0];
    assert.ok(mine, 'own key displayed');

    // own key, an unknown key, and the seeded admin key are all not the exploit
    assertNoFlag((await c.get(`/idor/apikey/use?key=${mine}`)).text, 'own key');
    const unknown = await c.get('/idor/apikey/use?key=idor_doesnotexist');
    assert.equal(unknown.status, 401);
    assertNoFlag((await c.get('/idor/apikey/use?key=idor_admin_key_9f8e7d6c5b4a')).text, 'seeded key');
    assert.deepEqual(await idorCaptured(c), []);

    // bob reusing a key that alice was shown is not the exploit either
    const bob = await asUser(srv.base, 'bob');
    assertNoFlag((await bob.get(`/idor/apikey/use?key=${mine}`)).text, 'swapped shown key');
    // regenerating your own key and having someone else use it is not the exploit
    const own = await c.post('/idor/apikey/regen', { user_id: '2' });
    const ownKey = (own.text.match(/idor_[0-9a-f]{24}/) || [])[0];
    assert.ok(ownKey);
    assertNoFlag((await bob.get(`/idor/apikey/use?key=${ownKey}`)).text, 'self-rotated key used by another member');
    assertNoFlag((await c.get(`/idor/apikey/use?key=${ownKey}`)).text, 'self-rotated key used by its owner');
    assert.deepEqual(await idorCaptured(c), []);
    assert.deepEqual(await idorCaptured(bob), []);

    // the real exploit: rotate the admin's key through the IDOR, then use it
    const regen = await c.post('/idor/apikey/regen', { user_id: '1' });
    assert.equal(regen.status, 200);
    assertNoFlag(regen.text, 'regen response itself');
    const fresh = (regen.text.match(/idor_[0-9a-f]{24}/) || [])[0];
    assert.ok(fresh);
    assert.deepEqual(await idorCaptured(c), [], 'regenerating alone does not capture');
    const hit = await c.get(`/idor/apikey/use?key=${fresh}`);
    assert.ok(hit.text.includes(flagOf('idor-apikey-regen')));
    assert.ok(hit.text.includes('admin'));
    await c.get(`/idor/apikey/use?key=${fresh}`);
    assert.deepEqual(await idorCaptured(c), ['idor:API Key Regeneration IDOR']);
    // the old key is dead after rotation
    assert.equal((await c.get('/idor/apikey/use?key=idor_admin_key_9f8e7d6c5b4a')).status, 401);
  });

  await t.test('function-browse: guest 401, admin earns nothing, a normal member earns the flag', async () => {
    assert.equal((await client(srv.base).get('/idor/admin/users')).status, 401);
    const admin = await asUser(srv.base, 'admin');
    const a = await admin.get('/idor/admin/users');
    assert.equal(a.status, 200);
    assertNoFlag(a.text, 'admin directory as admin');
    assert.deepEqual(await idorCaptured(admin), []);

    const c = await asUser(srv.base, 'alice');
    const nav = await c.get('/idor/users/2');
    assert.ok(!nav.text.includes('/idor/admin/users'), 'the directory is not linked for members');
    assert.deepEqual(await idorCaptured(c), []);
    const hit = await c.get('/idor/admin/users');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('function-browse')));
    assertStyled(hit.text, '/idor/admin/users');
    await assertTargetsResolve(srv.base, hit.text, '/idor/admin/users');
    await c.get('/idor/admin/users');
    assert.deepEqual(await idorCaptured(c), ['idor:Forced Browsing to Admin Function']);
  });

  await t.test('idor-comment-delete: guest 401, own comment earns nothing, deleting another member\'s comment does', async () => {
    assert.equal((await client(srv.base).post('/idor/comments/delete', { id: '1' })).status, 401);
    const c = await asUser(srv.base, 'bob');
    const list = await c.get('/idor/comments');
    assertStyled(list.text, '/idor/comments');
    assertNoFlag(list.text, '/idor/comments');
    const idOf = (html, author) => Number((html.match(new RegExp(`<tr><td>(\\d+)</td><td>${author}</td>`)) || [])[1]);
    const bobId = idOf(list.text, 'bob');
    const aliceId = idOf(list.text, 'alice');
    assert.ok(bobId && aliceId);
    assert.ok(list.text.includes(`name="id" value="${bobId}"`), 'delete button for your own comment');
    assert.ok(!list.text.includes(`name="id" value="${aliceId}"`), 'no button for someone else\'s comment');

    assert.equal((await c.post('/idor/comments/delete', { id: '99999' })).status, 404);
    const own = await c.post('/idor/comments/delete', { id: String(bobId) });
    assert.equal(own.status, 200);
    assertNoFlag(own.text, 'deleting your own comment');
    assert.deepEqual(await idorCaptured(c), []);

    // an admin moderating someone else's comment is legitimate
    const admin = await asUser(srv.base, 'admin');
    const adminList = await admin.get('/idor/comments');
    const aliceNow = idOf(adminList.text, 'alice');
    assertNoFlag((await admin.post('/idor/comments/delete', { id: String(aliceNow) })).text, 'admin moderation');
    assert.deepEqual(await idorCaptured(admin), []);

    // the comment wall repopulates so the lab can be replayed
    const again = await c.get('/idor/comments');
    const target = idOf(again.text, 'alice');
    assert.ok(target, 'alice has a comment again');
    const hit = await c.post('/idor/comments/delete', { id: String(target) });
    assert.ok(hit.text.includes(flagOf('idor-comment-delete')));
    const repeat = await c.post('/idor/comments/delete', { id: String(target) });
    assert.equal(repeat.status, 404);
    assert.deepEqual(await idorCaptured(c), ['idor:Comment Deletion IDOR']);
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = await asUser(srv.base, 'alice');
    await c.get('/idor/users/1');
    await c.get('/idor/users/1');
    await c.get('/idor/admin');
    await c.get('/idor/invoice/3');
    await c.get('/idor/invoice/3');
    const got = await idorCaptured(c);
    assert.deepEqual(got.sort(), ['idor:Invoice Download IDOR', 'idor:Profile IDOR', 'idor:Unprotected Admin Panel']);
  });
});
