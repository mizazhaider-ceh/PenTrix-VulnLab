'use strict';
// CORS module: each lab must be provable through /cors/prove with a genuinely
// vulnerable Origin, and must NOT award for a benign or off-target Origin.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const MOD = 'cors';
const NAMES = [
  'Reflected Origin with Credentials',
  'Null Origin Trusted',
  'Regex Allowlist Bypass',
  'Wildcard on Sensitive Data',
  'Subdomain Suffix Check',
  'Exposed Admin Token Header',
];

test('cors module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, MOD, id);
  const prove = (id, origin) =>
    '/cors/prove?vuln=' + id + (origin === undefined ? '' : '&origin=' + encodeURIComponent(origin));

  await t.test('module page renders, links resolve, no em dash, no flag leak', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/cors');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 6);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/cors/reflect', '/cors/null-origin', '/cors/regex',
      '/cors/wildcard', '/cors/subdomain', '/cors/expose',
      '/cors/prove?vuln=cors-reflect',
      '/cors/api/profile', '/cors/api/settings', '/cors/api/data',
      '/cors/api/users', '/cors/api/partner', '/cors/api/token',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
    assert.equal((await c.get('/cors/prove?vuln=nope')).status, 400);
  });

  await t.test('cors-reflect: any origin is echoed with credentials, proving it earns the flag', async () => {
    const c = client(srv.base);
    const raw = await c.get('/cors/api/profile', { origin: 'https://evil.com' });
    assert.equal(raw.headers.get('access-control-allow-origin'), 'https://evil.com');
    assert.equal(raw.headers.get('access-control-allow-credentials'), 'true');
    // Benign: no Origin header means nothing is reflected, and prove awards nothing.
    const noOrigin = await c.get('/cors/api/profile');
    assert.equal(noOrigin.headers.get('access-control-allow-origin'), null);
    const hit = await c.get(prove('cors-reflect', 'https://evil.com'));
    assert.ok(hit.text.includes(flagOf('cors-reflect')));
    assert.ok((await capturedSet(c)).includes('cors:Reflected Origin with Credentials'));
  });

  await t.test('cors-null: only Origin null is trusted, other origins earn nothing', async () => {
    const c = client(srv.base);
    const other = await c.get('/cors/api/settings', { origin: 'https://evil.com' });
    assert.equal(other.headers.get('access-control-allow-origin'), null);
    const neg = await c.get(prove('cors-null', 'https://evil.com'));
    assert.ok(!neg.text.includes(flagOf('cors-null')), 'a non-null origin must not award');
    const raw = await c.get('/cors/api/settings', { origin: 'null' });
    assert.equal(raw.headers.get('access-control-allow-origin'), 'null');
    assert.equal(raw.headers.get('access-control-allow-credentials'), 'true');
    const hit = await c.get(prove('cors-null', 'null'));
    assert.ok(hit.text.includes(flagOf('cors-null')));
    assert.ok((await capturedSet(c)).includes('cors:Null Origin Trusted'));
  });

  await t.test('cors-regex: evil.com misses the regex, the real domain is excluded, lab.evil.com wins', async () => {
    const c = client(srv.base);
    const miss = await c.get('/cors/api/data', { origin: 'https://evil.com' });
    assert.equal(miss.headers.get('access-control-allow-origin'), null);
    const neg = await c.get(prove('cors-regex', 'https://evil.com'));
    assert.ok(!neg.text.includes(flagOf('cors-regex')), 'an origin outside the regex must not award');
    // The real domain passes the regex but the prove check refuses it as
    // actually ours: headers reflect, yet no flag.
    const own = await c.get(prove('cors-regex', 'https://pentrix.lab'));
    assert.ok(!own.text.includes(flagOf('cors-regex')), 'the genuine pentrix.lab origin must not award');
    const raw = await c.get('/cors/api/data', { origin: 'https://pentrix.lab.evil.com' });
    assert.equal(raw.headers.get('access-control-allow-origin'), 'https://pentrix.lab.evil.com');
    assert.equal(raw.headers.get('access-control-allow-credentials'), 'true');
    const hit = await c.get(prove('cors-regex', 'https://pentrix.lab.evil.com'));
    assert.ok(hit.text.includes(flagOf('cors-regex')));
    assert.ok((await capturedSet(c)).includes('cors:Regex Allowlist Bypass'));
  });

  await t.test('cors-wildcard-data: wildcard on user emails, the prove form alone awards nothing', async () => {
    const c = client(srv.base);
    const raw = await c.get('/cors/api/users');
    assert.equal(raw.headers.get('access-control-allow-origin'), '*');
    assert.ok(raw.text.includes('alice@pentrix.lab'));
    assert.ok(!raw.text.includes(flagOf('cors-wildcard-data')), 'the endpoint itself never awards');
    const form = await c.get(prove('cors-wildcard-data'));
    assert.equal(form.status, 200);
    assert.ok(!form.text.includes(flagOf('cors-wildcard-data')), 'the prove form without an origin must not award');
    const hit = await c.get(prove('cors-wildcard-data', 'https://evil.com'));
    assert.ok(hit.text.includes(flagOf('cors-wildcard-data')));
    assert.ok((await capturedSet(c)).includes('cors:Wildcard on Sensitive Data'));
  });

  await t.test('cors-subdomain: suffix check accepts any invented subdomain label, unrelated hosts and the bare domain do not award', async () => {
    const c = client(srv.base);
    const other = await c.get('/cors/api/partner', { origin: 'https://evil.com' });
    assert.equal(other.headers.get('access-control-allow-origin'), null);
    // The bare trusted domain has no subdomain label: the suffix check fails.
    const bare = await c.get(prove('cors-subdomain', 'https://trusted.pentrix.lab'));
    assert.ok(!bare.text.includes(flagOf('cors-subdomain')), 'the bare trusted domain must not award');
    const raw = await c.get('/cors/api/partner', { origin: 'https://evil.trusted.pentrix.lab' });
    assert.equal(raw.headers.get('access-control-allow-origin'), 'https://evil.trusted.pentrix.lab');
    assert.equal(raw.headers.get('access-control-allow-credentials'), 'true');
    const hit = await c.get(prove('cors-subdomain', 'https://evil.trusted.pentrix.lab'));
    assert.ok(hit.text.includes(flagOf('cors-subdomain')));
    // Any invented label works, not just "evil": the check has no allowlist.
    const c2 = client(srv.base);
    const anyLabel = await c2.get(prove('cors-subdomain', 'https://shop.trusted.pentrix.lab'));
    assert.ok(anyLabel.text.includes(flagOf('cors-subdomain')), 'any invented subdomain label must award');
    assert.ok((await capturedSet(c)).includes('cors:Subdomain Suffix Check'));
  });

  await t.test('cors-expose-headers: admin token exposed to any origin, prove confirms the header combo', async () => {
    const c = client(srv.base);
    const raw = await c.get('/cors/api/token');
    assert.equal(raw.headers.get('access-control-allow-origin'), '*');
    assert.ok((raw.headers.get('access-control-expose-headers') || '').toLowerCase().includes('x-admin-token'));
    assert.ok(raw.headers.get('x-admin-token'));
    assert.ok(!raw.text.includes(flagOf('cors-expose-headers')), 'the endpoint itself never awards');
    const hit = await c.get(prove('cors-expose-headers', 'https://evil.com'));
    assert.ok(hit.text.includes(flagOf('cors-expose-headers')));
    assert.ok((await capturedSet(c)).includes('cors:Exposed Admin Token Header'));
  });

  await t.test('scoreboard counts each captured challenge exactly once', async () => {
    const c = client(srv.base);
    const origins = {
      'cors-reflect': 'https://evil.com',
      'cors-null': 'null',
      'cors-regex': 'https://pentrix.lab.evil.com',
      'cors-wildcard-data': 'https://evil.com',
      'cors-subdomain': 'https://evil.trusted.pentrix.lab',
      'cors-expose-headers': 'https://evil.com',
    };
    for (const [id, origin] of Object.entries(origins)) {
      const r = await c.get(prove(id, origin));
      assert.ok(r.text.includes(flagOf(id)), id + ' did not award');
    }
    // Re-prove one lab: captures must not be duplicated.
    await c.get(prove('cors-reflect', 'https://evil.com'));
    const got = (await capturedSet(c)).filter((s) => s.startsWith('cors:'));
    assert.equal(got.length, 6);
    for (const name of NAMES) {
      assert.ok(got.includes('cors:' + name), name);
    }
  });
});
