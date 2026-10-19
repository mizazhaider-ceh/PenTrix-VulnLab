'use strict';
// OAuth module: every challenge must be solvable by the documented technique
// and must NOT be solvable by the obvious shortcut or benign action.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const CALLBACK = 'http://app.pentrix.lab/callback';
const EVIL_CB = 'http://app.pentrix.lab.evil.com/cb';

// POST the IdP approval form directly (what the consent screen submits).
async function approve(c, form) {
  const r = await c.post('/oauth/idp/approve', form);
  assert.equal(r.status, 200, 'approve should succeed');
  return r.text;
}

function codeOf(text) {
  const m = text.match(/\?code=([0-9a-f]{32})/);
  assert.ok(m, 'no authorization code on the approve page');
  return m[1];
}

function tokenOf(text) {
  const m = text.match(/#access_token=([0-9a-f]{48})/);
  assert.ok(m, 'no access token on the implicit approve page');
  return m[1];
}

async function exchange(c, params) {
  return c.post('/oauth/idp/token', params);
}

test('oauth module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'oauth', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/oauth');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/oauth/redirect-bypass', '/oauth/code-leak', '/oauth/no-state',
      '/oauth/implicit', '/oauth/scope-upgrade', '/oauth/secret-in-js',
      '/oauth/code-replay', '/oauth/pkce-skip',
      '/oauth/idp/log', '/oauth/client/', '/oauth/client/history',
      '/oauth/login/alice', '/oauth/login/bob', '/oauth/login/admin',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('redirect-bypass: legit redirect earns nothing, prefix-bypass URI earns the flag', async () => {
    const c = client(srv.base);
    await c.get('/oauth/login/alice');
    const legit = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    assert.ok(!legit.includes(flagOf('redirect-bypass')), 'legit redirect must not award');
    assert.ok(/\?code=/.test(legit), 'legit flow should still issue a code');
    const evil = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: EVIL_CB, response_type: 'code', scope: 'read',
    });
    assert.ok(evil.includes(flagOf('redirect-bypass')));
    assert.ok((await capturedSet(c)).includes('oauth:Redirect URI Prefix Bypass'));
  });

  await t.test('code-leak: own code earns nothing, a logged code spent by someone else earns the flag', async () => {
    const c = client(srv.base);
    // Benign: alice exchanges her own freshly issued code.
    await c.get('/oauth/login/alice');
    const ownText = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    const own = await exchange(c, { client_id: 'pentrix-spa', code: codeOf(ownText) });
    assert.equal(own.status, 200);
    assert.ok(!('flag' in own.body), 'exchanging your own code must not award');
    // Exploit: grab a code from the world-readable log and spend it with no IdP session.
    const attacker = client(srv.base);
    const log = await attacker.get('/oauth/idp/log');
    const m = log.text.match(/code=([0-9a-f]{32})/);
    assert.ok(m, 'expected a code in the IdP log');
    const hit = await exchange(attacker, { client_id: 'pentrix-spa', code: m[1] });
    assert.equal(hit.status, 200);
    assert.equal(hit.body.flag, flagOf('code-leak'));
    assert.ok((await capturedSet(attacker)).includes('oauth:Authorization Code Leaked in Server Log'));
  });

  await t.test('no-state: own code at the callback earns nothing, attacker code logs the victim in as the attacker', async () => {
    const c = client(srv.base);
    await c.get('/oauth/login/bob');
    // Benign: visiting the callback with your own code awards nothing.
    const ownText = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    const benign = await c.get('/oauth/client/callback?code=' + codeOf(ownText));
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('no-state')), 'own code at the callback must not award');
    // Exploit: mint a code for bob, then let alice (the victim) visit the link.
    const gen = await c.get('/oauth/no-state/attacker');
    const m = gen.text.match(/\/oauth\/client\/callback\?code=([0-9a-f]{32})/);
    assert.ok(m, 'no malicious login link generated');
    const victim = client(srv.base);
    await victim.get('/oauth/login/alice');
    const hit = await victim.get('/oauth/client/callback?code=' + m[1]);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('no-state')));
    assert.ok(hit.text.includes('bob'), 'victim should be logged in as the attacker');
    assert.ok((await capturedSet(victim)).includes('oauth:Login CSRF (Missing state Parameter)'));
  });

  await t.test('implicit: owner use of the token earns nothing, a history-stolen token earns the flag', async () => {
    const alice = client(srv.base);
    await alice.get('/oauth/login/alice');
    const text = await approve(alice, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'token', scope: 'read',
    });
    const tok = tokenOf(text);
    // The victim's own call is not the exploit.
    const own = await alice.get('/oauth/idp/userinfo?access_token=' + tok);
    assert.equal(own.status, 200);
    assert.ok(!('flag' in own.body), 'the token owner must not get the flag');
    // Simulate the victim browser recording the fragment URL in its history.
    const logged = await alice.postJson('/oauth/client/history-log', {
      url: CALLBACK + '#access_token=' + tok + '&token_type=Bearer',
    });
    assert.equal(logged.body.ok, true);
    // The attacker reads the history, steals the token, and calls userinfo.
    const attacker = client(srv.base);
    const history = await attacker.get('/oauth/client/history');
    assert.ok(history.text.includes(tok), 'token should be visible in the recorded history');
    const hit = await attacker.get('/oauth/idp/userinfo?access_token=' + tok);
    assert.equal(hit.status, 200);
    assert.equal(hit.body.flag, flagOf('implicit'));
    assert.ok((await capturedSet(attacker)).includes('oauth:Implicit Flow Token in URL Fragment'));
  });

  await t.test('scope-upgrade: read scope is refused, admin scope granted to a plain user earns the flag', async () => {
    const c = client(srv.base);
    await c.get('/oauth/login/bob');
    // Benign: a read-scoped token cannot read admin data.
    const readText = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    const readTok = await exchange(c, { client_id: 'pentrix-spa', code: codeOf(readText) });
    const denied = await c.get('/oauth/idp/admin-data?access_token=' + readTok.body.access_token);
    assert.equal(denied.status, 403);
    // Exploit: request scope=admin as a plain user.
    const adminText = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'admin',
    });
    const adminTok = await exchange(c, { client_id: 'pentrix-spa', code: codeOf(adminText) });
    const hit = await c.get('/oauth/idp/admin-data?access_token=' + adminTok.body.access_token);
    assert.equal(hit.status, 200);
    assert.equal(hit.body.flag, flagOf('scope-upgrade'));
    assert.ok((await capturedSet(c)).includes('oauth:Scope Tampering'));
    // Benign: a real admin reading admin data earns nothing.
    const a2 = client(srv.base);
    await a2.get('/oauth/login/admin');
    const a2Text = await approve(a2, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'admin',
    });
    const a2Tok = await exchange(a2, { client_id: 'pentrix-spa', code: codeOf(a2Text) });
    const a2Hit = await a2.get('/oauth/idp/admin-data?access_token=' + a2Tok.body.access_token);
    assert.equal(a2Hit.status, 200);
    assert.ok(!('flag' in a2Hit.body), 'a real admin must not get the flag');
  });

  await t.test('secret-in-js: exchange without the secret fails, with the leaked secret earns the flag', async () => {
    const c = client(srv.base);
    const js = await c.get('/oauth/client/app.js');
    const m = js.text.match(/CLIENT_SECRET = '([^']+)'/);
    assert.ok(m, 'client secret should be readable in the public bundle');
    await c.get('/oauth/login/bob');
    const text = await approve(c, {
      client_id: 'pentrix-client', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    const code = codeOf(text);
    // Benign: no secret, no token.
    const bad = await exchange(c, { client_id: 'pentrix-client', code });
    assert.equal(bad.status, 401);
    assert.ok(!('flag' in bad.body));
    // Exploit: the secret from the public bundle, direct token call.
    const hit = await exchange(c, { client_id: 'pentrix-client', client_secret: m[1], code });
    assert.equal(hit.status, 200);
    assert.equal(hit.body.flag, flagOf('secret-in-js'));
    assert.ok((await capturedSet(c)).includes('oauth:Client Secret in Public JavaScript'));
  });

  await t.test('code-replay: first exchange earns nothing, second exchange of the same code earns the flag', async () => {
    const c = client(srv.base);
    await c.get('/oauth/login/bob');
    const text = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    const code = codeOf(text);
    const first = await exchange(c, { client_id: 'pentrix-spa', code });
    assert.equal(first.status, 200);
    assert.ok(first.body.access_token);
    assert.ok(!('flag' in first.body), 'first exchange must not award');
    const second = await exchange(c, { client_id: 'pentrix-spa', code });
    assert.equal(second.status, 200);
    assert.ok(second.body.access_token);
    assert.notEqual(second.body.access_token, first.body.access_token, 'replay should mint a fresh token');
    assert.equal(second.body.flag, flagOf('code-replay'));
    assert.ok((await capturedSet(c)).includes('oauth:Authorization Code Replay'));
  });

  await t.test('pkce-skip: plain code earns nothing, challenge-bound code without a verifier earns the flag', async () => {
    const c = client(srv.base);
    await c.get('/oauth/login/bob');
    // Benign: a code with no challenge awards nothing.
    const plainText = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    const plain = await exchange(c, { client_id: 'pentrix-spa', code: codeOf(plainText) });
    assert.equal(plain.status, 200);
    assert.ok(!('flag' in plain.body));
    // Exploit: bind a challenge, then exchange with no verifier at all.
    const boundText = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
    });
    const hit = await exchange(c, { client_id: 'pentrix-spa', code: codeOf(boundText) });
    assert.equal(hit.status, 200);
    assert.equal(hit.body.flag, flagOf('pkce-skip'));
    assert.ok((await capturedSet(c)).includes('oauth:PKCE Downgrade'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.get('/oauth/login/bob');
    // redirect-bypass
    await approve(c, { client_id: 'pentrix-spa', redirect_uri: EVIL_CB, response_type: 'code', scope: 'read' });
    // code-leak (seeded alice code from the log, spent with bob's session... use fresh client with no session)
    const leak = client(srv.base);
    const log = await leak.get('/oauth/idp/log');
    const lm = log.text.match(/code=([0-9a-f]{32})/);
    assert.ok(lm, 'expected a code in the IdP log');
    await exchange(leak, { client_id: 'pentrix-spa', code: lm[1] });
    // no-state
    const gen = await c.get('/oauth/no-state/attacker');
    const nm = gen.text.match(/\/oauth\/client\/callback\?code=([0-9a-f]{32})/);
    const victim = client(srv.base);
    await victim.get('/oauth/login/alice');
    await victim.get('/oauth/client/callback?code=' + nm[1]);
    // implicit
    const alice = client(srv.base);
    await alice.get('/oauth/login/alice');
    const itext = await approve(alice, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'token', scope: 'read',
    });
    const itok = tokenOf(itext);
    const atk = client(srv.base);
    await atk.get('/oauth/idp/userinfo?access_token=' + itok);
    // scope-upgrade
    const stext = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'admin',
    });
    const stok = await exchange(c, { client_id: 'pentrix-spa', code: codeOf(stext) });
    await c.get('/oauth/idp/admin-data?access_token=' + stok.body.access_token);
    // secret-in-js
    const js = await c.get('/oauth/client/app.js');
    const sm = js.text.match(/CLIENT_SECRET = '([^']+)'/);
    const jtext = await approve(c, {
      client_id: 'pentrix-client', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    await exchange(c, { client_id: 'pentrix-client', client_secret: sm[1], code: codeOf(jtext) });
    // code-replay (exchange twice; only the second awards)
    const rtext = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
    });
    const rcode = codeOf(rtext);
    await exchange(c, { client_id: 'pentrix-spa', code: rcode });
    await exchange(c, { client_id: 'pentrix-spa', code: rcode });
    // pkce-skip
    const ptext = await approve(c, {
      client_id: 'pentrix-spa', redirect_uri: CALLBACK, response_type: 'code', scope: 'read',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
    });
    await exchange(c, { client_id: 'pentrix-spa', code: codeOf(ptext) });

    const got = (await capturedSet(c)).filter((s) => s.startsWith('oauth:'));
    assert.deepEqual(got.sort(), [
      'oauth:Authorization Code Replay',
      'oauth:Client Secret in Public JavaScript',
      'oauth:PKCE Downgrade',
      'oauth:Redirect URI Prefix Bypass',
      'oauth:Scope Tampering',
    ]);
    const leakGot = (await capturedSet(leak)).filter((s) => s.startsWith('oauth:'));
    assert.deepEqual(leakGot, ['oauth:Authorization Code Leaked in Server Log']);
    const victimGot = (await capturedSet(victim)).filter((s) => s.startsWith('oauth:'));
    assert.deepEqual(victimGot, ['oauth:Login CSRF (Missing state Parameter)']);
    const atkGot = (await capturedSet(atk)).filter((s) => s.startsWith('oauth:'));
    assert.deepEqual(atkGot, ['oauth:Implicit Flow Token in URL Fragment']);
  });
});
