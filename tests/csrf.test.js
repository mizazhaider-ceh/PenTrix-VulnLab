'use strict';
// CSRF module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut. Clickjacking needs a real
// browser to physically click; here we replay exactly what the framed page
// does (load the demo, load the framed victim with its token, post the form).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const NAMES = {
  email: 'Change Email with No CSRF Token (state-changing GET)',
  clickjacking: 'Clickjacking (missing X-Frame-Options)',
  'json-csrf': 'JSON API CSRF via text/plain (simple request)',
  'referer-bypass': 'Weak Referer Check Bypass',
  'method-override-csrf': 'HTTP Method Override Smuggling (_method=DELETE)',
};
const key = (id) => `csrf:${NAMES[id]}`;
const decode = (s) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'");
const flagsIn = (text) => text.match(FLAG_RE) || [];

// Shared UI assertions applied to every page this file fetches.
function checkUi(text, label) {
  assert.ok(!text.includes('\u2014'), `em dash in ${label}`);
  assert.ok(!/\sstyle=/.test(text), `inline style in ${label}`);
  assert.ok(!/<style[\s>]/.test(text), `style block in ${label}`);
  assert.ok(!/<table(?![^>]*class=)/.test(text), `bare table in ${label}`);
  for (const m of text.matchAll(/<table[^>]*>/g)) assert.ok(/class="tbl"/.test(m[0]), `table class in ${label}`);
  for (const m of text.matchAll(/<(input|select|textarea|button)\b[^>]*>/g)) {
    if (/type="hidden"/.test(m[0])) continue;
    assert.ok(/class="[^"]*(clay-input|clay-select|clay-btn|copy-btn)/.test(m[0]), `unstyled control ${m[0]} in ${label}`);
  }
}

function hrefsOf(text) {
  return [...text.matchAll(/(?:href|src)="([^"]+)"/g)]
    .map((m) => decode(m[1]))
    .filter((h) => h.startsWith('/') && !h.startsWith('//'));
}

function formsOf(text) {
  return [...text.matchAll(/<form\b[^>]*>/g)].map((m) => ({
    method: ((m[0].match(/method="(\w+)"/i) || [])[1] || 'get').toUpperCase(),
    action: decode((m[0].match(/action="([^"]*)"/) || [])[1] || ''),
  }));
}

test('csrf module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'csrf', id);
  const login = async () => {
    const c = client(srv.base);
    await c.get('/csrf/login/alice');
    return c;
  };
  // Raw request with a custom body and content type, reusing the client's cookie jar.
  const raw = async (c, method, url, body, headers) => {
    const res = await fetch(srv.base + url, {
      method,
      redirect: 'manual',
      headers: { cookie: c.cookie(), ...headers },
      body,
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, text, json, headers: res.headers };
  };

  await t.test('module index renders cleanly with a way into every challenge', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/csrf');
    assert.equal(status, 200);
    checkUi(text, '/csrf');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 5);
    assert.equal(flagsIn(text).length, 0);
    for (const id of Object.keys(NAMES)) assert.ok(text.includes(`id="${id}"`), `card ${id}`);
    for (const p of ['/csrf/change-email', '/csrf/framedemo', '/csrf/json-email', '/csrf/nickname', '/csrf/account']) {
      assert.ok(text.includes(`href="${p}"`), `index links to ${p}`);
    }
    assert.equal((text.match(/Hint \d: (Nudge|Technique|Explicit)/g) || []).length, 15, '3 hints per challenge');
  });

  await t.test('source files contain no em dash', () => {
    const root = path.join(__dirname, '..', 'modules', 'csrf');
    const files = [path.join(root, 'index.js'), path.join(root, 'shared.js'),
      ...fs.readdirSync(path.join(root, 'challenges')).map((f) => path.join(root, 'challenges', f)), __filename];
    for (const f of files) assert.ok(!fs.readFileSync(f, 'utf8').includes('\u2014'), `em dash in ${f}`);
  });

  await t.test('every page is styled, flag-free in normal views, and every link resolves', async () => {
    const out = client(srv.base);
    const anon = await out.get('/csrf/change-email');
    assert.equal(anon.status, 200);
    checkUi(anon.text, 'logged-out prompt');
    assert.ok(anon.text.includes('/csrf/login/alice'));

    const c = await login();
    const pages = ['/csrf', '/csrf/change-email', '/csrf/framedemo', '/csrf/vip-action', '/csrf/json-email', '/csrf/nickname', '/csrf/account'];
    const seen = new Set(pages);
    const links = new Set();
    const forms = new Map();
    for (const p of pages) {
      const r = await c.get(p);
      assert.equal(r.status, 200, p);
      checkUi(r.text, p);
      assert.equal(flagsIn(r.text).length, 0, `flag leaked in ${p}`);
      if (p !== '/csrf' && p !== '/csrf/vip-action') assert.equal((r.text.match(/Hint \d: (Nudge|Technique|Explicit)/g) || []).length, 3, `hint ladder on ${p}`);
      for (const h of hrefsOf(r.text)) links.add(h);
      for (const f of formsOf(r.text)) forms.set(`${f.method} ${f.action}`, f);
    }
    // Follow links with a throwaway browser so forged links cannot award this session.
    const walker = client(srv.base);
    for (const h of links) {
      if (seen.has(h)) continue;
      const r = await walker.get(h);
      assert.notEqual(r.status, 404, `dead link ${h}`);
    }
    for (const f of forms.values()) {
      assert.ok(f.action.startsWith('/'), `form action ${f.action}`);
      const r = f.method === 'POST' ? await walker.post(f.action, {}) : await walker.get(f.action);
      assert.notEqual(r.status, 404, `dead form action ${f.method} ${f.action}`);
    }
    // Error and failure pages are styled too.
    const bad = await raw(c, 'POST', '/csrf/api/nickname', 'nickname=x', { 'content-type': 'application/x-www-form-urlencoded' });
    assert.equal(bad.status, 403);
    checkUi(bad.text, '403 referer page');
  });

  await t.test('email: only the forged state-changing GET earns the flag', async () => {
    const flag = flagOf('email');
    const nobody = client(srv.base);
    const anon = await nobody.get('/csrf/change-email?email=x@evil.com');
    assert.equal(flagsIn(anon.text).length, 0, 'no session, no change');

    const c = await login();
    const form = await c.get('/csrf/change-email');
    assert.equal(flagsIn(form.text).length, 0, 'viewing the form is not the exploit');
    const empty = await c.get('/csrf/change-email?email=%20%20');
    assert.equal(flagsIn(empty.text).length, 0, 'empty email changes nothing');
    assert.deepEqual((await capturedSet(c)).filter((s) => s.startsWith('csrf:')), []);

    const hit = await c.get('/csrf/change-email?email=pwned%40evil.com');
    checkUi(hit.text, 'email success');
    assert.deepEqual(flagsIn(hit.text), [flag]);
    assert.ok(hit.text.includes('pwned@evil.com'));
    assert.ok((await c.get('/csrf/change-email')).text.includes('pwned@evil.com'), 'email really changed');
    assert.ok((await capturedSet(c)).includes(key('email')));
    await c.get('/csrf/change-email?email=again%40evil.com');
    assert.equal((await capturedSet(c)).filter((s) => s === key('email')).length, 1, 'no double count');
  });

  await t.test('clickjacking: the full framing chain is required', async () => {
    const flag = flagOf('clickjacking');
    // A bare POST, with or without a made-up token, earns nothing.
    const bare = await login();
    assert.equal(flagsIn((await bare.post('/csrf/vip-action', {})).text).length, 0);
    assert.equal(flagsIn((await bare.post('/csrf/vip-action', { frame: 'deadbeef' })).text).length, 0);

    // Visiting the demo and posting its token without ever loading the frame earns nothing.
    const lazy = await login();
    const demo0 = await lazy.get('/csrf/framedemo');
    assert.equal(flagsIn(demo0.text).length, 0, 'visiting the demo is not the exploit');
    const nonce0 = decode(demo0.text.match(/src="\/csrf\/vip-action\?frame=([0-9a-f]+)"/)[1]);
    assert.equal(flagsIn((await lazy.post('/csrf/vip-action', { frame: nonce0 })).text).length, 0, 'token never seen on a framed load');

    // Loading the frame with a wrong token does not register as a framed load.
    const wrong = await login();
    const demoW = await wrong.get('/csrf/framedemo');
    const nonceW = demoW.text.match(/frame=([0-9a-f]+)"/)[1];
    await wrong.get('/csrf/vip-action?frame=0000');
    assert.equal(flagsIn((await wrong.post('/csrf/vip-action', { frame: nonceW })).text).length, 0);

    // The real chain: demo issues the token, the framed victim page loads with it, the framed form posts it back.
    const c = await login();
    const demo = await c.get('/csrf/framedemo');
    checkUi(demo.text, 'framedemo');
    const nonce = demo.text.match(/src="\/csrf\/vip-action\?frame=([0-9a-f]+)"/)[1];
    const framed = await c.get(`/csrf/vip-action?frame=${nonce}`);
    assert.equal(framed.headers.get('x-frame-options'), null, 'the victim page must be frameable');
    assert.ok(!/frame-ancestors/i.test(framed.headers.get('content-security-policy') || ''));
    assert.ok(framed.text.includes(`name="frame" value="${nonce}"`), 'framed page carries the token');
    checkUi(framed.text, 'vip-action framed');
    const hit = await c.post('/csrf/vip-action', { frame: nonce });
    checkUi(hit.text, 'vip-action success');
    assert.deepEqual(flagsIn(hit.text), [flag]);
    assert.ok((await capturedSet(c)).includes(key('clickjacking')));
    // The token is single use.
    const again = await c.post('/csrf/vip-action', { frame: nonce });
    assert.equal(flagsIn(again.text).length, 0, 'token cannot be replayed');
    assert.equal((await capturedSet(c)).filter((s) => s === key('clickjacking')).length, 1);
  });

  await t.test('json-csrf: only a text/plain body carrying JSON earns the flag', async () => {
    const flag = flagOf('json-csrf');
    const nobody = client(srv.base);
    const anon = await raw(nobody, 'POST', '/csrf/api/email', '{"email":"a@evil.com"}', { 'content-type': 'text/plain' });
    assert.equal(anon.status, 401);

    const c = await login();
    const page = await c.get('/csrf/json-email');
    assert.ok(/<form[^>]*enctype="text\/plain"/.test(page.text), 'attack form uses text/plain');
    const junk = await raw(c, 'POST', '/csrf/api/email', 'hello there', { 'content-type': 'text/plain' });
    assert.equal(junk.status, 400);
    assert.equal(flagsIn(junk.text).length, 0);
    const form = await c.post('/csrf/api/email', { email: 'form@evil.com' });
    assert.equal(form.status, 400, 'urlencoded form is not accepted');
    assert.equal(flagsIn(form.text).length, 0);
    // The genuine JSON client works but is not the exploit.
    const legit = await raw(c, 'POST', '/csrf/api/email', JSON.stringify({ email: 'legit@pentrix.lab' }), { 'content-type': 'application/json' });
    assert.equal(legit.status, 200);
    assert.equal(legit.json.ok, true);
    assert.equal(flagsIn(legit.text).length, 0, 'a real JSON call is not a cross-site forgery');
    const missing = await raw(c, 'POST', '/csrf/api/email', JSON.stringify({ nope: 1 }), { 'content-type': 'application/json' });
    assert.equal(missing.status, 400);
    assert.deepEqual((await capturedSet(c)).filter((s) => s.startsWith('csrf:')), []);

    // Exactly what the auto-submitting enctype="text/plain" form sends.
    const hit = await raw(c, 'POST', '/csrf/api/email', '{"email":"attacker@evil.com"}=ignored', { 'content-type': 'text/plain' });
    assert.equal(hit.status, 200);
    checkUi(hit.text, 'json-csrf success');
    assert.deepEqual(flagsIn(hit.text), [flag]);
    assert.ok((await c.get('/csrf/json-email')).text.includes('attacker@evil.com'), 'email really changed');
    assert.ok((await capturedSet(c)).includes(key('json-csrf')));
    await raw(c, 'POST', '/csrf/api/email', '{"email":"x@evil.com"}=1', { 'content-type': 'text/plain' });
    assert.equal((await capturedSet(c)).filter((s) => s === key('json-csrf')).length, 1);
  });

  await t.test('referer-bypass: a trusted-looking substring in a foreign Referer earns the flag', async () => {
    const flag = flagOf('referer-bypass');
    const post = (c, referer, nick = 'hacked') => raw(c, 'POST', '/csrf/api/nickname', `nickname=${nick}`, {
      'content-type': 'application/x-www-form-urlencoded',
      ...(referer ? { referer } : {}),
    });
    const nobody = client(srv.base);
    assert.equal((await post(nobody, 'https://evil.com/?pentrix.lab')).status, 401);

    const c = await login();
    assert.equal((await post(c, null)).status, 403, 'no Referer');
    const foreign = await post(c, 'https://evil.com/');
    assert.equal(foreign.status, 403, 'foreign Referer without the magic string');
    assert.equal(flagsIn(foreign.text).length, 0);
    const legitForm = await post(c, `${srv.base}/csrf/nickname`);
    assert.equal(legitForm.status, 403, 'this lab is not served from pentrix.lab');
    assert.equal(flagsIn(legitForm.text).length, 0);
    // A same-origin referer that happens to contain the string is a legitimate request, not a forgery.
    const same = await post(c, `${srv.base}/csrf/nickname?pentrix.lab`, 'honest');
    assert.equal(same.status, 200);
    assert.equal(flagsIn(same.text).length, 0, 'same-origin request is not the exploit');
    assert.deepEqual((await capturedSet(c)).filter((s) => s.startsWith('csrf:')), []);

    const hit = await post(c, 'https://evil.com/?pentrix.lab');
    assert.equal(hit.status, 200);
    checkUi(hit.text, 'referer-bypass success');
    assert.deepEqual(flagsIn(hit.text), [flag]);
    assert.ok((await c.get('/csrf/nickname')).text.includes('hacked'), 'nickname really changed');
    assert.ok((await capturedSet(c)).includes(key('referer-bypass')));
    await post(c, 'https://attacker.test/pentrix.lab/x', 'again');
    assert.equal((await capturedSet(c)).filter((s) => s === key('referer-bypass')).length, 1);
  });

  await t.test('method-override-csrf: only the _method=DELETE smuggle earns the flag', async () => {
    const flag = flagOf('method-override-csrf');
    const nobody = client(srv.base);
    assert.equal((await nobody.post('/csrf/account', { _method: 'DELETE' })).status, 401);

    const plain = await login();
    assert.equal(flagsIn((await plain.post('/csrf/account', {})).text).length, 0, 'plain POST does nothing');
    assert.equal(flagsIn((await plain.post('/csrf/account', { _method: 'PUT' })).text).length, 0, 'other overrides do nothing');
    assert.ok((await plain.get('/csrf/account')).text.includes('active'));

    // The proper DELETE deletes but is not the challenge.
    const del = await login();
    const real = await raw(del, 'DELETE', '/csrf/account');
    assert.equal(real.status, 200);
    assert.equal(flagsIn(real.text).length, 0, 'a real DELETE earns no flag');
    assert.ok((await del.get('/csrf/account')).text.includes('DELETED'));
    assert.deepEqual((await capturedSet(del)).filter((s) => s.startsWith('csrf:')), []);

    const c = await login();
    const hit = await c.post('/csrf/account', { _method: 'DELETE' });
    checkUi(hit.text, 'method-override success');
    assert.deepEqual(flagsIn(hit.text), [flag]);
    assert.ok((await c.get('/csrf/account')).text.includes('DELETED'));
    assert.ok((await capturedSet(c)).includes(key('method-override-csrf')));
    await c.post('/csrf/account', { _method: 'delete' });
    assert.equal((await capturedSet(c)).filter((s) => s === key('method-override-csrf')).length, 1);
  });

  await t.test('scoreboard counts each captured csrf challenge exactly once', async () => {
    const c = await login();
    await c.get('/csrf/change-email?email=sb%40evil.com');
    await c.get('/csrf/change-email?email=sb2%40evil.com');
    await c.post('/csrf/account', { _method: 'DELETE' });
    await c.post('/csrf/account', { _method: 'DELETE' });
    const demo = await c.get('/csrf/framedemo');
    const nonce = demo.text.match(/frame=([0-9a-f]+)"/)[1];
    await c.get(`/csrf/vip-action?frame=${nonce}`);
    await c.post('/csrf/vip-action', { frame: nonce });
    const got = (await capturedSet(c)).filter((s) => s.startsWith('csrf:')).sort();
    assert.deepEqual(got, [key('clickjacking'), key('email'), key('method-override-csrf')].sort());
  });
});
