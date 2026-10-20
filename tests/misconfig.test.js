'use strict';
// Misconfiguration module: every challenge must be solvable by the documented
// technique and must NOT be solvable by the obvious shortcut.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// Raw HTTP request that shares one student's cookie jar with the client
// helper, for the methods and bodies the client helper does not cover (PUT
// with a raw body, TRACE). Uses node:http because fetch refuses TRACE.
const http = require('node:http');

function rawReq(srv, c, method, url, { body, contentType, headers } = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(srv.base);
    const req = http.request(
      {
        host: target.hostname,
        port: target.port,
        path: url,
        method,
        headers: {
          ...(c.cookie() ? { cookie: c.cookie() } : {}),
          ...(contentType ? { 'content-type': contentType } : {}),
          ...(headers || {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const set = res.headers['set-cookie'] || [];
          let cookie = c.cookie();
          for (const sc of set) {
            const pair = sc.split(';')[0];
            const name = pair.split('=')[0];
            cookie = cookie.split('; ').filter((p) => p && !p.startsWith(name + '=')).concat(pair).join('; ');
          }
          c.setCookie(cookie);
          resolve({
            status: res.statusCode,
            text: buf.toString('utf8'),
            buf,
            headers: { get: (n) => res.headers[String(n).toLowerCase()] },
          });
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const BASIC = (u, p) => 'Basic ' + Buffer.from(`${u}:${p}`).toString('base64');

test('misconfig module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  // PUT exploit tests write pwn-*/sb-* scratch files into the misconfig
  // public-files dir; remove them afterwards so runs leave the tree clean.
  t.after(() => {
    const dir = require('node:path').join(__dirname, '..', 'modules', 'misconfig', 'public-files');
    const fs = require('node:fs');
    try {
      for (const f of fs.readdirSync(dir)) {
        if (/^(pwn|sb)-.*\.txt$/.test(f)) {
          try { fs.unlinkSync(require('node:path').join(dir, f)); } catch { /* gone */ }
        }
      }
    } catch { /* dir absent */ }
  });
  const flagOf = (id) => flagFromDb(dataDir, 'misconfig', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/misconfig');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 10);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/misconfig/debug',
      '/misconfig/backup.sql',
      '/misconfig/files/',
      '/misconfig/.git/HEAD',
      '/misconfig/app.js.swp',
      '/misconfig/trace',
      '/misconfig/.env',
      '/misconfig/manager',
      '/misconfig/robots.txt',
      '/misconfig/backup.zip',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('debug: status page alone awards nothing, ?err=1 leaks the flag', async () => {
    const c = client(srv.base);
    const calm = await c.get('/misconfig/debug');
    assert.equal(calm.status, 200);
    assert.deepEqual(await capturedSet(c), [], 'the calm status page must not award');
    const hit = await c.get('/misconfig/debug?err=1');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes('ENOENT'), 'verbose stack trace expected');
    assert.ok(hit.text.includes(flagOf('debug')), 'flag must be in the debug output');
    assert.ok((await capturedSet(c)).includes('misconfig:Verbose Debug Errors'));
  });

  await t.test('backup: guessing wrong names awards nothing, backup.sql captures', async () => {
    const c = client(srv.base);
    assert.equal((await c.get('/misconfig/backup.bak')).status, 404);
    assert.deepEqual(await capturedSet(c), []);
    const r = await c.get('/misconfig/backup.sql');
    assert.equal(r.status, 200);
    assert.ok(r.text.includes('svc_backup'), 'the dump should read like a real database backup');
    // P3-9: the award must be VISIBLE in the response (banner with the real
    // flag), and the old flag-shaped decoy must be gone.
    assert.ok(r.text.includes(flagOf('backup')), 'the real flag must be visible in the served dump banner');
    assert.ok(!r.text.includes('DECOY_DO_NOT_USE'), 'the decoy token must not be served');
    assert.ok((await capturedSet(c)).includes('misconfig:Exposed Database Backup'));
  });

  await t.test('listing: browsing and benign files award nothing, secret.txt captures', async () => {
    const c = client(srv.base);
    const idx = await c.get('/misconfig/files/');
    assert.equal(idx.status, 200);
    assert.ok(idx.text.includes('secret.txt'), 'the listing must expose secret.txt');
    assert.deepEqual(await capturedSet(c), [], 'browsing the listing must not award');
    const readme = await c.get('/misconfig/files/readme.txt');
    assert.equal(readme.status, 200);
    assert.deepEqual(await capturedSet(c), [], 'reading a benign file must not award');
    assert.equal((await c.get('/misconfig/files/nope.txt')).status, 404);
    const hit = await c.get('/misconfig/files/secret.txt');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes('FLAG CAPTURED'), 'the listing capture must be visible in the served file');
    assert.ok(hit.text.includes(flagOf('listing')), 'the real flag must be visible in the served file banner');
    assert.ok(!hit.text.includes('DECOY_DO_NOT_USE'), 'the decoy token must not be served');
    assert.equal((hit.text.match(FLAG_RE) || []).length, 1, 'exactly one flag-shaped string in the served file');
    assert.ok((await capturedSet(c)).includes('misconfig:Directory Listing Leak'));
  });

  await t.test('git: walking HEAD to the commit object, intermediate steps award nothing', async () => {
    const c = client(srv.base);
    const head = await c.get('/misconfig/.git/HEAD');
    assert.equal(head.status, 200);
    assert.ok(head.text.includes('refs/heads/main'));
    assert.deepEqual(await capturedSet(c), [], 'HEAD alone must not award');
    const ref = await c.get('/misconfig/.git/refs/heads/main');
    const commit = ref.text.trim();
    assert.match(commit, /^[0-9a-f]{40}$/, 'the ref must resolve to a commit hash');
    assert.deepEqual(await capturedSet(c), [], 'the ref alone must not award');
    const dir = commit.slice(0, 2);
    const rest = commit.slice(2);
    const objects = await c.get('/misconfig/.git/objects/');
    assert.equal(objects.status, 200);
    assert.deepEqual(await capturedSet(c), [], 'the object listing must not award');
    const hit = await c.get(`/misconfig/.git/objects/${dir}/${rest}`);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('git')), 'the commit diff must carry the flag');
    assert.ok((await capturedSet(c)).includes('misconfig:Exposed .git Directory'));
  });

  await t.test('swp: fetching the swap file leaks the flag', async () => {
    const c = client(srv.base);
    const r = await c.get('/misconfig/app.js.swp');
    assert.equal(r.status, 200);
    assert.ok(r.text.includes('VIM'), 'the swap file should look recovered');
    assert.ok(r.text.includes(flagOf('swp')));
    assert.ok((await capturedSet(c)).includes('misconfig:Vim Swap File Leak'));
  });

  await t.test('trace: GET only explains, a real TRACE reflects and captures', async () => {
    const c = client(srv.base);
    const expl = await c.get('/misconfig/trace');
    assert.equal(expl.status, 200);
    assert.deepEqual(await capturedSet(c), [], 'the explainer page must not award');
    const hit = await rawReq(srv, c, 'TRACE', '/misconfig/trace', { headers: { 'x-probe': 'traceworks' } });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes('x-probe: traceworks'), 'the request must be reflected back');
    assert.ok((await capturedSet(c)).includes('misconfig:HTTP TRACE Enabled (XST)'));
  });

  await t.test('env: the .env file serves the flag as plain text', async () => {
    const c = client(srv.base);
    const r = await c.get('/misconfig/.env');
    assert.equal(r.status, 200);
    assert.ok(r.text.includes('ADMIN_API_TOKEN=' + flagOf('env')));
    assert.ok((await capturedSet(c)).includes('misconfig:Exposed .env File'));
  });

  await t.test('manager: 401 without or with wrong creds, admin:admin captures', async () => {
    const c = client(srv.base);
    assert.equal((await c.get('/misconfig/manager')).status, 401);
    assert.deepEqual(await capturedSet(c), []);
    const wrong = await c.get('/misconfig/manager', { authorization: BASIC('admin', 'password') });
    assert.equal(wrong.status, 401);
    assert.deepEqual(await capturedSet(c), [], 'wrong credentials must not award');
    const hit = await c.get('/misconfig/manager', { authorization: BASIC('admin', 'admin') });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('manager')));
    assert.ok((await capturedSet(c)).includes('misconfig:Default Credentials'));
  });

  await t.test('robots: robots.txt is only a map, the zip is the exploit', async () => {
    const c = client(srv.base);
    const robots = await c.get('/misconfig/robots.txt');
    assert.equal(robots.status, 200);
    assert.ok(robots.text.includes('/misconfig/backup.zip'));
    assert.deepEqual(await capturedSet(c), [], 'reading robots.txt must not award');
    const r = await rawReq(srv, c, 'GET', '/misconfig/backup.zip');
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'application/zip');
    assert.equal(r.buf.subarray(0, 2).toString(), 'PK', 'must be a real zip archive');
    assert.ok(r.text.includes('backup token: ' + flagOf('robots')));
    assert.ok((await capturedSet(c)).includes('misconfig:Robots.txt Disclosure'));
  });

  await t.test('put: bad uploads and upload alone award nothing, read-back captures', async () => {
    const c = client(srv.base);
    const name = 'pwn-' + Date.now() + '.txt';
    const bad = await rawReq(srv, c, 'PUT', '/misconfig/files/' + name);
    assert.equal(bad.status, 400);
    assert.deepEqual(await capturedSet(c), [], 'a bodyless PUT must not award');
    const up = await rawReq(srv, c, 'PUT', '/misconfig/files/' + name, { body: 'hello pentrix', contentType: 'text/plain' });
    assert.equal(up.status, 201);
    assert.deepEqual(await capturedSet(c), [], 'the upload alone must not award');
    const back = await c.get('/misconfig/files/' + name);
    assert.equal(back.status, 200);
    assert.ok(back.text.includes('FLAG CAPTURED'), 'the PUT capture must be visible in the read-back');
    assert.ok(back.text.includes(flagOf('put')), 'the real flag must be visible in the read-back banner');
    assert.ok(back.text.includes('hello pentrix'), 'the read-back must still serve the uploaded content');
    assert.ok((await capturedSet(c)).includes('misconfig:Unauthenticated HTTP PUT'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.get('/misconfig/debug?err=1');
    await c.get('/misconfig/backup.sql');
    await c.get('/misconfig/files/secret.txt');
    const ref = await c.get('/misconfig/.git/refs/heads/main');
    const commit = ref.text.trim();
    await c.get(`/misconfig/.git/objects/${commit.slice(0, 2)}/${commit.slice(2)}`);
    await c.get('/misconfig/app.js.swp');
    await rawReq(srv, c, 'TRACE', '/misconfig/trace');
    await c.get('/misconfig/.env');
    await c.get('/misconfig/manager', { authorization: BASIC('admin', 'admin') });
    await rawReq(srv, c, 'GET', '/misconfig/backup.zip');
    const pname = 'sb-' + Date.now() + '.txt';
    await rawReq(srv, c, 'PUT', '/misconfig/files/' + pname, { body: 'x', contentType: 'text/plain' });
    await c.get('/misconfig/files/' + pname);
    // Repeat captures: still counted once.
    await c.get('/misconfig/debug?err=1');
    await c.get('/misconfig/files/secret.txt');
    const got = (await capturedSet(c)).filter((s) => s.startsWith('misconfig:'));
    assert.equal(got.length, 10);
    assert.equal(new Set(got).size, 10);
  });
});
