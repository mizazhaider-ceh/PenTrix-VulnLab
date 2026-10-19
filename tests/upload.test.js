'use strict';
// Upload module: every challenge must be solvable by the documented technique
// and must NOT be solvable by the obvious shortcut or a benign upload.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// The avatar-overwrite challenge mutates uploads/avatars/avatar-bob.png on
// disk. Snapshot the pristine bytes at load and reset to the text fixture
// before the exploit runs so the test is idempotent across re-runs in the
// same tree. The original PNG is restored afterwards so the working tree
// stays clean.
const AVATAR_BOB = path.join(__dirname, '..', 'uploads', 'avatars', 'avatar-bob.png');
const BOB_ORIGINAL = fs.readFileSync(AVATAR_BOB);
function resetBobAvatar() {
  fs.writeFileSync(AVATAR_BOB, 'BOB-ORIGINAL-AVATAR-v1\n');
}
function restoreBobAvatar() {
  fs.writeFileSync(AVATAR_BOB, BOB_ORIGINAL);
}

// Local raw-binary client: the upload endpoints take raw request bytes, not
// forms. Same cookie-jar behavior as helpers.client, so session-scoped flag
// captures are visible to capturedSet().
function uploadClient(base) {
  let cookie = '';
  async function send(method, url, { body, headers } = {}) {
    const res = await fetch(base + url, {
      method,
      redirect: 'manual',
      headers: { ...(cookie ? { cookie } : {}), ...headers },
      body,
    });
    const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of set) {
      const pair = c.split(';')[0];
      const name = pair.split('=')[0];
      cookie = cookie.split('; ').filter((p) => p && !p.startsWith(name + '=')).concat(pair).join('; ');
    }
    const text = await res.text();
    return { status: res.status, text, headers: res.headers };
  }
  return {
    get: (url, headers) => send('GET', url, { headers }),
    postRaw: (url, body, headers) => send('POST', url, { body, headers }),
  };
}

test('upload module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  t.after(restoreBobAvatar);
  const flagOf = (id) => flagFromDb(dataDir, 'upload', id);
  const OCTET = { 'content-type': 'application/octet-stream' };

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = uploadClient(srv.base);
    const { status, text } = await c.get('/upload');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const id of ['stored-xss', 'upload-double-ext', 'upload-case', 'upload-ctype', 'upload-traversal', 'upload-strip-once', 'upload-overwrite', 'upload-polyglot']) {
      assert.ok(text.includes(`id="${id}"`), `missing card ${id}`);
    }
    const avatar = await c.get('/upload/avatar/bob');
    assert.equal(avatar.status, 200, 'victim avatar route');
    const stored = await c.postRaw('/upload/mime-check?filename=mp-ping.png', Buffer.from('x'), { 'content-type': 'image/png' });
    assert.notEqual(stored.status, 404, 'mime-check route');
    const viewMiss = await c.get('/upload/view/no-such-file-xyz');
    assert.equal(viewMiss.status, 404, 'viewer route handles missing file');
  });

  await t.test('stored-xss: plain file gives nothing, .html with script earns the flag', async () => {
    const c = uploadClient(srv.base);
    const benign = await c.postRaw('/upload?filename=note-x.txt', Buffer.from('just a note'), OCTET);
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('stored-xss')));
    assert.deepEqual(await capturedSet(c), []);
    const hit = await c.postRaw('/upload?filename=xss-a.html', Buffer.from('<html><body><script>alert(1)</script></body></html>'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('stored-xss')));
    const served = await c.get('/uploads/xss-a.html');
    assert.equal(served.status, 200);
    assert.ok(served.text.includes('<script>alert(1)</script>'));
    assert.ok((await capturedSet(c)).includes('upload:Stored XSS via file upload'));
  });

  await t.test('ext-blacklist: exact .svg is blocked, .SVG case bypass earns the flag', async () => {
    const c = uploadClient(srv.base);
    const blocked = await c.postRaw('/upload/ext-blacklist?filename=evil-case.svg', Buffer.from('<svg></svg>'), OCTET);
    assert.equal(blocked.status, 400);
    assert.ok(!blocked.text.includes(flagOf('upload-case')));
    const hit = await c.postRaw('/upload/ext-blacklist?filename=case-a.SVG', Buffer.from('<svg onload="alert(1)"></svg>'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('upload-case')));
    assert.ok(!hit.text.includes(flagOf('upload-double-ext')), 'case bypass must not award the double-extension flag');
    const view = await c.get('/upload/view/case-a.SVG');
    assert.equal(view.status, 200);
    assert.ok(String(view.headers.get('content-type')).includes('image/svg+xml'));
  });

  await t.test('ext-blacklist: plain .jpg gives nothing, shell.svg.jpg earns the flag', async () => {
    const c = uploadClient(srv.base);
    const plain = await c.postRaw('/upload/ext-blacklist?filename=plain-a.jpg', Buffer.from('fakejpg'), OCTET);
    assert.equal(plain.status, 200);
    assert.ok(!plain.text.includes(flagOf('upload-double-ext')));
    const hit = await c.postRaw('/upload/ext-blacklist?filename=shell-a.svg.jpg', Buffer.from('<svg onload="alert(1)"></svg>'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('upload-double-ext')));
    assert.ok(!hit.text.includes(flagOf('upload-case')), 'double extension must not award the case flag');
    const view = await c.get('/upload/view/shell-a.svg.jpg');
    assert.equal(view.status, 200);
    assert.ok(String(view.headers.get('content-type')).includes('image/svg+xml'));
  });

  await t.test('mime-check: html without image header is blocked, spoofed header earns the flag', async () => {
    const c = uploadClient(srv.base);
    const blocked = await c.postRaw('/upload/mime-check?filename=ctype-a.html', Buffer.from('<script>alert(1)</script>'), { 'content-type': 'text/html' });
    assert.equal(blocked.status, 400);
    assert.ok(!blocked.text.includes(flagOf('upload-ctype')));
    const benign = await c.postRaw('/upload/mime-check?filename=ctype-a.png', Buffer.from('PNGDATA'), { 'content-type': 'image/png' });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('upload-ctype')), 'a real image upload must not award');
    const hit = await c.postRaw('/upload/mime-check?filename=ctype-b.html', Buffer.from('<script>alert(1)</script>'), { 'content-type': 'image/png' });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('upload-ctype')));
  });

  await t.test('traverse: plain name stays inside, ../ escapes and earns the flag', async () => {
    const c = uploadClient(srv.base);
    const inside = await c.postRaw('/upload/traverse?filename=trav-inside.txt', Buffer.from('inside'), OCTET);
    assert.equal(inside.status, 200);
    assert.ok(!inside.text.includes(flagOf('upload-traversal')));
    const hit = await c.postRaw('/upload/traverse?filename=../trav-escape.txt', Buffer.from('escaped-by-test'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('upload-traversal')));
    const back = await c.get('/upload/traversed?f=../trav-escape.txt');
    assert.equal(back.status, 200);
    assert.ok(back.text.includes('escaped-by-test'));
  });

  await t.test('filter: single strip neuters .svg, nested name rebuilds it and earns the flag', async () => {
    const c = uploadClient(srv.base);
    const neutered = await c.postRaw('/upload/filter?filename=strip-plain.svg', Buffer.from('<svg></svg>'), OCTET);
    assert.equal(neutered.status, 200);
    assert.ok(!neutered.text.includes(flagOf('upload-strip-once')), 'stripped name must not award');
    const hit = await c.postRaw('/upload/filter?filename=strip-a.s.svgvg', Buffer.from('<svg onload="alert(1)"></svg>'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('upload-strip-once')));
    const view = await c.get('/upload/view/strip-a.svg');
    assert.equal(view.status, 200);
    assert.ok(String(view.headers.get('content-type')).includes('image/svg+xml'));
  });

  await t.test('avatar: other users give nothing, overwriting bob earns the flag', async () => {
    resetBobAvatar();
    const c = uploadClient(srv.base);
    const before = await c.get('/upload/avatar/bob');
    assert.equal(before.status, 200);
    assert.ok(before.text.includes('BOB-ORIGINAL-AVATAR-v1'));
    const other = await c.postRaw('/upload/avatar?user=alice', Buffer.from('ALICE-BYTES'), OCTET);
    assert.equal(other.status, 200);
    assert.ok(!other.text.includes(flagOf('upload-overwrite')), 'own avatar must not award');
    const hit = await c.postRaw('/upload/avatar?user=bob', Buffer.from('<script>alert(1)</script>'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('upload-overwrite')));
    const after = await c.get('/upload/avatar/bob');
    assert.ok(after.text.includes('<script>alert(1)</script>'));
    assert.ok(String(after.headers.get('content-type')).includes('text/html'), 'replaced avatar is sniffed as html');
  });

  await t.test('polyglot: non-gif blocked, gif without html gives nothing, full polyglot earns the flag', async () => {
    const c = uploadClient(srv.base);
    const blocked = await c.postRaw('/upload/polyglot?filename=poly-a.gif', Buffer.from('not a gif at all'), OCTET);
    assert.equal(blocked.status, 400);
    const plain = await c.postRaw('/upload/polyglot?filename=poly-b.gif', Buffer.from('GIF89aplain-bytes'), OCTET);
    assert.equal(plain.status, 200);
    assert.ok(!plain.text.includes(flagOf('upload-polyglot')), 'gif header without html must not award');
    const hit = await c.postRaw('/upload/polyglot?filename=poly-c.gif', Buffer.from('GIF89a<script>alert(1)</script>'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('upload-polyglot')));
    const rendered = await c.get('/upload/poly/poly-c.gif');
    assert.equal(rendered.status, 200);
    assert.ok(String(rendered.headers.get('content-type')).includes('text/html'));
    assert.ok(rendered.text.includes('<script>alert(1)</script>'));
  });

  await t.test('oversized upload is rejected with 413', async () => {
    const c = uploadClient(srv.base);
    const big = Buffer.alloc(2 * 1024 * 1024 + 1, 'a');
    const r = await c.postRaw('/upload?filename=big.bin', big, OCTET);
    assert.equal(r.status, 413);
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = uploadClient(srv.base);
    await c.postRaw('/upload?filename=sb.html', Buffer.from('<script>1</script>'), OCTET);
    await c.postRaw('/upload/ext-blacklist?filename=sb.SVG', Buffer.from('<svg></svg>'), OCTET);
    await c.postRaw('/upload/ext-blacklist?filename=sb.svg.jpg', Buffer.from('<svg></svg>'), OCTET);
    await c.postRaw('/upload/mime-check?filename=sb2.html', Buffer.from('<script>1</script>'), { 'content-type': 'image/png' });
    await c.postRaw('/upload/traverse?filename=../sb-escape.txt', Buffer.from('x'), OCTET);
    await c.postRaw('/upload/filter?filename=sb.s.svgvg', Buffer.from('<svg></svg>'), OCTET);
    await c.postRaw('/upload/avatar?user=bob', Buffer.from('SB-BYTES'), OCTET);
    await c.postRaw('/upload/polyglot?filename=sb.gif', Buffer.from('GIF89a<script>1</script>'), OCTET);
    const got = (await capturedSet(c)).filter((s) => s.startsWith('upload:'));
    assert.equal(got.length, 8);
    assert.deepEqual([...got].sort(), [
      'upload:Avatar overwrite',
      'upload:Case-sensitive blacklist bypass',
      'upload:Content-Type header spoofing',
      'upload:Extension blacklist bypass',
      'upload:GIF/HTML polyglot',
      'upload:Path traversal on write',
      'upload:Stored XSS via file upload',
      'upload:Strip-once filter bypass',
    ]);
  });
});
