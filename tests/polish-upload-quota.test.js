'use strict';
// Upload quota is per-session accounting (P1B): one session flooding past
// its own quota evicts only its own oldest files. Another session's stored
// files must survive byte-identical, and their beacon proof must still
// verify afterwards. Regression guard against the old global newest-200
// sweep, where one flooding student evicted every other student's files.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { bootLab, flagFromDb } = require('./helpers');

const UPLOADS_ROOT = path.join(__dirname, '..', 'uploads');
const KEEPER = 'quota-keeper-b.html';
const FLOOD_COUNT = 205; // the per-session cap in shared.js is 200
const floodName = (i) => 'quota-a-' + String(i).padStart(3, '0') + '.txt';
const floodBody = (i) => 'A-file-' + i + '-bytes';

// Raw-binary cookie-jar client, same shape as tests/upload.test.js.
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

function beaconTokenFor(pageText, id) {
  const m = pageText.match(new RegExp('data-beacon="' + id + '">([0-9a-f]{32})'));
  assert.ok(m, 'beacon token for ' + id + ' not found on the module page');
  return m[1];
}

test('upload quota: session A flooding past its cap never evicts session B', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const OCTET = { 'content-type': 'application/octet-stream' };
  t.after(() => {
    for (const name of [KEEPER, ...Array.from({ length: FLOOD_COUNT }, (_, i) => floodName(i))]) {
      try { fs.unlinkSync(path.join(UPLOADS_ROOT, name)); } catch { /* absent or already evicted */ }
    }
  });

  // Session B stores its proof file first: an HTML payload carrying B's
  // own stored-xss beacon snippet, exactly the honest solve setup.
  const B = uploadClient(srv.base);
  const tokenB = beaconTokenFor((await B.get('/upload')).text, 'stored-xss');
  const keeperPayload = `<html><body><script>fetch('/upload/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:'stored-xss',file:'${KEEPER}',token:'${tokenB}'})})</script>KEEPER-BYTES</body></html>`;
  const keeperUp = await B.postRaw('/upload?filename=' + KEEPER, Buffer.from(keeperPayload), OCTET);
  assert.equal(keeperUp.status, 200, 'B keeper upload stored');
  const keeperBefore = await B.get('/uploads/' + KEEPER);
  assert.equal(keeperBefore.status, 200);
  assert.equal(keeperBefore.text, keeperPayload, 'B keeper served byte-identical before the flood');

  // Session A floods: 205 small uploads against a 200-file per-session
  // cap, all under names only A uses.
  const A = uploadClient(srv.base);
  for (let i = 0; i < FLOOD_COUNT; i++) {
    const r = await A.postRaw('/upload?filename=' + floodName(i), Buffer.from(floodBody(i)), OCTET);
    assert.equal(r.status, 200, 'A flood upload ' + i + ' accepted');
  }

  // A's own oldest files are the ones evicted: with 205 uploads and a cap
  // of 200, the first five are gone, and the boundary file survives.
  for (let i = 0; i < 5; i++) {
    const gone = await A.get('/uploads/' + floodName(i));
    assert.equal(gone.status, 404, 'A oldest file ' + floodName(i) + ' evicted by A own quota');
  }
  const boundary = await A.get('/uploads/' + floodName(5));
  assert.equal(boundary.status, 200, 'A file at the cap boundary survives');
  assert.equal(boundary.text, floodBody(5), 'A boundary file byte-identical');
  const newest = await A.get('/uploads/' + floodName(FLOOD_COUNT - 1));
  assert.equal(newest.status, 200, 'A newest file survives');
  assert.equal(newest.text, floodBody(FLOOD_COUNT - 1), 'A newest file byte-identical');

  // B's file is untouched by A's flood: still served byte-identical, and
  // B's beacon proof against the stored artifact still verifies, so B
  // still earns the stored-xss flag honestly after the flood.
  const keeperAfter = await B.get('/uploads/' + KEEPER);
  assert.equal(keeperAfter.status, 200, 'B keeper still served after A flood');
  assert.equal(keeperAfter.text, keeperPayload, 'B keeper byte-identical after A flood');
  const beacon = await B.postRaw('/upload/beacon', Buffer.from(JSON.stringify({ id: 'stored-xss', file: KEEPER, token: tokenB })), { 'content-type': 'application/json' });
  assert.equal(beacon.status, 200, 'B beacon still verifies after A flood');
  assert.ok(beacon.text.includes(flagFromDb(dataDir, 'upload', 'stored-xss')), 'B earns stored-xss after A flood');
});
