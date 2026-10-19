'use strict';
// Crypto module: every challenge must be solvable by the documented technique
// and must NOT be solvable by the obvious shortcut. Oracle challenges are
// driven programmatically in the test.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

function flagsIn(text) {
  return text.match(FLAG_RE) || [];
}

// Display names as listed by the scoreboard (capturedSet returns "crypto:Name").
const NAMES = {
  'crypto-rand-pin': 'Predictable Reset PIN',
  'crypto-ecb-oracle': 'ECB Decryption Oracle',
  'crypto-cbc-bitflip': 'CBC Bit-Flipping',
  'crypto-hash-ext': 'Hash Length Extension',
  'crypto-md5-crack': 'Crack the MD5',
  // Scoreboard HTML-escapes names: Base64 "Encryption" renders as &quot;.
  'crypto-b64-cookie': 'Base64 &quot;Encryption&quot;',
  'crypto-xor-crib': 'XOR Crib Dragging',
  'crypto-key-in-js': 'Key in JavaScript',
};
const capturedName = (id) => `crypto:${NAMES[id]}`;

// ---------------------------------------------------------------------------
// Minimal SHA-256 that accepts a restored compression state, for the length
// extension test. stateWords: 8 uint32 from the original MAC (big-endian).
// hashedLen: bytes already absorbed (secret + original message + glue).
// data: the suffix bytes to hash on top.
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}
function sha256WithState(stateWords, hashedLen, data) {
  let h = stateWords.slice();
  const bitLen = BigInt((hashedLen + data.length) * 8);
  const withOne = Buffer.concat([data, Buffer.from([0x80])]);
  const padZeros = (64 - ((withOne.length + 8) % 64)) % 64;
  const padded = Buffer.concat([withOne, Buffer.alloc(padZeros), Buffer.alloc(8)]);
  padded.writeBigUInt64BE(bitLen, padded.length - 8);
  for (let off = 0; off < padded.length; off += 64) {
    const w = new Array(64);
    for (let i = 0; i < 16; i++) w[i] = padded.readUInt32BE(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h = h.map((x, i) => (x + [a, b, c, d, e, f, g, hh][i]) >>> 0);
  }
  const out = Buffer.alloc(32);
  h.forEach((x, i) => out.writeUInt32BE(x, i * 4));
  return out.toString('hex');
}
// Sanity: plain SHA-256("abc") must match the known digest.
assert.equal(
  sha256WithState(
    [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
    0, Buffer.from('abc')),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  'sha256 sanity failed',
);

// ---------------------------------------------------------------------------
// Exploit helpers (each performs the documented attack and returns the value
// that earns the flag).
async function ecbRecoverSecret(c) {
  async function oracleHex(prefixBuf) {
    const r = await c.post('/crypto/ecb/encrypt', { inhex: prefixBuf.toString('hex') });
    assert.equal(r.status, 200);
    const m = r.text.match(/<code id="ct">([0-9a-f]+)<\/code>/);
    assert.ok(m, 'oracle ciphertext not found');
    return m[1];
  }
  const secretLen = 28; // base64 of 20 random bytes, per the challenge page
  let known = Buffer.alloc(0);
  for (let i = 0; i < secretLen; i++) {
    const blockIdx = Math.floor(i / 16);
    const prefix = Buffer.alloc(15 - (i % 16), 'A');
    const targetBlock = (await oracleHex(prefix)).slice(blockIdx * 32, blockIdx * 32 + 32);
    const trials = [];
    for (let b = 0; b < 256; b++) {
      trials.push(oracleHex(Buffer.concat([prefix, known, Buffer.from([b])])));
    }
    const cts = await Promise.all(trials);
    const hit = cts.findIndex((ct) => ct.slice(blockIdx * 32, blockIdx * 32 + 32) === targetBlock);
    assert.notEqual(hit, -1, `ecb oracle failed at byte ${i}`);
    known = Buffer.concat([known, Buffer.from([hit])]);
  }
  return known.toString('utf8');
}

async function cbcForgeAdmin(c) {
  const login = await c.post('/crypto/cbc/login');
  assert.equal(login.status, 200);
  const m = login.text.match(/<code id="ck">([^<]+)<\/code>/);
  assert.ok(m, 'guest cookie not found');
  const raw = Buffer.from(m[1], 'base64');
  const iv = raw.subarray(0, 16);
  // Plaintext is {"role":"guest","user":"guest"}; the role value 'guest'
  // sits at bytes 9..13 of block 0, directly under the IV.
  const from = Buffer.from('guest');
  const to = Buffer.from('admin');
  for (let i = 0; i < 5; i++) iv[9 + i] ^= from[i] ^ to[i];
  return { original: m[1], forged: Buffer.concat([iv, raw.subarray(16)]).toString('base64') };
}

async function hashExtForge(c) {
  const r = await c.get('/crypto/mac/sign?msg=role%3Duser');
  assert.equal(r.status, 200);
  const { msg, mac } = r.body;
  assert.equal(msg, 'role=user');
  assert.ok(/^[0-9a-f]{64}$/.test(mac), 'bad mac from signer');
  const orig = Buffer.from(msg, 'utf8');
  const secretLen = 16; // stated on the challenge page
  // Glue padding for (secret + original message).
  const total = secretLen + orig.length;
  const glueZeros = 64 - ((total + 1 + 8) % 64);
  const glue = Buffer.alloc(1 + glueZeros + 8);
  glue[0] = 0x80;
  glue.writeBigUInt64BE(BigInt(total * 8), 1 + glueZeros);
  const suffix = Buffer.from(';admin=1', 'utf8');
  const forgedMsg = Buffer.concat([orig, glue, suffix]);
  // Restore the compression state from the MAC and continue the hash.
  const state = [];
  for (let i = 0; i < 8; i++) state.push(parseInt(mac.slice(i * 8, i * 8 + 8), 16));
  const forgedMac = sha256WithState(state, total + glue.length, suffix);
  return { msghex: forgedMsg.toString('hex'), mac: forgedMac };
}

async function md5CrackPassword(c) {
  const page = await c.get('/crypto/md5');
  assert.equal(page.status, 200);
  const m = page.text.match(/([0-9a-f]{32})/);
  assert.ok(m, 'leaked hash not found');
  const target = m[1];
  const wl = await c.get('/crypto/md5/wordlist.txt');
  assert.equal(wl.status, 200);
  for (const w of wl.text.split('\n')) {
    const word = w.trim();
    if (!word) continue;
    if (crypto.createHash('md5').update(word).digest('hex') === target) return word;
  }
  assert.fail('password not in wordlist');
  return null;
}

async function xorRecoverPlaintext(c) {
  const page = await c.get('/crypto/xor');
  assert.equal(page.status, 200);
  const m = page.text.match(/<pre class="payload-body">([0-9a-f]+)<\/pre>/);
  assert.ok(m, 'ciphertext not found');
  const ct = Buffer.from(m[1], 'hex');
  const crib = Buffer.from('{"user":"guest","token":"', 'utf8'); // 24 known bytes
  for (let kl = 1; kl <= 12; kl++) {
    const key = Buffer.alloc(kl);
    const seen = new Array(kl).fill(false);
    let ok = true;
    for (let i = 0; i < crib.length; i++) {
      const kb = ct[i] ^ crib[i];
      if (seen[i % kl] && key[i % kl] !== kb) { ok = false; break; }
      key[i % kl] = kb;
      seen[i % kl] = true;
    }
    if (!ok || seen.some((s) => !s)) continue;
    const dec = Buffer.from(ct.map((b, i) => b ^ key[i % kl]));
    try {
      const obj = JSON.parse(dec.toString('utf8'));
      if (obj && obj.user === 'guest' && typeof obj.token === 'string') return dec.toString('utf8');
    } catch { /* not this key length */ }
  }
  assert.fail('xor key recovery failed');
  return null;
}

async function keyjsDecryptNote(c) {
  const js = await c.get('/crypto/keyjs/app.js');
  assert.equal(js.status, 200);
  const km = js.text.match(/ENCRYPTION_KEY = '([^']+)'/);
  assert.ok(km, 'key not found in served JS');
  const page = await c.get('/crypto/keyjs');
  assert.equal(page.status, 200);
  const cm = page.text.match(/<pre class="payload-body">([0-9a-f]+)<\/pre>/);
  assert.ok(cm, 'ciphertext not found');
  const raw = Buffer.from(cm[1], 'hex');
  const d = crypto.createDecipheriv('aes-128-cbc', Buffer.from(km[1], 'utf8'), raw.subarray(0, 16));
  return Buffer.concat([d.update(raw.subarray(16)), d.final()]).toString('utf8');
}

test('crypto module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'crypto', id);

  await t.test('module page renders, links resolve, no em dash, no flag', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/crypto');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal(flagsIn(text).length, 0);
    for (const href of ['/crypto/pin', '/crypto/ecb', '/crypto/cbc', '/crypto/mac',
      '/crypto/md5', '/crypto/b64', '/crypto/xor', '/crypto/keyjs']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('rand-pin: wrong guesses earn nothing and are never throttled; the real brute-force space is open', async () => {
    const c = client(srv.base);
    // No PIN issued yet: nothing to guess.
    assert.equal((await c.post('/crypto/pin/verify', { pin: '000000' })).status, 401);
    await c.post('/crypto/pin/generate');
    for (const bad of ['000000', '123456', '111111', '']) {
      const r = await c.post('/crypto/pin/verify', { pin: bad });
      assert.equal(r.status, 401, `PIN ${bad || '(empty)'} should fail`);
      assert.equal(flagsIn(r.text).length, 0, 'a wrong guess must not leak a flag');
    }
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-rand-pin')));
    // The flaw: no rate limiting, so the whole 10^6 space is scriptable.
    const burst = await Promise.all(
      Array.from({ length: 60 }, (_, i) => c.post('/crypto/pin/verify', { pin: String(900000 + i) })));
    assert.ok(burst.every((r) => r.status === 401), 'guessing must never be throttled');
  });

  await t.test('rand-pin: a correct PIN (via controlled randomness) earns the flag', async () => {
    // A full 10^6 HTTP brute-force is the documented attack but takes far too
    // long for a regression test. Instead: stub Math.random in-process so the
    // issued PIN is known, then drive the REAL challenge router and prove a
    // correct guess awards the flag while a wrong one does not.
    const express = require('express');
    const session = require('express-session');
    const http = require('http');
    const origRandom = Math.random;
    process.env.DB_PATH = path.join(dataDir, 'vulnlab.db');
    Math.random = () => 0.654321; // floor(0.654321 * 1e6) = 654321
    let pinMod;
    try {
      pinMod = require('../modules/crypto/challenges/crypto-rand-pin');
    } finally {
      Math.random = origRandom;
    }
    const app = express();
    app.use(session({ secret: 'test-only', resave: false, saveUninitialized: true }));
    app.use('/crypto', pinMod.router);
    const server = http.createServer(app);
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = (p, body) => fetch(base + p, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' }, body,
    });
    try {
      Math.random = () => 0.654321;
      const g = await post('/crypto/pin/generate', '');
      assert.equal(g.status, 302);
      Math.random = origRandom;
      const wrong = await post('/crypto/pin/verify', 'pin=000000');
      assert.equal(wrong.status, 401);
      assert.equal(flagsIn(await wrong.text()).length, 0);
      const hit = await post('/crypto/pin/verify', 'pin=654321');
      assert.equal(hit.status, 200);
      assert.ok((await hit.text()).includes(flagOf('crypto-rand-pin')));
    } finally {
      Math.random = origRandom;
      await new Promise((r) => server.close(r));
    }
  });

  await t.test('ecb-oracle: wrong secrets earn nothing, byte-at-a-time decryption earns the flag', async () => {
    const c = client(srv.base);
    const bad = await c.post('/crypto/ecb/solve', { plaintext: 'not the secret' });
    assert.equal(bad.status, 400);
    assert.equal(flagsIn(bad.text).length, 0);
    const empty = await c.post('/crypto/ecb/solve', { plaintext: '' });
    assert.equal(empty.status, 400);
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-ecb-oracle')));
    const secret = await ecbRecoverSecret(c);
    const hit = await c.post('/crypto/ecb/solve', { plaintext: secret });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('crypto-ecb-oracle')));
    assert.ok((await capturedSet(c)).some((s) => s === capturedName('crypto-ecb-oracle')));
  });

  await t.test('cbc-bitflip: the guest cookie earns nothing, the IV-flipped cookie earns the flag', async () => {
    const c = client(srv.base);
    const { original, forged } = await cbcForgeAdmin(c);
    const neg = await c.post('/crypto/cbc/check', { cookie: original });
    assert.equal(neg.status, 200);
    assert.equal(flagsIn(neg.text).length, 0, 'an unmodified guest cookie must not award');
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-cbc-bitflip')));
    const hit = await c.post('/crypto/cbc/check', { cookie: forged });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('crypto-cbc-bitflip')));
    assert.ok((await capturedSet(c)).includes(capturedName('crypto-cbc-bitflip')));
    const garbage = await c.post('/crypto/cbc/check', { cookie: '!!!not-base64!!!' });
    assert.equal(garbage.status, 400);
  });

  await t.test('hash-ext: a wrong MAC earns nothing, the length-extended MAC earns the flag', async () => {
    const c = client(srv.base);
    const refused = await c.get('/crypto/mac/sign?msg=' + encodeURIComponent('role=user;admin=1'));
    assert.equal(refused.status, 400, 'the signer must refuse admin messages');
    const { msghex, mac } = await hashExtForge(c);
    const wrongMac = await c.post('/crypto/mac/verify', { msghex, mac: '0'.repeat(64) });
    assert.equal(wrongMac.status, 400);
    assert.equal(flagsIn(wrongMac.text).length, 0);
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-hash-ext')));
    const hit = await c.post('/crypto/mac/verify', { msghex, mac });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('crypto-hash-ext')));
    assert.ok((await capturedSet(c)).includes(capturedName('crypto-hash-ext')));
  });

  await t.test('md5-crack: a wrong password earns nothing, the cracked password earns the flag', async () => {
    const c = client(srv.base);
    const bad = await c.post('/crypto/md5/login', { password: 'definitely-not-it' });
    assert.equal(bad.status, 401);
    assert.equal(flagsIn(bad.text).length, 0);
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-md5-crack')));
    const pw = await md5CrackPassword(c);
    const hit = await c.post('/crypto/md5/login', { password: pw });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('crypto-md5-crack')));
    assert.ok((await capturedSet(c)).includes(capturedName('crypto-md5-crack')));
  });

  await t.test('b64-cookie: the untouched cookie earns nothing, the re-encoded admin cookie earns the flag', async () => {
    const c = client(srv.base);
    const login = await c.post('/crypto/b64/login');
    const m = login.text.match(/<code id="ck">([^<]+)<\/code>/);
    assert.ok(m, 'session cookie not found');
    const neg = await c.post('/crypto/b64/check', { cookie: m[1] });
    assert.equal(neg.status, 200);
    assert.equal(flagsIn(neg.text).length, 0, 'the issued user cookie must not award');
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-b64-cookie')));
    const data = JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'));
    data.role = 'admin';
    const forged = Buffer.from(JSON.stringify(data), 'utf8').toString('base64');
    const hit = await c.post('/crypto/b64/check', { cookie: forged });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('crypto-b64-cookie')));
    assert.ok((await capturedSet(c)).includes(capturedName('crypto-b64-cookie')));
  });

  await t.test('xor-crib: a wrong plaintext earns nothing, the crib-dragged plaintext earns the flag', async () => {
    const c = client(srv.base);
    const bad = await c.post('/crypto/xor/solve', { plaintext: '{"user":"guest"}' });
    assert.equal(bad.status, 400);
    assert.equal(flagsIn(bad.text).length, 0);
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-xor-crib')));
    const pt = await xorRecoverPlaintext(c);
    const hit = await c.post('/crypto/xor/solve', { plaintext: pt });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('crypto-xor-crib')));
    assert.ok((await capturedSet(c)).includes(capturedName('crypto-xor-crib')));
  });

  await t.test('key-in-js: a wrong note earns nothing, the offline-decrypted note earns the flag', async () => {
    const c = client(srv.base);
    const bad = await c.post('/crypto/keyjs/solve', { plaintext: 'wrong note' });
    assert.equal(bad.status, 400);
    assert.equal(flagsIn(bad.text).length, 0);
    assert.ok(!(await capturedSet(c)).some((s) => s === capturedName('crypto-key-in-js')));
    const note = await keyjsDecryptNote(c);
    const hit = await c.post('/crypto/keyjs/solve', { plaintext: note });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('crypto-key-in-js')));
    assert.ok((await capturedSet(c)).includes(capturedName('crypto-key-in-js')));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    assert.deepEqual(await capturedSet(c), []);
    // Capture every HTTP-exploitable challenge (rand-pin is covered by its own test).
    const secret = await ecbRecoverSecret(c);
    await c.post('/crypto/ecb/solve', { plaintext: secret });
    const { forged } = await cbcForgeAdmin(c);
    await c.post('/crypto/cbc/check', { cookie: forged });
    const { msghex, mac } = await hashExtForge(c);
    await c.post('/crypto/mac/verify', { msghex, mac });
    await c.post('/crypto/md5/login', { password: await md5CrackPassword(c) });
    const login = await c.post('/crypto/b64/login');
    const ck = login.text.match(/<code id="ck">([^<]+)<\/code>/)[1];
    const admin = JSON.parse(Buffer.from(ck, 'base64').toString('utf8'));
    admin.role = 'admin';
    await c.post('/crypto/b64/check', { cookie: Buffer.from(JSON.stringify(admin), 'utf8').toString('base64') });
    await c.post('/crypto/xor/solve', { plaintext: await xorRecoverPlaintext(c) });
    await c.post('/crypto/keyjs/solve', { plaintext: await keyjsDecryptNote(c) });
    // Re-capture one challenge: the scoreboard must still list it once.
    await c.post('/crypto/b64/check', { cookie: Buffer.from(JSON.stringify(admin), 'utf8').toString('base64') });
    const got = (await capturedSet(c)).filter((s) => s.startsWith('crypto:')).sort();
    const want = ['crypto-ecb-oracle', 'crypto-cbc-bitflip', 'crypto-hash-ext', 'crypto-md5-crack',
      'crypto-b64-cookie', 'crypto-xor-crib', 'crypto-key-in-js'].map(capturedName).sort();
    assert.deepEqual(got, want);
  });
});
