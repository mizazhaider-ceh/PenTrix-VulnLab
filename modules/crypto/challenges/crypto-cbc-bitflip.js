'use strict';
// CBC bit-flipping: base64(iv || AES-128-CBC) role cookie whose IV sits right
// over the plaintext role value, so flipping IV bits forges an admin cookie.
const express = require('express');
const crypto = require('crypto');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const cbcKey = crypto.randomBytes(16);
function mintRoleCookie() {
  const iv = crypto.randomBytes(16);
  // Layout: {"role":"guest","user":"guest"} (31 bytes). role sits in block 0,
  // so flipping IV bits flips the role plaintext. 'guest' -> 'admin' is 5:5.
  const pt = Buffer.from(JSON.stringify({ role: 'guest', user: 'guest' }), 'utf8');
  const c = crypto.createCipheriv('aes-128-cbc', cbcKey, iv);
  return Buffer.concat([iv, c.update(pt), c.final()]).toString('base64');
}
function readRoleCookie(b64) {
  const raw = Buffer.from(b64, 'base64');
  if (raw.length < 32 || raw.length % 16 !== 0) throw new Error('bad cookie length');
  const iv = raw.subarray(0, 16);
  const ct = raw.subarray(16);
  const d = crypto.createDecipheriv('aes-128-cbc', cbcKey, iv);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
}

router.get('/cbc', (req, res) => {
  let seen = null;
  try { seen = readRoleCookie(req.cookies.vlab_cbc || '').role; } catch (e) { /* no/invalid cookie */ }
  res.send(page('CBC Bit-Flipping', `
    <h2>Role cookie (AES-128-CBC)</h2>
    <p>Your session is <code>base64(iv || AES-128-CBC(iv, '{"role":"guest","user":"guest"}'))</code>.
    CBC decryption XORs each ciphertext block with the previous one, so flipping
    a bit in the IV (or in ciphertext block N) flips the same bit in plaintext
    block N+1. The role value lives in block 0, right under the IV.</p>
    <form method="POST" action="/crypto/cbc/login">
      <button class="clay-btn clay-btn-primary" type="submit">Mint a guest cookie</button>
    </form>
    <p>Server currently sees you as role: <b>${esc(seen === null ? '(no valid cookie)' : String(seen))}</b></p>
    <hr />
    <h3>Forge a cookie</h3>
    <p>Paste your bit-flipped cookie (base64). If it decrypts to valid JSON with
    <code>role === 'admin'</code>, you win.</p>
    <form method="POST" action="/crypto/cbc/check">
      <div class="clay-field">
        <label for="cookie">Forged cookie</label>
        <textarea class="clay-input" id="cookie" name="cookie" rows="4" placeholder="base64(iv || ciphertext)"></textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Submit forged cookie</button>
    </form>
    <p class="note">You know the full plaintext and the layout. XOR the IV bytes
    sitting over <code>"guest"</code> with <code>"guest" xor "admin"</code>.</p>
  `));
});

router.post('/cbc/login', (req, res) => {
  const v = mintRoleCookie();
  res.cookie('vlab_cbc', v, { httpOnly: false });
  res.send(page('Guest cookie minted', `
    <h2>Cookie minted</h2>
    <p>Your cookie (also set as <code>vlab_cbc</code>):</p>
    <p><code id="ck">${v}</code></p>
    <p>Now flip it: <a href="/crypto/cbc">back to the challenge</a>.</p>
  `));
});

router.post('/cbc/check', (req, res) => {
  const forged = (req.body.cookie || '').toString().trim();
  let data;
  try {
    // VULN: CBC malleability is not integrity: bit flips in the IV produce
    // predictable plaintext changes and the server still accepts the cookie.
    data = readRoleCookie(forged);
  } catch (e) {
    return res.status(400).send(page('Bad cookie', `
      <h2>Cookie rejected</h2>
      <p>Decryption failed: <code>${esc(e.message)}</code>. A flipped bit must
      not break the JSON structure or the padding.</p>
      <p><a href="/crypto/cbc">Back</a></p>
    `));
  }
  if (data && data.role === 'admin') {
    const flag = award(req, 'crypto', 'crypto-cbc-bitflip');
    return res.send(page('Admin cookie accepted', `
      <h2>Forged cookie accepted</h2>
      <p>The server decrypted your cookie and sees <code>role = 'admin'</code>.
      IV bit-flipping worked.</p>
      ${flagBox(flag)}
      ${fixPanel('crypto', 'crypto-cbc-bitflip')}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.send(page('Cookie accepted', `
    <h2>Valid cookie, wrong role</h2>
    <p>The server decrypted your cookie and sees <code>role = ${esc(String(data && data.role))}</code>.
    You need <code>admin</code>.</p>
    <p><a href="/crypto/cbc">Back</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'crypto-cbc-bitflip',
    name: 'CBC Bit-Flipping',
    difficulty: 'Hard',
    est: '20-40 minutes',
    hint: 'CBC decryption XORs each block with the previous ciphertext (or IV). You know the full plaintext and the layout: role sits in block 0, under the IV.',
    hints: ["Mint a guest cookie with Burp Proxy on. The vlab_cbc cookie (or the code value on the mint page) is your starting material; send it to Decoder.", "In Decoder, decode the cookie as Base64. The first 16 bytes are the IV, and the page shows the plaintext layout, so work out which IV bytes sit over 'guest'. Decoder has a Hex editor plus XOR and Encode transforms.", "Flip those IV bytes with 'guest' xor 'admin', re-encode to Base64 in Decoder, and send the forged cookie to POST /crypto/cbc/check (from Repeater, or paste it into the form on the page). The flag shows when the server sees role=admin."],
    tools: 'BZ, P, C',
    how: 'Your cookie decrypts to a role you did not choose. CBC decryption is malleable: the right edits before decryption rewrite the plaintext that comes out.',
    link: '/crypto#crypto-cbc-bitflip',
    start: 'In Burp Proxy, open /crypto/cbc in your browser and click "Mint a guest cookie". Copy the vlab_cbc cookie (or the value on the mint page), send it to Decoder, base64-decode it, and flip the IV bytes so the decrypted role becomes admin.',
  },
  router,
};
