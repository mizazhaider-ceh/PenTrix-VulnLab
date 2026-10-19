'use strict';
// ECB Decryption Oracle: /crypto/ecb/encrypt encrypts attacker_prefix || secret
// with AES-128-ECB under a random key. ECB leaks block equality, so a
// byte-at-a-time attack recovers the secret.
const express = require('express');
const crypto = require('crypto');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();
// Form parsing for this challenge's routes (mirrors router.js router-scoped use).
router.use(express.urlencoded({ extended: false }));

// Vulnerable state and helper: random-per-boot key and secret (was
// module-level in router.js, now owned by this challenge file).
const ecbKey = crypto.randomBytes(16);
const ecbSecret = crypto.randomBytes(20).toString('base64'); // 28 printable chars
function ecbEncrypt(buf) {
  // VULN: AES-128-ECB on attacker_prefix || secret. ECB leaks block equality,
  // so a byte-at-a-time attack recovers the secret.
  const c = crypto.createCipheriv('aes-128-ecb', ecbKey, null);
  return Buffer.concat([c.update(buf), c.final()]);
}

router.get('/ecb', (req, res) => {
  const secretCt = ecbEncrypt(Buffer.alloc(0)).toString('hex');
  res.send(page('ECB Decryption Oracle', `
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">🗝️</span><b>VaultKeeper</b><span class="dim">encrypted secret vault</span></div>
      <h2>Secret vault (AES-128-ECB)</h2>
      <p>The vault encrypts <b>your input followed by a secret</b> with AES-128-ECB
      under a random key, PKCS#7 padded. ECB encrypts identical plaintext blocks
      to identical ciphertext blocks.</p>
      <h3>Encryption oracle</h3>
      <form method="POST" action="/crypto/ecb/encrypt">
        <input class="clay-input" name="input" size="50" placeholder="your prefix (printable text)" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Encrypt</button></p>
      </form>
      <p class="note">Scripting? POST <code>input=...</code> (text, max 64 chars) or
      <code>inhex=...</code> (raw bytes as hex) to <code>/crypto/ecb/encrypt</code>;
      the hex ciphertext is in <code>&lt;code id="ct"&gt;</code>.</p>
      <h3>Secret ciphertext</h3>
      <p>Encryption of the secret alone (empty prefix):</p>
      <p><code>${secretCt}</code></p>
      <hr />
      <h3>Submit the recovered secret</h3>
      <form method="POST" action="/crypto/ecb/solve">
        <input class="clay-input" name="plaintext" size="50" placeholder="decrypted secret" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Claim flag</button></p>
      </form>
      <p class="note">Steps: find the block size, confirm ECB with a repeated block,
      then decrypt byte-at-a-time.</p>
    </div>
  `));
});

router.post('/ecb/encrypt', (req, res) => {
  let buf;
  const hex = (req.body.inhex || '').toString().trim();
  if (hex) {
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0 || hex.length > 128) {
      return res.status(400).send(page('Bad hex input', `
        <div class="card clay-card">
          <div class="card-top"><span class="orb" aria-hidden="true">🗝️</span><b>VaultKeeper</b><span class="dim">encrypted secret vault</span></div>
          <h2>Bad hex input</h2>
          <p class="clay-err" role="alert">Bad hex input.</p>
          <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto/ecb">Back to the oracle</a></p>
        </div>`));
    }
    buf = Buffer.from(hex, 'hex');
  } else {
    buf = Buffer.from((req.body.input || '').toString(), 'utf8');
  }
  if (buf.length > 64) return res.status(400).send(page('Input too long', `
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">🗝️</span><b>VaultKeeper</b><span class="dim">encrypted secret vault</span></div>
      <h2>Input too long</h2>
      <p class="clay-err" role="alert">Input too long (max 64 bytes).</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto/ecb">Back to the oracle</a></p>
    </div>`));
  const ct = ecbEncrypt(Buffer.concat([buf, Buffer.from(ecbSecret, 'utf8')]));
  res.send(page('Oracle output', `
    <div class="card clay-card">
      <h2>Ciphertext</h2>
      <p><code id="ct">${ct.toString('hex')}</code></p>
      <p><a href="/crypto/ecb">Back to the oracle</a></p>
    </div>
  `));
});

router.post('/ecb/solve', (req, res) => {
  const pt = (req.body.plaintext || '').toString();
  if (pt === ecbSecret) {
    const flag = award(req, 'crypto', 'crypto-ecb-oracle');
    return res.send(page('Secret recovered', `
      <div class="card clay-card">
        <h2>Byte-at-a-time decryption worked</h2>
        <p>You recovered the full secret: <code>${esc(pt)}</code></p>
        ${flagBox(flag)}
        ${fixPanel('crypto', 'crypto-ecb-oracle')}
        <p><a href="/crypto">Back to the module</a></p>
      </div>
    `));
  }
  res.status(400).send(page('Wrong secret', `
    <div class="card clay-card">
      <h2>Not the secret</h2>
      <p><code>${esc(pt) || '(empty)'}</code> does not match the vault secret.</p>
      <p><a href="/crypto/ecb">Back to the oracle</a></p>
    </div>
  `));
});

module.exports = {
  vuln: {
    id: 'crypto-ecb-oracle',
    name: 'ECB Decryption Oracle',
    difficulty: 'Hard',
    hint: 'Identical plaintext blocks give identical ciphertext blocks. Align your input so the unknown byte sits at the end of a block, then try all 256 values.',
    hints: ["ECB encrypts identical blocks identically. What does that leak?", "Block equality. Use it as an oracle to decrypt byte-by-byte.", "Submit chosen plaintexts, observe which blocks match, extract the secret."],
    tools: 'P, C',
    how: 'Find the block size, confirm ECB, then decrypt the secret byte-at-a-time and submit it.',
    link: '/crypto#crypto-ecb-oracle',
    start: 'curl -s http://localhost:3000/crypto/ecb | grep -o "id=\\"ct\\"[^<]*" | head -1',
  },
  router,
};
