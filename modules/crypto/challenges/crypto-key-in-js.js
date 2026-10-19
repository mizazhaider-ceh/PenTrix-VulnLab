'use strict';
// Key in JavaScript: the AES key used by the frontend is hardcoded in the
// served JavaScript bundle, so the ciphertext can be decrypted offline.
const express = require('express');
const crypto = require('crypto');
const { brief, esc, fixPanel, flagBox, hintLadder, page, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

// Challenge-scoped state, created once at boot (same as the module router).
const JS_KEY = 'PenTrixKey2026!!'; // 16 bytes, hardcoded in the served JS: the flaw
const jsIv = crypto.randomBytes(16);
const JS_MSG = 'Vault combination: 04-17-2026. Do not share.';
const jsCt = (() => {
  const c = crypto.createCipheriv('aes-128-cbc', Buffer.from(JS_KEY, 'utf8'), jsIv);
  return Buffer.concat([jsIv, c.update(Buffer.from(JS_MSG, 'utf8')), c.final()]).toString('hex');
})();

const vuln = {
  id: 'crypto-key-in-js',
  name: 'Key in JavaScript',
  difficulty: 'Easy',
  hint: 'The frontend encrypts, so the frontend must know the key. Read the served JavaScript file.',
  hints: ["The AES key is in the public JavaScript. Find it.", "Send the served app.js to Repeater and read the key constant.", "Decrypt the note ciphertext offline in Python, then submit the plaintext with a Repeater POST to the solve endpoint."],
  tools: 'BZ, DT, P',
  how: 'Find the hardcoded AES key in the served JavaScript, decrypt the ciphertext offline, and submit the note.',
  link: '/crypto#crypto-key-in-js',
  start: 'Browse to the Secure Notes vault note page through Burp Proxy, then open the linked app.js in Repeater to read the served JavaScript.',
};

// --- local clay UI helpers (self-contained; no crypto shared module yet) ---
function card(crumb, body) {
  return `<section class="clay-card">
  <div class="card-top"><span class="orb" aria-hidden="true">N</span><b>Secure Notes</b><span class="dim">${esc(crumb)}</span></div>
  ${body}
</section>`;
}

function field(opts) {
  const o = opts || {};
  const value = o.value !== undefined && o.value !== null ? ` value="${esc(o.value)}"` : '';
  const attrs = o.attrs ? ` ${o.attrs}` : '';
  return `<div class="clay-field">
    <label for="${esc(o.id)}">${esc(o.label)}</label>
    <input class="clay-input" id="${esc(o.id)}" name="${esc(o.name)}" type="text"${value} required${attrs}>
  </div>`;
}

function submitButton(label) {
  return `<button type="submit" class="clay-btn clay-btn-primary">${esc(label)}</button>`;
}

function navLinks(links) {
  const all = (links || []).concat([['/crypto', 'Module index']]);
  return `<p>${all.map(([href, label]) =>
    `<a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(href)}">${esc(label)}</a>`).join(' ')}</p>`;
}

// GET /keyjs/app.js -> the frontend bundle, served byte-identical to the
// original module router (this is the attack surface, so it must not change).
router.get('/keyjs/app.js', (req, res) => {
  res.type('application/javascript').send(
`// dashboard.js - frontend bundle v2.4.1
// Notes are encrypted client-side before upload, so the server never sees them.
const ENCRYPTION_KEY = '${JS_KEY}'; // VULN: AES key shipped to every browser
const API_BASE = '/api/v2';

function saveNote(text) {
  // (demo) encrypt with AES-128-CBC, random IV, prepend IV to ciphertext
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  return { iv: iv, note: text, keyHint: 'see ENCRYPTION_KEY' };
}

function renderDashboard(user) {
  document.title = 'Dashboard - ' + user;
}
`);
});

// GET /keyjs -> the vault note page: ciphertext and the solve form.
router.get('/keyjs', (req, res) => {
  res.send(page('Key in JavaScript', `
    ${brief('Decrypt the vault note', `The frontend encrypts vault notes with AES-128-CBC before uploading them, and the IV is prepended to the ciphertext. The frontend must keep the key somewhere it can use it: check the served JavaScript.`)}
    ${card('Encrypted note', `
      <h2>Client-side encrypted vault note</h2>
      <p>One encrypted note, straight from the vault:</p>
      ${payloadBlock('Ciphertext (hex)', jsCt)}
      <p>The encryption key lives where the frontend can reach it: <a href="/crypto/keyjs/app.js"><code>/crypto/keyjs/app.js</code></a></p>
      <hr />
      <h3>Submit the decrypted note</h3>
      <form method="POST" action="/crypto/keyjs/solve">
        ${field({ id: 'plaintext', name: 'plaintext', label: 'Decrypted note', attrs: 'size="60" placeholder="decrypted note text"' })}
        ${submitButton('Claim flag')}
      </form>
    `)}
    ${hintLadder(vuln)}
    ${navLinks([])}
  `));
});

// POST /keyjs/solve -> award when the note is decrypted correctly.
router.post('/keyjs/solve', (req, res) => {
  const pt = (req.body.plaintext || '').toString();
  if (pt === JS_MSG) {
    const flag = award(req, 'crypto', 'crypto-key-in-js');
    return res.send(page('Note decrypted', `
      ${card('Result', `
        <h2>Decrypted offline</h2>
        <p>Note: <code>${esc(pt)}</code></p>
        <p>A key the browser can read is a key the attacker can read.</p>
      `)}
      ${flagBox(flag)}
      ${fixPanel('crypto', 'crypto-key-in-js')}
      ${navLinks([])}
    `));
  }
  res.status(400).send(page('Wrong plaintext', `
    ${card('Result', `
      <h2>Not the note</h2>
      <p class="clay-err" role="alert"><code>${esc(pt) || '(empty)'}</code> is not the decrypted note.</p>
    `)}
    ${navLinks([['/crypto/keyjs', 'Try again']])}
  `));
});

module.exports = { vuln, router };
