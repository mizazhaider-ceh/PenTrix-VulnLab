'use strict';
// XOR crib-dragging: a secret JSON document encrypted with a short repeating
// XOR key. A known plaintext header recovers the key, then the full plaintext.
const express = require('express');
const crypto = require('crypto');
const { brief, esc, fixPanel, flagBox, hintLadder, page, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

// Challenge-scoped state, created once at boot (same as the module router).
const xorKey = crypto.randomBytes(8); // short repeating key: the whole flaw
const xorPt = `{"user":"guest","token":"${crypto.randomBytes(8).toString('hex')}"}`;
const xorCt = Buffer.from(xorPt, 'utf8').map((b, i) => b ^ xorKey[i % xorKey.length]);

const vuln = {
  id: 'crypto-xor-crib',
  name: 'XOR Crib Dragging',
  difficulty: 'Medium',
  hint: 'The key repeats every few bytes and you know the plaintext header {"user":". Copy the ciphertext from the page via Proxy, crib-drag against it to recover the key, trying lengths 1-12.',
  hints: ["Repeating-key XOR with a known plaintext (crib). What does that give you?", "XOR the crib with the ciphertext to recover the key stream, then decrypt.", "Try key lengths 1 to 12: derive each candidate key from the known header {\"user\":\" and keep the one that decrypts to valid JSON. Submit the plaintext through Repeater."],
  tools: 'BZ, P',
  how: 'Copy the ciphertext via Burp, recover the repeating key with the known header in Python, decrypt the full ciphertext, and submit the plaintext through Repeater.',
  link: '/crypto#crypto-xor-crib',
  start: 'Open Burp, proxy your browser, and browse to /crypto/xor. Copy the ciphertext hex from the payload block. Do the crib-drag offline in Python, then send POST /crypto/xor/solve through Repeater with the recovered plaintext.',
};

// --- local clay UI helpers (self-contained; no crypto shared module yet) ---
function card(crumb, body) {
  return `<section class="clay-card">
  <div class="card-top"><span class="orb" aria-hidden="true">V</span><b>XOR Vault</b><span class="dim">${esc(crumb)}</span></div>
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

// GET /xor -> the vault page: ciphertext, crib hint, and the solve form.
router.get('/xor', (req, res) => {
  res.send(page('XOR Crib Dragging', `
    ${brief('Crack the vault cipher', `The vault keeps a secret JSON document encrypted with a <b>short repeating XOR key</b> (key length is between 1 and 12 bytes). Every document here starts with the header <code>{"user":"</code>. XOR that known header against the ciphertext to recover key bytes (crib-dragging), then decrypt the rest.`)}
    ${card('Encrypted document', `
      <h2>Repeating-key XOR vault</h2>
      <p>Ciphertext of the secret document:</p>
      ${payloadBlock('Ciphertext (hex)', xorCt.toString('hex'))}
      <hr />
      <h3>Submit the recovered plaintext</h3>
      <form method="POST" action="/crypto/xor/solve">
        ${field({ id: 'plaintext', name: 'plaintext', label: 'Decrypted document', attrs: 'size="60" placeholder="decrypted document JSON"' })}
        ${submitButton('Claim flag')}
      </form>
      <p class="dim">Try each key length 1 to 12: derive the key from the crib, decrypt, keep the one that yields valid JSON.</p>
    `)}
    ${hintLadder(vuln)}
    ${navLinks([])}
  `));
});

// POST /xor/solve -> award when the full plaintext is recovered.
router.post('/xor/solve', (req, res) => {
  const pt = (req.body.plaintext || '').toString();
  // VULN: repeating-key XOR with a short key falls to known-plaintext crib-dragging.
  if (pt === xorPt) {
    const flag = award(req, 'crypto', 'crypto-xor-crib');
    return res.send(page('Plaintext recovered', `
      ${card('Result', `
        <h2>Key recovered, message decrypted</h2>
        <p>Full plaintext: <code>${esc(pt)}</code></p>
      `)}
      ${flagBox(flag)}
      ${fixPanel('crypto', 'crypto-xor-crib')}
      ${navLinks([])}
    `));
  }
  res.status(400).send(page('Wrong plaintext', `
    ${card('Result', `
      <h2>Not the plaintext</h2>
      <p class="clay-err" role="alert"><code>${esc(pt) || '(empty)'}</code> does not match the vault document.</p>
    `)}
    ${navLinks([['/crypto/xor', 'Try again']])}
  `));
});

module.exports = { vuln, router };
