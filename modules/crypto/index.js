'use strict';
// Cryptographic Failures: eight intentionally vulnerable crypto-misuse labs
// built only on Node's built-in crypto module.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/crypto-rand-pin'),
  require('./challenges/crypto-ecb-oracle'),
  require('./challenges/crypto-cbc-bitflip'),
  require('./challenges/crypto-hash-ext'),
  require('./challenges/crypto-md5-crack'),
  require('./challenges/crypto-b64-cookie'),
  require('./challenges/crypto-xor-crib'),
  require('./challenges/crypto-key-in-js'),
];

const router = express.Router();

// Router-scoped form parsing (kept from the old module router in router.js):
// the challenge POST handlers below expect urlencoded form bodies.
router.use(express.urlencoded({ extended: false }));

const BRIEF_HTML = `
<p><b>What fails here?</b> Not the ciphers themselves: AES, SHA-256 and friends
are fine. What fails is <i>how they are used</i>: predictable random numbers,
ECB mode leaking structure, malleable CBC cookies, MACs built as
<code>hash(secret || message)</code>, fast unsalted password hashes, base64
masquerading as encryption, short repeating XOR keys, and secret keys shipped
to the browser.</p>
<p><b>The goal in this module:</b> break each misuse with real technique. Every
challenge page shows you the exact attack surface: the oracle to query, the
cookie to forge, the hash to extend, the ciphertext to decrypt.</p>
<p>Keys and secrets are random per server boot, so restart the lab for a fresh game.</p>`;

// GET /crypto -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('crypto', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'crypto', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Cryptographic Failures', `
    ${brief('Module briefing', BRIEF_HTML)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Eight labs where the cipher is fine but the usage is broken. Each card
    has a hint ladder: level 1 nudges, level 2 teaches the technique, level 3
    shows the shape of the attack. Keys and secrets are random per server boot,
    so restart the lab for a fresh game.</p>
    ${cards}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/">Back to all modules</a></p>
  ${fixSection('crypto', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'crypto',
  name: 'Cryptographic Failures',
  tagline: 'Break real crypto misuses: weak randomness, ECB oracles, CBC bit-flipping, length extension, and more.',
  description: 'The ciphers are fine; their usage is not. Eight hands-on labs built only on Node built-in crypto: brute-force a Math.random PIN, decrypt byte-at-a-time through an ECB oracle, flip CBC bits to forge an admin cookie, extend a SHA-256 MAC, crack an MD5 password, peel base64 "encryption", crib-drag a repeating XOR key, and steal an AES key from served JavaScript.',
  difficulty: 'Advanced',
  track: 'Advanced',
  prerequisites: ['Injection track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
