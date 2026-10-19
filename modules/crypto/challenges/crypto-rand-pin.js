'use strict';
// Predictable Reset PIN: /crypto/pin/generate issues a 6-digit PIN drawn from
// Math.random(), and /crypto/pin/verify accepts guesses with no rate limiting,
// so brute-forcing 000000-999999 recovers the PIN.
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();
// Form parsing for this challenge's routes (mirrors router.js router-scoped use).
router.use(express.urlencoded({ extended: false }));

// Vulnerable state: the active reset PIN (was module-level in router.js,
// now owned by this challenge file).
let resetPin = null;

router.get('/pin', (req, res) => {
  res.send(page('Predictable Reset PIN', `
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">📱</span><b>Acme Account Recovery</b><span class="dim">demo support portal</span></div>
      <h2>Password reset</h2>
      <p>Click below and we will text a 6-digit reset PIN to the demo account's
      (imaginary) phone. Then prove you received it.</p>
      <form method="POST" action="/crypto/pin/generate">
        <button class="clay-btn clay-btn-primary" type="submit">Generate reset PIN</button>
      </form>
      <p>PIN status: <b>${resetPin === null ? 'no PIN issued yet' : 'a PIN is active (it was "sent" to the phone)'}</b></p>
      <hr />
      <h3>Enter PIN</h3>
      <form method="POST" action="/crypto/pin/verify">
        <input class="clay-input" name="pin" size="10" maxlength="6" placeholder="000000" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Verify</button></p>
      </form>
      <p class="note">There is no rate limiting on purpose. A 6-digit space is only
      one million guesses: script it.</p>
    </div>
  `));
});

router.post('/pin/generate', (req, res) => {
  // VULN: Math.random is not cryptographically secure, and 10^6 guesses with
  // no rate limiting is a trivially brute-forceable space.
  resetPin = String(Math.floor(Math.random() * 1e6)).padStart(6, '0');
  res.redirect('/crypto/pin');
});

router.post('/pin/verify', (req, res) => {
  const guess = (req.body.pin || '').toString().trim();
  if (resetPin !== null && guess === resetPin) {
    const flag = award(req, 'crypto', 'crypto-rand-pin');
    return res.send(page('PIN accepted', `
      <div class="card clay-card">
        <h2>Reset authorized</h2>
        <p>PIN <code>${esc(guess)}</code> accepted. You brute-forced the whole
        6-digit space.</p>
        ${flagBox(flag)}
        ${fixPanel('crypto', 'crypto-rand-pin')}
        <p><a href="/crypto">Back to the module</a></p>
      </div>
    `));
  }
  res.status(401).send(page('Wrong PIN', `
    <div class="card clay-card">
      <h2>Wrong PIN</h2>
      <p><code>${esc(guess) || '(empty)'}</code> is not the active PIN. Keep guessing:
      there is no lockout.</p>
      <p><a href="/crypto/pin">Back</a></p>
    </div>
  `));
});

module.exports = {
  vuln: {
    id: 'crypto-rand-pin',
    name: 'Predictable Reset PIN',
    difficulty: 'Easy',
    hint: 'The 6-digit PIN comes from Math.random and nothing stops you from guessing. One million guesses is an Intruder job, not a chore.',
    hints: ["The PIN is from Math.random(). Is that cryptographically secure?", "No rate limiting. Load the verify POST into Intruder and brute-force the PIN space.", "Use a null payload generating 000000-999999. Watch for a 200 among the 401s."],
    tools: 'BZ',
    how: 'Generate a PIN, then let Burp Intruder brute-force the whole 6-digit space against the verify endpoint.',
    link: '/crypto#crypto-rand-pin',
    start: 'Open Burp, set it as your browser proxy, and browse to /crypto/pin. Click Generate reset PIN. In Proxy history find POST /crypto/pin/verify, Send to Intruder, and attack the PIN field with a null payload generating 000000-999999. One response returns 200.',
  },
  router,
};
