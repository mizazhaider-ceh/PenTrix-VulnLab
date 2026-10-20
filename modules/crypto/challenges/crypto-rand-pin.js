'use strict';
// Predictable Reset PIN: /crypto/pin/generate issues a 4-digit PIN drawn from
// Math.random(), and /crypto/pin/verify accepts guesses with no rate limiting,
// so brute-forcing 0000-9999 recovers the PIN. The space is deliberately 4
// digits: small enough for Burp Community Intruder to walk in minutes,
// which keeps the lesson (predictable PRNG plus no throttling) honest.
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
      <p>Click below and we will text a 4-digit reset PIN to the demo account's
      (imaginary) phone. Then prove you received it.</p>
      <form method="POST" action="/crypto/pin/generate">
        <button class="clay-btn clay-btn-primary" type="submit">Generate reset PIN</button>
      </form>
      <p>PIN status: <b>${resetPin === null ? 'no PIN issued yet' : 'a PIN is active (it was "sent" to the phone)'}</b></p>
      <hr />
      <h3>Enter PIN</h3>
      <form method="POST" action="/crypto/pin/verify">
        <input class="clay-input" name="pin" size="10" maxlength="4" placeholder="0000" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Verify</button></p>
      </form>
      <p class="note">There is no rate limiting on purpose. A 4-digit space is only
      10,000 guesses, which is exactly why a predictable generator plus no
      throttling is dangerous in real products too.</p>
    </div>
  `));
});

router.post('/pin/generate', (req, res) => {
  // VULN: Math.random is not cryptographically secure, and 10^4 guesses with
  // no rate limiting is a trivially brute-forceable space.
  resetPin = String(Math.floor(Math.random() * 1e4)).padStart(4, '0');
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
        4-digit space.</p>
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
    hint: 'The 4-digit PIN comes from Math.random and nothing stops you from guessing. Ten thousand guesses is an Intruder job, not a chore.',
    hints: ["The PIN is from Math.random(). Is that cryptographically secure? A predictable generator is the bug; the missing rate limit is what makes it exploitable by hand.", "No rate limiting. Load the verify POST into Intruder: the space is only 0000-9999. Honest timing: Community Intruder is throttled to roughly 5 to 10 requests per second, so expect on the order of 20 to 40 minutes for the full space. Time your first 100 payloads, multiply by 100, and decide whether to let Intruder run or switch to a 20-line script (about a minute at localhost speed).", "Use a numbers payload (or null payloads) generating 0000-9999. Read the results with Grep-Match on the success text (Tool Setup Guide, section 8) instead of eyeballing 10,000 rows. Watch for a 200 among the 401s."],
    tools: 'BZ',
    est: 'about 10 to 30 minutes',
    how: 'Request a reset PIN, then count what stands between an attacker and the right one: a small space, a predictable generator, and nothing that slows a guesser down.',
    link: '/crypto#crypto-rand-pin',
    start: 'Open Burp, set it as your browser proxy, and browse to /crypto/pin. Click Generate reset PIN. In Proxy history find POST /crypto/pin/verify, Send to Intruder, and attack the PIN field with a numbers payload from 0000 to 9999. One response returns 200.',
  },
  router,
};
