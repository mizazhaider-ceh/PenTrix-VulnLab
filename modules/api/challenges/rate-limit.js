'use strict';
// Missing rate limiting: POST /api/login counts attempts but never blocks them.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');

const router = express.Router();

// VULN: brute-force counter lives in memory and is never enforced, so an
// attacker can hammer POST /api/login without lockout or slowdown.
const attempts = {};

// POST /api/login -> v3 credential stuffing target with no rate limiting.
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const key = String(username || '');
  // VULN: attempts are counted but never limited, so unlimited password
  // guesses can be fired at this endpoint with no lockout or CAPTCHA.
  attempts[key] = (attempts[key] || 0) + 1;

  const user = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = !!(user && user.password === password);
  let flag = null;
  if (ok && key === 'alice' && attempts[key] >= 15) {
    flag = award(req, 'api', 'rate-limit');
  }
  res.json({ ok, attempts: attempts[key], flag });
});

module.exports = {
  vuln: {
    id: 'rate-limit',
    name: 'Missing Rate Limiting',
    difficulty: 'Medium',
    hint: 'POST /api/login counts attempts per username but never blocks them. Fire 14+ wrong guesses for alice, then log in with the right password on the 15th attempt.',
    hints: ["The login endpoint counts attempts but never blocks them. What does that allow an attacker with Intruder?", "Without throttling, no guess is ever punished. A Sniper run can fire as many passwords as you like.", "Build the attempt count first: send 14 wrong guesses through Intruder, then forward the correct login in Repeater so the success lands on attempt 15 or later."],
    tools: 'BZ, C',
    how: 'Brute force alice\u2019s password, then fire 14 wrong guesses followed by the correct login. In Burp, run the guesses through Intruder and send the final login in Repeater; the flag is awarded when the successful login follows 15 or more attempts.',
    link: '/api#rate-limit',
    start: 'In Burp, proxy one login attempt to /api/login, send the request to Intruder, and run a Sniper attack with a list of wrong passwords for alice.',
  },
  router,
};
