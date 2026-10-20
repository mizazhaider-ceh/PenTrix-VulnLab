'use strict';
// Missing rate limiting: POST /api/login counts attempts but never blocks them.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { passwordMatches } = require('../../../lib/account-state');
const { award } = require('../../../lib/flags');

const router = express.Router();

// VULN: brute-force counter lives in memory and is never enforced, so an
// Attempt counts are per session (P1-1): one student's guesses no longer
// stack onto another student's counter toward the flag.
const { createSessionState } = require('../../../lib/session-state');
const attemptStates = createSessionState(() => ({}));

// POST /api/login -> v3 credential stuffing target with no rate limiting.
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const key = String(username || '');
  const attempts = attemptStates.get(req);
  // VULN: attempts are counted but never limited, so unlimited password
  // guesses can be fired at this endpoint with no lockout or CAPTCHA.
  attempts[key] = (attempts[key] || 0) + 1;

  const user = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = passwordMatches(req, user, password);
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
    est: '15-25 minutes',
    hint: 'POST /api/login counts attempts per username but never blocks them. What does a long history of failed guesses in one session, followed by a success, prove about this endpoint?',
    hints: ["The login endpoint counts attempts but never blocks them. What does that allow an attacker with Intruder?", "Without throttling, no guess is ever punished. A Sniper run can fire as many passwords as you like.", "Build the history first: send a run of wrong guesses through Intruder in one session, then send the correct login in Repeater so the success lands on top of that history."],
    tools: 'BZ, C',
    how: 'Nothing ever slows a guesser down on this login. Build a history of failed attempts in one session, then land a successful login on top of it.',
    link: '/api#rate-limit',
    start: 'In Burp, proxy one login attempt to /api/login, send the request to Intruder, and run a Sniper attack with a list of wrong passwords for alice.',
  },
  router,
};
