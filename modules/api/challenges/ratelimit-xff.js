'use strict';
// Rate limit bypass: the lockout identity comes from the spoofable X-Forwarded-For header.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');
const { passwordMatches } = require('../../../lib/account-state');

const router = express.Router();

// Rate-limit state for POST /api/v1/login, keyed by claimed client IP.
// Lockout counters are per session (P1-1): another student's attempts no
// longer trip your lockout or fill your counter.
const { createSessionState } = require('../../../lib/session-state');
const attemptStates = createSessionState(() => ({}));

router.post('/v1/login', (req, res) => {
  const { username, password } = req.body || {};
  const realIp = req.ip || req.socket.remoteAddress || 'unknown';
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const key = xff || realIp;
  const v1LoginAttempts = attemptStates.get(req);
  v1LoginAttempts[key] = (v1LoginAttempts[key] || 0) + 1;
  // VULN: the rate-limit identity comes from the client-controlled
  // X-Forwarded-For header, so the lockout is bypassed by spoofing a new IP.
  if (v1LoginAttempts[key] > 3) {
    return res.status(429).json({ ok: false, error: 'Too many attempts. Try again later.', attempts: v1LoginAttempts[key] });
  }
  const dbUser = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = passwordMatches(req, dbUser, password);
  let flag = null;
  if (ok && xff && (v1LoginAttempts[realIp] || 0) > 3) {
    // Genuine bypass: the real IP was locked out, yet login succeeded under a spoofed one.
    flag = award(req, 'api', 'ratelimit-xff');
  }
  if (ok) {
    req.session.user = { id: dbUser.id, username: dbUser.username, role: dbUser.role };
  }
  res.json({ ok, attempts: v1LoginAttempts[key], flag });
});

module.exports = {
  vuln: {
    id: 'ratelimit-xff',
    name: 'Rate Limit Bypass via X-Forwarded-For',
    difficulty: 'Medium',
    est: '10-20 minutes',
    hint: 'POST /api/v1/login locks an IP out after a few bad attempts, but the server does not check the real socket IP; it trusts a request header you can set yourself.',
    hints: ["The rate limit is keyed by client IP. Where does the server get the IP from?", "It trusts a client-controlled header. In Repeater you can add or edit any header before sending.", "First get your real identity locked out with bad passwords. Then, in Repeater, present the correct login under a different claimed identity: which header could carry that claim, so the limiter counts someone else?"],
    tools: 'BZ, C',
    how: 'The lockout counts an identity the client gets to choose. Prove you can be locked out and let in at the same time.',
    link: '/api#ratelimit-xff',
    start: 'In Burp, proxy one login attempt to /api/v1/login and send the request to Repeater, so you can edit headers and resend at will.',
  },
  router,
};
