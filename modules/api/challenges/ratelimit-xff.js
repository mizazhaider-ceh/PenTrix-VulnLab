'use strict';
// Rate limit bypass: the lockout identity comes from the spoofable X-Forwarded-For header.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');

const router = express.Router();

// Rate-limit state for POST /api/v1/login, keyed by claimed client IP.
const v1LoginAttempts = {};

router.post('/v1/login', (req, res) => {
  const { username, password } = req.body || {};
  const realIp = req.ip || req.socket.remoteAddress || 'unknown';
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const key = xff || realIp;
  v1LoginAttempts[key] = (v1LoginAttempts[key] || 0) + 1;
  // VULN: the rate-limit identity comes from the client-controlled
  // X-Forwarded-For header, so the lockout is bypassed by spoofing a new IP.
  if (v1LoginAttempts[key] > 3) {
    return res.status(429).json({ ok: false, error: 'Too many attempts. Try again later.', attempts: v1LoginAttempts[key] });
  }
  const dbUser = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = !!(dbUser && dbUser.password === password);
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
    hint: 'POST /api/v1/login locks an IP out after 3 bad attempts, but the server does not check the real socket IP; it trusts a request header you can set yourself.',
    hints: ["The rate limit is keyed by client IP. Where does the server get the IP from?", "It trusts a client-controlled header. In Repeater you can add or edit any header before sending.", "Push your real IP past the lockout with bad passwords first, then resend the correct login with a spoofed forwarding header added in Repeater, so the limit counts a different identity."],
    tools: 'BZ, C',
    how: 'Trigger the lockout with bad passwords, then retry with the correct password and a spoofed X-Forwarded-For header. In Repeater this is one header edit before resending.',
    link: '/api#ratelimit-xff',
    start: 'In Burp, proxy one login attempt to /api/v1/login and send the request to Repeater, so you can edit headers and resend at will.',
  },
  router,
};
