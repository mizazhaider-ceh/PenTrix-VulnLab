'use strict';
// Brute-Forcing a 4-Digit OTP: the verify endpoint has no rate limit, lockout or expiry, so all 10,000 codes can be tried.
const express = require('express');
const crypto = require('crypto');
const { page, esc, brief, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { getDb } = require('../../../lib/db');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'otp-bruteforce',
  name: 'Brute-Forcing a 4-Digit OTP',
  difficulty: 'Medium',
  hint: 'You get a valid reset token for admin on screen, but the 4-digit code is never shown and there is no rate limiting. Script all 10,000 codes against the verify endpoint.',
  hints: ["The OTP is 4 digits. How many possibilities is that, and is there any lockout?", "10,000 codes, no lockout, no expiry. A simple Python loop trying 0000-9999 will hit it.", "Script POSTs to the verify endpoint with codes 0000-9999 until one works."],
  tools: 'P, C',
  how: 'Brute-force the 4-digit OTP for the given admin reset token, then reset the password.',
  link: '/auth/otp-reset',
  start: 'curl -c jar -b jar http://localhost:3000/auth/otp-reset',
};

function ensureAuthOtpTable() {
  getDb().exec(`CREATE TABLE IF NOT EXISTS auth_otp (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    otp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
}
ensureAuthOtpTable();

function failure(message) {
  return page(
    'Reset failed',
    shared.portal('Admin recovery', `<h2>Reset failed</h2>
  <p class="clay-err" role="alert">${message}</p>`) +
      shared.navLinks([['/auth/otp-reset', 'Get a new token']])
  );
}

router.get('/otp-reset', (req, res) => {
  const admin = shared.findUser('admin');
  const token = crypto.randomBytes(16).toString('hex');
  const otp = String(Math.floor(Math.random() * 10000)).padStart(4, '0');
  getDb()
    .prepare('INSERT INTO auth_otp (token, user_id, otp) VALUES (?,?,?)')
    .run(token, admin.id, otp);

  res.send(
    page(
      'Admin account recovery',
      brief(
        'Four digits stand between you and admin',
        `A recovery SMS with a <b>4-digit code</b> was "sent" to the admin's
         phone. This scenario hands you the reset <b>token</b> below, but never
         the code itself. Recover the admin account.`
      ) +
        shared.portal('Admin account recovery', `
  <p>Your recovery token for <b>admin</b>:</p>
  <pre class="token">${esc(token)}</pre>
  <form method="POST" action="/auth/otp-reset/verify">
    ${shared.field({ id: 'token', name: 'token', label: 'Recovery token', value: token })}
    ${shared.field({ id: 'otp', name: 'otp', label: '4-digit code', attrs: 'pattern="[0-9]{4}" inputmode="numeric" autocomplete="one-time-code"' })}
    ${shared.field({ id: 'newPassword', name: 'newPassword', label: 'New password', type: 'password', attrs: 'autocomplete="new-password"' })}
    ${shared.submitButton('Verify and reset')}
  </form>`) +
        hintLadder(vuln) +
        shared.navLinks([])
    )
  );
});

router.post('/otp-reset/verify', (req, res) => {
  const token = String(req.body.token || '').trim();
  const otp = String(req.body.otp || '').trim();
  const newPassword = String(req.body.newPassword || '');
  const row = getDb().prepare('SELECT * FROM auth_otp WHERE token = ?').get(token);

  if (!row) {
    return res.send(failure('Unknown recovery token.'));
  }

  // VULN: a 4-digit code with no rate limiting, no lockout and no expiry is
  // brute-forceable; the token alone was never meant to be the only secret.
  if (row.otp !== otp) {
    return res.send(
      page(
        'Wrong code',
        shared.portal('Admin recovery', `<h2>Wrong code</h2>
  <p class="clay-err" role="alert">The code <b>${esc(otp)}</b> did not match.</p>`) +
          shared.navLinks([['/auth/otp-reset', 'Back']])
      )
    );
  }

  const user = getDb().prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
  getDb().prepare('UPDATE users SET password = ? WHERE id = ?').run(newPassword, row.user_id);
  getDb().prepare('DELETE FROM auth_otp WHERE token = ?').run(token);

  const extra = flagBox(award(req, 'auth', 'otp-bruteforce')) + fixPanel('auth', 'otp-bruteforce');
  res.send(
    page(
      'Password reset',
      shared.portal('Admin recovery', `<h2>Password changed</h2>
  <p>The password for <b>${esc(user.username)}</b> was reset with the verification code.</p>`) +
        extra +
        shared.navLinks([['/auth/login', 'Sign in as admin']])
    )
  );
});

module.exports = { vuln, router };
