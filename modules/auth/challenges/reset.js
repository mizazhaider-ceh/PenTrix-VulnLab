'use strict';
// Predictable Password Reset Tokens: the reset token is base64(username), shown on screen and accepted without any server-side record.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { setPasswordOverride } = require('../../../lib/account-state');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'reset',
  name: 'Predictable Password Reset Tokens',
  difficulty: 'Easy',
  hint: 'The reset link is displayed on screen and the token is just base64(username). Request a reset for alice to see the pattern, then mint a token for admin yourself and confirm it with a new password.',
  hints: [
    "Request a reset for alice and paste the token into Burp's Decoder. What does it turn out to be?",
    'The token carries no randomness and nothing binds it to a real email. Think about what a token minted for a different username would look like.',
    "Mint that token yourself and replay the confirm POST for it in Burp's Repeater, with a new password.",
  ],
  tools: 'BZ, B',
  how: 'Forge a reset token for admin (base64 of "admin") and submit it at /auth/reset/confirm to change admin\'s password. The whole chain runs through Burp Decoder and Repeater.',
  link: '/auth/reset',
  start: 'With Burp Proxy on your browser, open /auth/reset, request a reset for alice, follow the confirm link, and send its POST to Repeater.',
};

// VULN: the reset token is just base64(username), fully predictable and
// handed out without any email verification.
function resetTokenFor(username) {
  return Buffer.from(username, 'utf8').toString('base64');
}

// Usernames the reset flow has shown a token for in THIS session. The token
// is deterministic (base64(username)), so a token shown on screen is
// byte-identical to a forged one. Without a per-session record, that token
// could be replayed for the flag with no forging. The intended solve still
// works: forging a token for a user that was never issued one to this
// session still awards. (P1-1: this used to be process-global, so one
// student's issued reset blocked everyone else's forged-token solve.)

function failure(message) {
  return page(
    'Reset failed',
    shared.portal('Password reset', `<h2>Reset failed</h2>
  <p class="clay-err" role="alert">${message}</p>`) +
      shared.navLinks([['/auth/reset', 'Try again']])
  );
}

router.get('/reset', (req, res) => {
  const user = String(req.query.user || '').trim();
  let result = '';

  if (user) {
    const u = shared.findUser(user);
    if (u) {
      const token = resetTokenFor(u.username);
      req.session.issuedResets = req.session.issuedResets || [];
      if (!req.session.issuedResets.includes(token)) {
        req.session.issuedResets.push(token);
      }
      req.session.issuedResetUsers = req.session.issuedResetUsers || [];
      if (!req.session.issuedResetUsers.includes(u.username)) {
        req.session.issuedResetUsers.push(u.username);
      }
      // VULN: the "email" with the reset link is rendered right here on the
      // page for anyone to read, and the token is trivially predictable.
      const link = `/auth/reset/confirm?token=${encodeURIComponent(token)}`;
      result = `<div class="note">
    <p>A reset email was queued for <b>${esc(u.email)}</b>. This lab has no mail
    server, so the message is shown here instead:</p>
    <p><a href="${esc(link)}">${esc(link)}</a></p>
    <pre class="token">${esc(token)}</pre>
  </div>`;
    } else {
      result = `<p class="clay-err" role="alert">No account found for user <b>${esc(user)}</b>.</p>`;
    }
  }

  res.send(
    page(
      'Forgot password',
      brief(
        'Get admin\'s password changed',
        `Northwind emails a reset link to the address on file. Look at how this
         flow identifies the account being reset, and use that to change the
         password of the <b>admin</b> account.`
      ) +
        shared.portal('Forgot your password?', `
  <form method="GET" action="/auth/reset">
    ${shared.field({ id: 'user', name: 'user', label: 'Username', value: user || 'alice' })}
    ${shared.submitButton('Send reset link')}
  </form>
  ${result}`) +
        hintLadder(vuln) +
        shared.navLinks([])
    )
  );
});

router.get('/reset/confirm', (req, res) => {
  const token = String(req.query.token || '');
  res.send(
    page(
      'Set a new password',
      shared.portal('Choose a new password', `
  <form method="POST" action="/auth/reset/confirm">
    ${shared.field({ id: 'token', name: 'token', label: 'Reset token', value: token })}
    ${shared.field({ id: 'newPassword', name: 'newPassword', label: 'New password', type: 'password', attrs: 'autocomplete="new-password"' })}
    ${shared.submitButton('Change password')}
  </form>`) +
        shared.navLinks([['/auth/reset', 'Request a reset link']])
    )
  );
});

router.post('/reset/confirm', (req, res) => {
  const token = String(req.body.token || '').trim();
  const newPassword = String(req.body.newPassword || '');

  if (!token || !newPassword) {
    return res.send(failure('Token and new password are both required.'));
  }

  let username;
  try {
    // VULN: any base64-decodable string is treated as a token, and it maps
    // straight onto an account. No signature, no expiry, no binding.
    username = Buffer.from(token, 'base64').toString('utf8');
  } catch (e) {
    username = null;
  }

  const user = username ? shared.findUser(username) : null;
  if (!user) {
    return res.send(failure('This token does not map to an account.'));
  }

  const issued = req.session.issuedResets || [];
  // Multi-student isolation (P1-1): a token the reset flow showed to another
  // student's session must not block this session's forged token. The
  // "issued" record is per session; within one session the anti-replay
  // protection still holds (a token shown to you does not earn you the flag).
  const issuedUsers = req.session.issuedResetUsers || [];
  const wasLegit = issued.includes(token) || issuedUsers.includes(user.username);
  setPasswordOverride(req, user.username, newPassword);

  // Award when a password was changed with a token that was neither issued to
  // this session nor ever issued for that user (i.e. a forged / guessed
  // token), the classic outcome being admin's password.
  let extra = '';
  if (!wasLegit) {
    extra = flagBox(award(req, 'auth', 'reset')) + fixPanel('auth', 'reset');
  }

  res.send(
    page(
      'Password changed',
      shared.portal('Password reset', `<h2>Password changed</h2>
  <p>The password for user <b>${esc(user.username)}</b> was updated.</p>
  <p class="dim">Token used: <code>${esc(token)}</code></p>`) +
        extra +
        shared.navLinks([['/auth/login', 'Sign in with it']])
    )
  );
});

module.exports = { vuln, router };
