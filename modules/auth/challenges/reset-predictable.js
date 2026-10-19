'use strict';
// SHA-256 Predictable Reset Token: the reset token is a deterministic hash of public data, so anyone can mint one for any account.
const express = require('express');
const crypto = require('crypto');
const { page, esc, brief, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { getDb } = require('../../../lib/db');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'reset-predictable',
  name: 'SHA-256 Predictable Reset Token',
  difficulty: 'Medium',
  hint: 'The page shows the exact recipe: sha256(username + "reset-salt"). Compute it for "admin" with node or python and confirm the forged token without ever requesting an admin reset.',
  hints: ["The reset token is a SHA-256 hash. Hash of what? What inputs are predictable?", "The token is SHA-256 of the username plus a fixed string, and the recipe is printed on the page. Nothing in it is random or secret, so you can recompute it for any account.", "Compute the same hash locally for the admin account, then submit it on the confirm page with a new password, without requesting an admin reset first."],
  tools: 'B, P',
  how: 'Forge the admin reset token with SHA-256 and use it to change admin\'s password.',
  link: '/auth/sha-reset',
  start: 'curl "http://localhost:3000/auth/sha-reset?user=alice"',
};

// VULN: the reset token is a deterministic hash of public data, so anyone who
// knows the recipe can mint a valid token for any account.
function shaResetToken(username) {
  return crypto.createHash('sha256').update(username + 'reset-salt', 'utf8').digest('hex');
}

function failure(message) {
  return page(
    'Reset failed',
    shared.portal('Password reset', `<h2>Reset failed</h2>
  <p class="clay-err" role="alert">${message}</p>`) +
      shared.navLinks([['/auth/sha-reset', 'Try again']])
  );
}

router.get('/sha-reset', (req, res) => {
  const user = String(req.query.user || '').trim();
  let result = '';

  if (user) {
    const u = shared.findUser(user);
    if (u) {
      const token = shaResetToken(u.username);
      req.session.shaIssued = req.session.shaIssued || [];
      if (!req.session.shaIssued.includes(u.username)) {
        req.session.shaIssued.push(u.username);
      }
      const link = `/auth/sha-reset/confirm?token=${encodeURIComponent(token)}`;
      result = `<div class="note">
    <p>Reset link queued for <b>${esc(u.email)}</b>. This lab has no mail
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
      'Password reset (v2)',
      brief(
        'Reset admin without asking for it',
        `Northwind's newer reset flow builds its token in code that has been
         published with this page. Request a reset for alice to see how it
         works, then take over the <b>admin</b> account.`
      ) +
        shared.portal('Forgot your password? (v2)', `
  ${payloadBlock('Token recipe (from the app source)', "crypto.createHash('sha256').update(username + 'reset-salt').digest('hex')")}
  <form method="GET" action="/auth/sha-reset">
    ${shared.field({ id: 'user', name: 'user', label: 'Username', value: user || 'alice' })}
    ${shared.submitButton('Send reset link')}
  </form>
  ${result}`) +
        hintLadder(vuln) +
        shared.navLinks([])
    )
  );
});

router.get('/sha-reset/confirm', (req, res) => {
  const token = String(req.query.token || '');
  res.send(
    page(
      'Set a new password',
      shared.portal('Choose a new password', `
  <form method="POST" action="/auth/sha-reset/confirm">
    ${shared.field({ id: 'token', name: 'token', label: 'Reset token', value: token })}
    ${shared.field({ id: 'newPassword', name: 'newPassword', label: 'New password', type: 'password', attrs: 'autocomplete="new-password"' })}
    ${shared.submitButton('Change password')}
  </form>`) +
        shared.navLinks([['/auth/sha-reset', 'Request a reset link']])
    )
  );
});

router.post('/sha-reset/confirm', (req, res) => {
  const token = String(req.body.token || '').trim();
  const newPassword = String(req.body.newPassword || '');

  if (!token || !newPassword) {
    return res.send(failure('Token and new password are both required.'));
  }

  const users = getDb().prepare('SELECT username FROM users').all();
  const target = users.find((u) => shaResetToken(u.username) === token);
  if (!target) {
    return res.send(failure('This token does not map to an account.'));
  }

  getDb()
    .prepare('UPDATE users SET password = ? WHERE username = ?')
    .run(newPassword, target.username);

  // Award when admin's password was changed with a token this session never
  // legitimately received, i.e. a forged one.
  let extra = '';
  const issued = req.session.shaIssued || [];
  if (target.username === 'admin' && !issued.includes('admin')) {
    extra = flagBox(award(req, 'auth', 'reset-predictable')) + fixPanel('auth', 'reset-predictable');
  }

  res.send(
    page(
      'Password changed',
      shared.portal('Password reset', `<h2>Password changed</h2>
  <p>The password for user <b>${esc(target.username)}</b> was updated.</p>
  <p class="dim">Token used: <code>${esc(token)}</code></p>`) +
        extra +
        shared.navLinks([['/auth/login', 'Sign in']])
    )
  );
});

module.exports = { vuln, router };
