'use strict';
// Password Change Without Current Password: the endpoint trusts the session alone and never re-verifies identity.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, emptyState } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { getDb } = require('../../../lib/db');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'change-pass-noverify',
  name: 'Password Change Without Current Password',
  difficulty: 'Easy',
  hint: 'Log in as anyone through /auth/login, then open the change-password page and notice it never asks for the current password.',
  hints: ["You're logged in and want to change your password. Does it ask for the current one?", "The change-password endpoint only checks your session, not your current password. Anyone with session access (XSS, shared computer) can set a new password.", "Get yourself signed in, then submit a new password on the change-password page. The key insight: a correct implementation would demand proof of the old password first, and that check is missing here."],
  tools: 'B',
  how: 'While logged in, change the account password without knowing the current one.',
  link: '/auth/change-password',
  start: 'curl -c jar -b jar -d "username=bob&password=bob123" http://localhost:3000/auth/login',
};

router.get('/change-password', (req, res) => {
  const me = shared.authSessionUser(req);
  if (!me) {
    return res.send(
      page(
        'Change password',
        emptyState(
          'Sign in first',
          '<p>Account settings are only available to signed-in members.</p>',
          '<p><a class="clay-btn clay-btn-primary" href="/auth/login">Sign in</a></p>'
        ) + shared.navLinks([])
      )
    );
  }
  res.send(
    page(
      'Change password',
      brief(
        'Take over a signed-in account',
        `You are signed in as <b>${esc(me)}</b>. Imagine you only have brief access
         to this session (an unlocked laptop, a stolen cookie). Make the
         account yours.`
      ) +
        shared.portal('Account settings', `
  <h2>Change your password</h2>
  <form method="POST" action="/auth/change-password">
    ${shared.field({ id: 'newPassword', name: 'newPassword', label: 'New password', type: 'password', attrs: 'autocomplete="new-password"' })}
    ${shared.submitButton('Change password')}
  </form>`) +
        hintLadder(vuln) +
        shared.navLinks([])
    )
  );
});

router.post('/change-password', (req, res) => {
  const me = shared.authSessionUser(req);
  if (!me) {
    return res.status(401).send(
      page(
        'Denied',
        shared.portal('Account settings', `<h2>401</h2>
  <p class="clay-err" role="alert">Sign in first.</p>`) +
          shared.navLinks([['/auth/login', 'Sign in']])
      )
    );
  }
  const newPassword = String(req.body.newPassword || '');
  if (!newPassword) {
    return res.send(
      page(
        'Change failed',
        shared.portal('Account settings', `<h2>Change failed</h2>
  <p class="clay-err" role="alert">A new password is required.</p>`) +
          shared.navLinks([['/auth/change-password', 'Try again']])
      )
    );
  }

  // VULN: changing the password needs only an active session, never the
  // current password, so an unattended or hijacked session is enough to take
  // over the account.
  getDb().prepare('UPDATE users SET password = ? WHERE username = ?').run(newPassword, me);
  const extra = flagBox(award(req, 'auth', 'change-pass-noverify')) + fixPanel('auth', 'change-pass-noverify');
  res.send(
    page(
      'Password changed',
      shared.portal('Account settings', `<h2>Password changed</h2>
  <p>The password for <b>${esc(me)}</b> was changed without asking for the old one.</p>`) +
        extra +
        shared.navLinks([])
    )
  );
});

module.exports = { vuln, router };
