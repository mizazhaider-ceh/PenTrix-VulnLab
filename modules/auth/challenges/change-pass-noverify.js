'use strict';
// Password Change Without Current Password: the endpoint trusts the session alone and never re-verifies identity.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, emptyState } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { setPasswordOverride } = require('../../../lib/account-state');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'change-pass-noverify',
  name: 'Password Change Without Current Password',
  difficulty: 'Easy',
  est: '5-10 minutes',
  hint: 'Route your browser through Burp, log in at /auth/login, then open the change-password page and notice it never asks for the current password.',
  hints: ["Proxy your login through Burp so the session is captured. On the change-password page, does the form ask for the current password?", "Intercept the change-password POST in Burp and look at the parameters: the server checks your session cookie, never the old password.", "Send the change-password request to Repeater and replay it with a new password value. A correct implementation would demand proof of the old password first, and that check is missing here."],
  tools: 'BZ, B',
  how: 'In Burp, intercept the change-password request and replay it with a new password, without supplying the old one.',
  link: '/auth/change-password',
  start: 'Set Burp as your browser proxy, log in at /auth/login, then load /auth/change-password through the Proxy.',
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
  // Multi-student isolation (P1-1): the new password lives in this session
  // only. The shared accounts table keeps the seeded password, so another
  // student's brute-force lab still works.
  setPasswordOverride(req, me, newPassword);
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
