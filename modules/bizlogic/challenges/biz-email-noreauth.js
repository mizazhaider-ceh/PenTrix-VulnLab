'use strict';
// Email Change Without Re-Authentication: /bizlogic/account. Changing the
// account email needs no password check, so "forgot password" sends the reset
// link to the new (attacker's) address and the account is taken over.
// NOTE: the finisher's shared.js (modules/bizlogic/shared.js) must provide:
//   shop(req)     session shop state (balance, cart, orders, email, password)
//   money(n)      USD formatting helper
//   backLink(s)   "Back to module / Reset shop" footer for shop pages
//   resetTokens   sessionID -> { token, email } password-reset token store,
//                 shared with the module /reset route (which clears it)
// NOTE: this file's POST routes need express.urlencoded({ extended: false })
// applied at the module level (index.js), exactly as router.js applies it to
// the module router today. Do not rely on app-level parsing.
const crypto = require('crypto');
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');
const { shop, backLink, resetTokens } = shared;

const router = express.Router();

const vuln = {
  id: 'biz-email-noreauth',
  name: 'Email Change Without Re-Authentication',
  difficulty: 'Medium',
  est: '15-25 minutes',
  hint: 'You can change the account email with no password confirmation. Then "forgot password" sends the reset to the new address: yours.',
  hints: ["Proxy /bizlogic/account and send the email-change POST to Repeater. Try changing the email without touching the password field.", "The reset link follows the account email, not your session. Run forgot-password in Repeater against the address you just set.", "Copy the demo token from the response page, then POST it to /bizlogic/account/reset with a new password. Check which address the reset link went to."],
  tools: 'BZ, B',
  how: 'The account email can be changed without proving you own the account. Then consider where a password reset for that account would be delivered.',
  link: '/bizlogic#biz-email-noreauth',
  start: 'Open Burp with your browser proxied and visit the shop account page. Watch the Proxy history while you use the "Change email" form, then send that request to Repeater and try a new email address you control. Next, send the "Forgot password" form to Repeater for that same address and read the reset token off the demo page.',
};

const cardTop = (label) => `
  <div class="card-top"><span class="orb" aria-hidden="true">👤</span><b>PenTrix Shop</b><span class="dim">${label}</span></div>`;

router.get('/account', (req, res) => {
  const s = shop(req);
  res.send(page('Account settings', `
    <div class="card clay-card">
      ${cardTop('account settings')}
      <h2>Account</h2>
      <p>Email: <b>${esc(s.email)}</b> · Password: <b>${esc('*'.repeat(Math.min(s.password.length, 12)))}</b></p>
      <h3>Change email</h3>
      <form method="POST" action="/bizlogic/account/email">
        <label for="new_email">New email</label>
        <input class="clay-input" type="text" id="new_email" name="new_email" placeholder="new email" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Change email</button></p>
      </form>
      <p class="note">No password asked. Interesting.</p>
      <h3>Forgot password</h3>
      <form method="POST" action="/bizlogic/account/forgot">
        <label for="forgot_email">Account email</label>
        <input class="clay-input" type="text" id="forgot_email" name="email" placeholder="account email" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Send reset link</button></p>
      </form>
      <p class="note">Demo mode: the reset link is displayed on screen instead of emailed.</p>
    </div>
    ${backLink(s)}
  `));
});

router.post('/account/email', (req, res) => {
  const s = shop(req);
  const newEmail = String(req.body.new_email || '').trim().slice(0, 120);
  if (!newEmail.includes('@')) {
    return res.status(400).send(page('Account', `
      <div class="card clay-card">
        ${cardTop('account settings')}
        <h2>Invalid email</h2>
        <p>That is not a valid email address.</p>
      </div>
      ${backLink(s)}
    `));
  }
  // VULN: changing the account email requires no password confirmation or
  // other re-authentication, so anyone at the keyboard can reroute the account.
  s.email = newEmail;
  res.send(page('Email changed', `
    <div class="card clay-card">
      ${cardTop('account settings')}
      <h2>Email changed</h2>
      <p>Account email is now <b>${esc(s.email)}</b>. No password was required.</p>
      <p>Next: use <b>forgot password</b> with this address to receive the reset link.</p>
    </div>
    ${backLink(s)}
  `));
});

router.post('/account/forgot', (req, res) => {
  const s = shop(req);
  const email = String(req.body.email || '').trim();
  if (email !== s.email) {
    return res.send(page('Forgot password', `
      <div class="card clay-card">
        ${cardTop('account settings')}
        <h2>No account found</h2>
        <p>No account uses that email address.</p>
      </div>
      ${backLink(s)}
    `));
  }
  const token = crypto.randomBytes(16).toString('hex');
  resetTokens[req.sessionID] = { token, email };
  res.send(page('Reset link sent', `
    <div class="card clay-card">
      ${cardTop('account settings')}
      <h2>Reset link "sent" to ${esc(email)}</h2>
      <p class="note">Demo mode: the email is shown here instead.</p>
      <p><a class="clay-btn clay-btn-primary" href="/bizlogic/account/reset?token=${token}">Reset your password</a></p>
      <p class="dim">Token: <code>${token}</code></p>
    </div>
    ${backLink(s)}
  `));
});

router.get('/account/reset', (req, res) => {
  const s = shop(req);
  const rec = resetTokens[req.sessionID];
  const token = String(req.query.token || '');
  if (!rec || rec.token !== token) {
    return res.status(400).send(page('Reset password', `
      <div class="card clay-card">
        ${cardTop('account settings')}
        <h2>Bad token</h2>
        <p>Invalid or expired reset token.</p>
      </div>
      ${backLink(s)}
    `));
  }
  res.send(page('Reset password', `
    <div class="card clay-card">
      ${cardTop('account settings')}
      <h2>Choose a new password for ${esc(rec.email)}</h2>
      <form method="POST" action="/bizlogic/account/reset">
        <input type="hidden" name="token" value="${esc(token)}" />
        <label for="new_password">New password</label>
        <input class="clay-input" type="password" id="new_password" name="new_password" placeholder="new password" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Set new password</button></p>
      </form>
    </div>
    ${backLink(s)}
  `));
});

router.post('/account/reset', (req, res) => {
  const s = shop(req);
  const rec = resetTokens[req.sessionID];
  const token = String(req.body.token || '');
  const newPassword = String(req.body.new_password || '').slice(0, 80);
  if (!rec || rec.token !== token) {
    return res.status(400).send(page('Reset password', `
      <div class="card clay-card">
        ${cardTop('account settings')}
        <h2>Bad token</h2>
        <p>Invalid or expired reset token.</p>
      </div>
      ${backLink(s)}
    `));
  }
  if (!newPassword) {
    return res.status(400).send(page('Reset password', `
      <div class="card clay-card">
        ${cardTop('account settings')}
        <h2>Missing password</h2>
        <p>A new password is required.</p>
      </div>
      ${backLink(s)}
    `));
  }
  // Takeover complete: the email was rerouted without re-auth, the reset token
  // went to the attacker's address, and the password is now theirs.
  s.password = newPassword;
  delete resetTokens[req.sessionID];

  let flagHtml = '';
  if (s.email !== s.originalEmail && !captured(req, 'bizlogic', 'biz-email-noreauth')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-email-noreauth'));
    flagHtml += fixPanel('bizlogic', 'biz-email-noreauth');
  }
  res.send(page('Password reset', `
    <div class="card clay-card">
      ${cardTop('account settings')}
      <h2>Password changed for ${esc(s.email)}</h2>
      ${s.email !== s.originalEmail
        ? '<p><b>Account takeover.</b> The email was changed with no password check, the reset link went to the new address, and the password is now yours.</p>'
        : '<p>Password updated.</p>'}
      ${flagHtml}
    </div>
    ${backLink(s)}
  `));
});

module.exports = { vuln, router };
