'use strict';
// Password Reset Poisoning: POST /hostheader/forgot builds the emailed reset
// link from the untrusted Host header. A poisoned Host makes the victim's
// token point at the attacker's collector (GET /hostheader/evil-collect).
const express = require('express');
const crypto = require('crypto');
const { esc, page } = require('../../../lib/page');
const { tokenDb } = require('../shared');

const router = express.Router();

// GET /forgot -> password reset request form (fictional self-service portal).
router.get('/forgot', (req, res) => {
  res.send(page('Forgot password', `
    <div class="clay-card">
      <h2>Forgot your password?</h2>
      <p>Enter your email and we will send a reset link.</p>
      <form method="POST" action="/hostheader/forgot">
        <div class="clay-field">
          <label for="email">Email address</label>
          <input class="clay-input" type="email" id="email" name="email"
            placeholder="alice@pentrix.lab" required />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Send reset link</button>
      </form>
      <p class="note dim">The reset link is built from the <code>Host</code>
      request header. The "sent" email is shown on the next page so you can play
      both attacker and victim.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader">Back to the module</a></p>
    </div>
  `));
});

// POST /forgot -> issue a one-time token and show the "sent" email (lab view).
router.post('/forgot', (req, res) => {
  const email = String(req.body.email || '').slice(0, 120);
  if (!email.includes('@')) {
    return res.status(400).send(page('Forgot password', `
      <div class="clay-card">
        <p>A valid email address is required.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader/forgot">Back</a></p>
      </div>
    `));
  }
  const host = String(req.headers.host || '');
  const token = crypto.randomBytes(16).toString('hex');
  tokenDb()
    .prepare('INSERT INTO hostheader_tokens (token, email, issued_host, vuln) VALUES (?,?,?,?)')
    .run(token, email, host, 'host-reset-poison');
  // VULN: the password-reset link is built from an untrusted Host-style header.
  const link = 'http://' + host + '/hostheader/reset?token=' + token;
  res.send(page('Reset link sent', `
    <div class="clay-card">
      <h2>Email sent (lab view)</h2>
      <p>In a real app this would be emailed. The lab shows it so you can play
      both attacker and victim:</p>
      <div class="clay-well">
        <p>Hi ${esc(email)},</p>
        <p>Reset your password here:<br /><a href="${esc(link)}">${esc(link)}</a></p>
      </div>
      <p class="note dim">This email was built from the <code>Host</code> header
      your request carried. A victim who "clicks" this link sends the token to
      the collector at <code>/hostheader/evil-collect?token=...</code>, which
      awards the flag only when the token was issued under a poisoned host.</p>
      <p>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader/forgot">Send another</a>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader">Back to the module</a>
      </p>
    </div>
  `));
});

module.exports = {
  vuln: {
    id: 'host-reset-poison',
    name: 'Password Reset Poisoning',
    difficulty: 'Medium',
    hint: 'The reset email builds its link from the Host header. Make the victim\'s token land in your collector.',
    hints: ["The reset link is built from the Host header. In Burp Repeater you can rewrite the Host header of the forgot-password POST before you send it.", "Proxy the form submit, send it to Repeater, and edit the Host line to name a domain you control. Watch where the reset link in the lab-view email points.", "Request the reset for the victim's email with the poisoned Host. The victim receives a genuine link carrying a valid token, but your header decides where it points, so the token leaks to you. Carry that token to the collector with your normal browser."],
    tools: 'BZ, C',
    how: 'Send the forgot-password POST through Burp Repeater with a rewritten Host header, then take the token from the poisoned reset link to /hostheader/evil-collect?token=...',
    link: '/hostheader#host-reset-poison',
    start: 'In Burp, load the lab\'s forgot-password form (GET /hostheader/forgot). Proxy the POST request and send it to Repeater. In Repeater, edit the Host header to a domain you control and send it. Read the reset token from the "Email sent" lab view, then visit /hostheader/evil-collect?token=THE_TOKEN in your browser.',
  },
  router,
};
