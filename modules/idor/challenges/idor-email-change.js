'use strict';
// Email Change IDOR: the target account comes from a client-supplied user_id.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { deny, requireUser, shopPage, kvTable } = require('../shared');

const router = express.Router();

router.get('/account', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const row = getDb().prepare('SELECT id, username, email FROM users WHERE id = ?').get(u.id);
  res.send(shopPage(u, 'Account settings', `
    ${kvTable('Account details', [
      ['Username', esc(row.username)],
      ['Email', esc(row.email)],
    ])}
    <form class="clay-card" method="POST" action="/idor/account/email">
      <div class="card-top"><b>Change email</b></div>
      <input type="hidden" name="user_id" value="${Number(u.id)}">
      <div class="clay-field">
        <label for="email">New email address</label>
        <input class="clay-input" id="email" name="email" type="email" placeholder="you@example.com" required>
      </div>
      <button type="submit" class="clay-btn clay-btn-primary">Update email</button>
    </form>
    ${hintLadder(module.exports.vuln)}
  `));
});

router.post('/account/email', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const targetId = parseInt(req.body.user_id, 10);
  const email = String(req.body.email || '').trim();
  const target = getDb().prepare('SELECT id, username FROM users WHERE id = ?').get(targetId);
  if (!target || !email) {
    return deny(res, 400, 'Bad request',
      '<p class="muted">A valid account and email address are required.</p><p><a href="/idor/account">Back to account settings</a></p>');
  }
  // VULN: the target account comes from a client-supplied user_id parameter
  // with no check that it matches the logged-in user.
  getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(email, target.id);
  let flagHtml = '';
  // Award: a non-admin member changing another user's email address.
  if (target.id !== u.id && u.role !== 'admin') {
    flagHtml = flagBox(award(req, 'idor', 'idor-email-change')) + fixPanel('idor', 'idor-email-change');
  }
  res.send(shopPage(u, 'Email updated', `
    <div class="note"><p>The email for <strong>${esc(target.username)}</strong> (id ${Number(target.id)}) is now <strong>${esc(email)}</strong>.</p></div>
    ${flagHtml}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/idor/account">Back to account settings</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'idor-email-change',
    name: 'Email Change IDOR',
    difficulty: 'Easy',
    hint: 'The change-email form on /idor/account sends a hidden user_id field. Intercept the POST in Burp Proxy and read every parameter the browser sent.',
    hints: [
      'The email change form carries more than just the new address. Capture the POST in Burp\'s Proxy history and read every parameter.',
      'The form submits a user_id parameter that the server trusts. Send the captured request to Repeater.',
      'Replay the request in Repeater with another account\'s id in the user_id field (the admin is a strong target), then read the confirmation page carefully: it tells you whose address actually moved.',
    ],
    tools: 'BZ, B',
    how: 'POST /idor/account/email with another user\'s id in the user_id parameter.',
    link: '/idor#idor-email-change',
    start: 'In Burp Proxy, log in as alice, open Account settings, and submit the change-email form while watching the request in the proxy history.',
  },
  router,
};
