'use strict';
// Email Change IDOR: the target account comes from a client-supplied user_id.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { deny, requireUser, shopPage, kvTable } = require('../shared');
const { setEmailOverride, effectiveEmail } = require('../../../lib/account-state');

const router = express.Router();

router.get('/account', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const row = getDb().prepare('SELECT id, username, email FROM users WHERE id = ?').get(u.id);
  // A change this session made through the IDOR shows here for this session
  // only (P1-1); everyone else sees the account's real email.
  if (row) row.email = effectiveEmail(req, row.id, row.email);
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
  // Multi-student isolation (P1-1): the change is kept in this session, so
  // one student's IDOR cannot rewrite another student's view of the account.
  setEmailOverride(req, target.id, email);
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
      'Shape: the same change-email request with the account-identifying parameter pointed at a different account. Read the confirmation carefully afterwards: it tells you whose address actually moved.',
    ],
    tools: 'BZ, B',
    est: 'about 5 to 10 minutes',
    how: 'An account-settings action takes the target account from a form field, so the caller chooses whose account gets changed.',
    link: '/idor#idor-email-change',
    start: 'In Burp Proxy, log in as alice, open Account settings, and submit the change-email form while watching the request in the proxy history.',
  },
  router,
};
