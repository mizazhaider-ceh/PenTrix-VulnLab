'use strict';
// Profile IDOR: member profiles are fetched by id with no ownership check.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { currentUser, deny, shopPage, kvTable } = require('../shared');

const router = express.Router();

router.get('/users/:id', (req, res) => {
  const u = currentUser(req);
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    return deny(res, 400, 'Bad request', '<p class="muted">Member id must be a number.</p>');
  }
  // VULN: profile is fetched by id with no ownership check. Any logged-in user
  // can read any other user's record, including the secret field.
  const row = getDb().prepare('SELECT id, username, role, secret FROM users WHERE id = ?').get(id);
  if (!row) {
    return deny(res, 404, 'Not found', '<p class="muted">No member with id ' + esc(req.params.id) + '.</p>');
  }
  let flagHtml = '';
  // Award: a non-admin member viewing a profile that is not their own.
  if (u && u.id !== row.id && u.role !== 'admin') {
    flagHtml = flagBox(award(req, 'idor', 'profile')) + fixPanel('idor', 'profile');
  }
  // The admin secret is the SQL injection lab's exfiltration target, so it is
  // never rendered here (otherwise this page would be a shortcut for that lab).
  const secretCell = row.role === 'admin'
    ? '<span class="dim">Not shown for staff accounts</span>'
    : '<code>' + esc(row.secret) + '</code>';
  res.send(shopPage(u, 'Member profile', kvTable('Member profile', [
    ['ID', String(Number(row.id))],
    ['Username', esc(row.username)],
    ['Role', esc(row.role)],
    ['Secret note', secretCell],
  ]) + flagHtml));
});

module.exports = {
  vuln: {
    id: 'profile',
    name: 'Profile IDOR',
    difficulty: 'Easy',
    hint: 'Your profile page is chosen by a number in its URL. What decides whether you may see the profile that number names?',
    hints: [
      'Your profile page has a number in its URL. What does the server do when you ask for a different number?',
      'Proxy the profile request in Burp, then send it to Repeater and change the number. The server looks the member up by id and never compares it with the id in your session, so the number in the URL is the only thing deciding whose data you see.',
      'Shape: your own signed-in profile request with a single segment changed, the id in the URL, aimed at a profile that is not yours. If it renders, the id was the only access control.',
    ],
    tools: 'BZ, B, C',
    est: 'about 5 to 10 minutes',
    how: 'Profile pages are selected by a guessable id in the URL, and nothing checks that the profile belongs to the signed-in user.',
    link: '/idor#profile',
    start: 'Start Burp Suite Community with Proxy on 127.0.0.1:8080 and route your browser through it. Log in to the shop as alice, open your profile page, and send the profile request to Repeater. From there, experiment with the request itself.',
  },
  router,
};
