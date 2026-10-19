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
    hint: 'Log in as alice in the browser, then intercept the request for your own profile in Burp Proxy and send it to Repeater. In Repeater, change the number in the profile URL to a different member\'s id instead of your own.',
    hints: [
      'Your profile page has a number in its URL. What does the server do when you ask for a different number?',
      'Proxy the profile request in Burp, then send it to Repeater and change the number. The server looks the member up by id and never compares it with the id in your session, so the number in the URL is the only thing deciding whose data you see.',
      'Signed in as a normal user, in Repeater change the number in the profile URL to a different member\'s id (the admin\'s id is worth trying first) and read what the page returns.',
    ],
    tools: 'BZ, B, C',
    how: 'In Burp Repeater, change the :id in /idor/users/:id to another member\'s id and read the secret note the page returns.',
    link: '/idor#profile',
    start: 'Start Burp Suite Community with Proxy on 127.0.0.1:8080 and route your browser through it. Log in to the shop as alice, open your profile page, send GET /idor/users/2 to Repeater, then change the number in the URL to another member\'s id and resend it.',
  },
  router,
};
