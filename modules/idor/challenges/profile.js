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
    hint: 'Log in as alice (id 2), then open a different user id in the URL, e.g. /idor/users/1.',
    hints: [
      'Your profile page has a number in its URL. What does the server do when you ask for a different number?',
      'The server looks the member up by id and never compares it with the id in your session, so the number in the URL is the only thing deciding whose data you see.',
      'Signed in as a normal user, open the profile of a different member id (1 is the admin, 3 is bob) and read what the page returns.',
    ],
    tools: 'B, C',
    how: 'Change the :id in /idor/users/:id to another user and read their secret.',
    link: '/idor#profile',
    start: 'curl -s -c jar -L http://localhost:3000/idor/login/alice\ncurl -s -b jar http://localhost:3000/idor/users/2',
  },
  router,
};
