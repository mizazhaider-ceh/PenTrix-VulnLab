'use strict';
// Forced Browsing to Admin Function: an admin-only page checks login but not role.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { requireUser, shopPage } = require('../shared');

const router = express.Router();

router.get('/admin/users', (req, res) => {
  // VULN: only "logged in" is checked; the admin role is never required, so
  // any user can force-browse this admin function directly.
  const u = requireUser(req, res);
  if (!u) return;
  const users = getDb().prepare('SELECT id, username, role, email FROM users').all();
  let flagHtml = '';
  // Award: a non-admin user reached an admin-only function.
  if (u.role !== 'admin') {
    flagHtml = flagBox(award(req, 'idor', 'function-browse')) + fixPanel('idor', 'function-browse');
  }
  const rows = users.map((x) =>
    `<tr><td>${Number(x.id)}</td><td>${esc(x.username)}</td><td>${esc(x.role)}</td><td>${esc(x.email)}</td></tr>`).join('');
  res.send(shopPage(u, 'Member directory', `
    ${flagHtml}
    <div class="tbl-scroll"><table class="tbl">
      <caption>Staff tool: all registered members</caption>
      <thead><tr><th scope="col">ID</th><th scope="col">Username</th><th scope="col">Role</th><th scope="col">Email</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  `));
});

module.exports = {
  vuln: {
    id: 'function-browse',
    name: 'Forced Browsing to Admin Function',
    difficulty: 'Medium',
    hint: '/idor/admin/users is not linked anywhere for normal users, but nothing stops you from typing it. Log in as alice or bob and open it directly.',
    hints: [
      'Some URLs are not linked in the UI. Does that mean the server blocks them?',
      'Force-browse: type the staff URL directly. The server may not check your role on unlinked paths.',
      'Sign in as alice or bob and request a path under /idor/admin/ that would plausibly list the shop\'s members.',
    ],
    tools: 'B',
    how: 'Force-browse /idor/admin/users as a non-admin user.',
    link: '/idor#function-browse',
    start: 'curl -s -c jar -L http://localhost:3000/idor/login/bob\ncurl -s -b jar http://localhost:3000/idor/comments',
  },
  router,
};
