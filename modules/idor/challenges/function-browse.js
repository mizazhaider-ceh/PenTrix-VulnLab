'use strict';
// Forced Browsing to Admin Function: an admin-only page checks login but not role.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { effectiveEmail } = require('../../../lib/account-state');
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
    `<tr><td>${Number(x.id)}</td><td>${esc(x.username)}</td><td>${esc(x.role)}</td><td>${esc(effectiveEmail(req, x.id, x.email))}</td></tr>`).join('');
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
    hint: 'Some pages exist without being linked anywhere. Unlinked is not the same as protected: what plausible staff addresses follow from the paths you already know?',
    hints: [
      'Some URLs are not linked in the UI. Does that mean the server blocks them?',
      'Proxy a login as alice or bob, send the logged-in request to Repeater, then change only the request line path.',
      'Shape: a signed-in request with only the path changed, aimed at a plausible staff address under the admin area. If a members directory renders for a non-admin session, the missing link was the only protection.',
    ],
    tools: 'BZ, B',
    est: 'about 10 to 20 minutes',
    how: 'Staff pages are hidden by obscurity alone: unlinked, but served to any signed-in user who guesses the address.',
    link: '/idor#function-browse',
    start: 'Open the IDOR shop in Burp\'s built-in browser and log in as an ordinary user. In Proxy history, send a logged-in request to Repeater and experiment with the request path.',
  },
  router,
};
