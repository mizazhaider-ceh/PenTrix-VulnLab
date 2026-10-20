'use strict';
// Unprotected Admin Panel: the panel only checks that a session exists, never the role.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { requireUser, shopPage } = require('../shared');

const router = express.Router();

router.get('/admin', (req, res) => {
  // VULN: the panel only checks that a session exists; it never checks the
  // user's role, so any logged-in user can open the admin panel.
  const u = requireUser(req, res);
  if (!u) return;
  const db = getDb();
  const users = db.prepare('SELECT id, username, role FROM users').all();
  const orders = db.prepare('SELECT id, user_id, item, total, address FROM orders').all();
  let flagHtml = '';
  // Award: a non-admin user reached the admin panel.
  if (u.role !== 'admin') {
    flagHtml = flagBox(award(req, 'idor', 'admin')) + fixPanel('idor', 'admin');
  }
  const userRows = users.map((x) =>
    `<tr><td>${Number(x.id)}</td><td>${esc(x.username)}</td><td>${esc(x.role)}</td></tr>`).join('');
  const orderRows = orders.map((x) =>
    `<tr><td>${Number(x.id)}</td><td>${Number(x.user_id)}</td><td>${esc(x.item)}</td><td>${esc(Number(x.total).toFixed(2))}</td><td>${esc(x.address)}</td></tr>`).join('');
  res.send(shopPage(u, 'Admin panel', `
    ${flagHtml}
    <div class="tbl-scroll"><table class="tbl">
      <caption>All members</caption>
      <thead><tr><th scope="col">ID</th><th scope="col">Username</th><th scope="col">Role</th></tr></thead>
      <tbody>${userRows}</tbody>
    </table></div>
    <div class="tbl-scroll"><table class="tbl">
      <caption>All orders</caption>
      <thead><tr><th scope="col">ID</th><th scope="col">User ID</th><th scope="col">Item</th><th scope="col">Total (EUR)</th><th scope="col">Ship to</th></tr></thead>
      <tbody>${orderRows}</tbody>
    </table></div>
  `));
});

module.exports = {
  vuln: {
    id: 'admin',
    name: 'Unprotected Admin Panel',
    difficulty: 'Easy',
    hint: 'The admin panel is a URL like any other. What does the server actually check before serving it: that someone is signed in, or who that someone is?',
    hints: [
      'Proxy the browser traffic, then open Burp Repeater and resend the admin panel URL. Ask yourself: what actually protects that URL?',
      'A hidden link is not an access control. The page asks "are you signed in" but may never ask "are you an admin".',
      'Shape: a direct request for the admin panel URL, sent from an ordinary signed-in session. Compare what the server verified with what a role check would have verified.',
    ],
    tools: 'BZ, B',
    est: 'about 5 to 10 minutes',
    how: 'A privileged page is guarded by a login check only, so any signed-in account can open it.',
    link: '/idor#admin',
    start: 'Start Burp Suite Community, set Proxy on 127.0.0.1:8080, and point your browser through it. Log in to the shop as an ordinary user, then experiment in Repeater with requesting pages that were never linked to you.',
  },
  router,
};
