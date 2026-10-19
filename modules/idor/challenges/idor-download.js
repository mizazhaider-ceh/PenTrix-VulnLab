'use strict';
// Invoice Download IDOR: invoices are served by sequential id with no ownership check.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { deny, requireUser, shopPage } = require('../shared');

const router = express.Router();

router.get('/invoice/:id', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    return deny(res, 400, 'Bad request', '<p class="muted">Invoice id must be a number.</p>');
  }
  // VULN: the invoice is served by id with no ownership check, so any
  // logged-in user can download anyone else's invoice.
  const row = getDb().prepare('SELECT * FROM idor_invoices WHERE id = ?').get(id);
  if (!row) {
    return deny(res, 404, 'Not found', '<p class="muted">No invoice with id ' + esc(req.params.id) + '.</p>');
  }
  let flagHtml = '';
  // Award: a non-admin member downloading an invoice that belongs to someone else.
  if (u.id !== row.user_id && u.role !== 'admin') {
    flagHtml = flagBox(award(req, 'idor', 'idor-download')) + fixPanel('idor', 'idor-download');
  }
  res.send(shopPage(u, 'Invoice ' + row.ref, `
    <div class="clay-card">
      <div class="card-top"><b>${esc(row.ref)}</b><span class="clay-pill">Receipt</span></div>
      <pre>${esc(row.body)}</pre>
    </div>
    ${flagHtml}
  `));
});

module.exports = {
  vuln: {
    id: 'idor-download',
    name: 'Invoice Download IDOR',
    difficulty: 'Medium',
    hint: 'Log in as alice and change the number in the invoice URL to one that is not yours. The server never checks who the invoice belongs to.',
    hints: [
      'Invoices are downloaded by id. Do you own the invoice you are downloading?',
      'The download endpoint trusts the :id parameter with no ownership check. Invoice ids are sequential.',
      'Log in as alice, then request an invoice id that is not the one linked from your own navigation.',
    ],
    tools: 'B, C',
    how: 'Change the :id in /idor/invoice/:id to download someone else\'s invoice.',
    link: '/idor#idor-download',
    start: 'curl -s -c jar -L http://localhost:3000/idor/login/alice\ncurl -s -b jar http://localhost:3000/idor/invoice/1',
  },
  router,
};
