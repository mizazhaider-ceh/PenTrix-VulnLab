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
    hint: 'Invoices are fetched by a number in the URL. Find your own invoice request first, then ask what ties an invoice to its owner.',
    hints: [
      'Invoices are downloaded by id. Find your own invoice request in Burp\'s Proxy history first.',
      'The download endpoint trusts the :id parameter, and invoice ids follow a predictable pattern. Send the request to Repeater and vary the one thing that should not be yours to choose.',
      'Shape: your own invoice request with a single segment changed, the invoice id, aimed at an invoice issued to somebody else. If it downloads, ownership was never checked.',
    ],
    tools: 'BZ, B',
    est: 'about 10 to 20 minutes',
    how: 'Invoice downloads trust a predictable id in the URL, so any signed-in user can fetch invoices that belong to other customers.',
    link: '/idor#idor-download',
    start: 'In Burp Proxy, log in as alice, open your own invoice, and find the GET /idor/invoice/:id request in the proxy history.',
  },
  router,
};
