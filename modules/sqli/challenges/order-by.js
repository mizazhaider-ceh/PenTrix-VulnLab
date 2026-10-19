'use strict';
// ORDER BY Injection: the sort parameter goes straight into ORDER BY, which
// accepts full expressions, including a CASE WHEN boolean oracle.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { shopShell } = require('../shared');

const router = express.Router();

router.get('/sort', (req, res) => {
  const sort = req.query.sort !== undefined ? String(req.query.sort) : 'name';
  const db = getDb();
  // VULN: sort expression interpolated directly into the ORDER BY clause.
  const sql = `SELECT id, name, price FROM products ORDER BY ${sort}`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r, i) => `
    <tr><td>${i + 1}</td><td>${esc(String(r.id))}</td><td>${esc(r.name)}</td><td>${esc(String(r.price))}</td></tr>`
  ).join('\n');
  let body = `
    <h1>Sortable catalog</h1>
    ${brief('Sortable Catalog', 'Sort the product catalog. The <code>sort</code> parameter is interpolated straight into the <code>ORDER BY</code> clause, and ORDER BY accepts far more than a column name.')}
    <form class="clay-card" method="GET" action="/sqli/sort">
      <div class="card-top"><b>Sort the catalog</b></div>
      <div class="clay-field">
        <label for="sort">Sort by</label>
        <input class="clay-input" id="sort" name="sort" value="${esc(sort)}" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Sort</button>
    </form>
    <div class="note"><p>Try <code>price DESC</code>, a column index like <code>2</code>, then ask yourself what a <code>CASE WHEN</code> could do here.</p></div>
  `;
  body += error
    ? `<div class="warn"><p><strong>Database error:</strong> ${esc(error)}</p></div>`
    : `<div class="tbl-scroll"><table class="tbl">
        <caption class="sr-only">Sorted products</caption>
        <thead><tr><th scope="col">#</th><th scope="col">ID</th><th scope="col">Name</th><th scope="col">Price</th></tr></thead>
        <tbody>${table}</tbody>
      </table></div>`;
  let flagHtml = '';
  // The exploit genuinely ran when a CASE WHEN oracle against the users table
  // executed inside ORDER BY without error: the row order is the oracle.
  if (!error && /case\s+when/i.test(sort) && /\busers\b/i.test(sort)) {
    flagHtml = flagBox(award(req, 'sqli', 'order-by'));
    flagHtml += fixPanel('sqli', 'order-by');
  }
  res.send(page('Sortable Catalog (ORDER BY Injection)', shopShell('Catalog', body + flagHtml + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

module.exports = {
  vuln: {
    id: 'order-by',
    name: 'ORDER BY Injection',
    difficulty: 'Medium',
    hint: 'The sort parameter goes straight into ORDER BY. ORDER BY accepts full expressions, including CASE WHEN with a subquery against the users table. Watch the row order flip as your condition changes.',
    hints: ["The sort parameter changes the order of products. ORDER BY doesn't just take column names. What else can go there?", "ORDER BY accepts full SQL expressions, including CASE WHEN with a subquery. If the CASE condition is true, sort one way; if false, sort another way. The row order becomes your oracle.", "Inject: sort=CASE WHEN (SELECT substr(secret,1,1) FROM users WHERE username='admin')='P' THEN name ELSE price END --  and watch the order flip as your guess changes."],
    tools: "B, C",
    how: 'Run a CASE WHEN boolean oracle inside ORDER BY against the users table and observe the sorting change.',
    link: '/sqli/sort',
    start: "curl -G 'http://localhost:3000/sqli/sort' --data-urlencode 'sort=price DESC'",
  },
  router,
};
