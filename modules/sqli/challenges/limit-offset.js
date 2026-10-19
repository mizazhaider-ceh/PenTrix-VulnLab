'use strict';
// LIMIT/OFFSET Injection: the limit parameter is interpolated raw into the
// LIMIT clause, which accepts more than a plain page-size number.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { shopShell } = require('../shared');

const router = express.Router();

router.get('/paged', (req, res) => {
  const limit = req.query.limit !== undefined ? String(req.query.limit) : '2';
  const db = getDb();
  // VULN: limit interpolated raw into the LIMIT clause.
  const sql = `SELECT id, name, price FROM products ORDER BY id LIMIT ${limit}`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.id))}</td><td>${esc(r.name)}</td><td>${esc(String(r.price))}</td></tr>`
  ).join('\n');
  let body = `
    <h1>Paged catalog</h1>
    ${brief('Paged Catalog', 'The catalog shows 2 products per page. The <code>limit</code> parameter controls the page size and is interpolated raw into the query.')}
    <form class="clay-card" method="GET" action="/sqli/paged">
      <div class="card-top"><b>Page size</b></div>
      <div class="clay-field">
        <label for="limit">Limit</label>
        <input class="clay-input" id="limit" name="limit" value="${esc(limit)}" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Show</button>
    </form>
  `;
  body += error
    ? `<div class="warn"><p><strong>Database error:</strong> ${esc(error)}</p></div>`
    : `<p>Showing ${rows.length} product(s).</p>
      <div class="tbl-scroll"><table class="tbl">
        <caption class="sr-only">Paged products</caption>
        <thead><tr><th scope="col">ID</th><th scope="col">Name</th><th scope="col">Price</th></tr></thead>
        <tbody>${table}</tbody>
      </table></div>`;
  let flagHtml = '';
  // Genuine LIMIT-syntax injection: non-numeric LIMIT content that still runs
  // AND actually changes the page (more rows, or different rows, than the
  // default LIMIT 2 page). A no-op suffix such as "2--x", "+2" or "2.0" runs
  // fine but shows the same page, so it earns nothing.
  if (!error && /[^0-9]/.test(limit) && rows.length > 0) {
    const firstPage = db.prepare('SELECT id FROM products ORDER BY id LIMIT 2').all().map((r) => r.id);
    const got = rows.map((r) => r.id);
    const samePage = got.length === firstPage.length && got.every((id, i) => id === firstPage[i]);
    if (!samePage) {
      flagHtml = flagBox(award(req, 'sqli', 'limit-offset'));
      flagHtml += fixPanel('sqli', 'limit-offset');
      flagHtml += fixCta('sqli', 'limit-offset');
    }
  }
  res.send(page('Paged Catalog (LIMIT Injection)', shopShell('Catalog', body + flagHtml + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

module.exports = {
  vuln: {
    id: 'limit-offset',
    name: 'LIMIT/OFFSET Injection',
    difficulty: 'Easy',
    hint: 'The page shows only 2 products by default, but the limit parameter is interpolated raw into the LIMIT clause. LIMIT accepts more than a plain number.',
    hints: ["The page shows only 2 products, controlled by a limit parameter. LIMIT is part of the SQL query. What else can LIMIT do?", "The limit value is interpolated raw into the query. LIMIT accepts negative numbers and comma offsets (LIMIT 0,100), which dump rows beyond the intended page.", "Give the limit parameter values beyond plain positive numbers: go below zero, or pass two numbers separated by a comma. Watch how the returned rows shift and pull the hidden ones into view."],
    tools: "B",
    how: 'Inject LIMIT syntax (negative numbers, comma offsets) to dump rows beyond the default page.',
    link: '/sqli/paged',
    start: "curl 'http://localhost:3000/sqli/paged?limit=2'",
  },
  router,
};
