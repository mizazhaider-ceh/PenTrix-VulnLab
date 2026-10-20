'use strict';
// LIMIT/OFFSET Injection: the limit parameter is interpolated raw into the
// LIMIT clause, which accepts more than a plain page-size number.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { challengeTarget, shopShell, withChallengeTarget } = require('../shared');

const router = express.Router();

router.get('/paged', (req, res) => {
  const limit = req.query.limit !== undefined ? String(req.query.limit) : '2';
  const db = getDb();
  // VULN: limit interpolated raw into the LIMIT clause.
  const sql = `SELECT id, name, price, description FROM products ORDER BY id LIMIT ${limit}`;
  let rows = [];
  let error = null;
  try {
    rows = withChallengeTarget('limit-offset', () => db.prepare(sql).all());
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.id))}</td><td>${esc(r.name)}</td><td>${esc(String(r.price))}</td><td>${esc(r.description)}</td></tr>`
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
        <thead><tr><th scope="col">ID</th><th scope="col">Name</th><th scope="col">Price</th><th scope="col">Description</th></tr></thead>
        <tbody>${table}</tbody>
      </table></div>`;
  let flagHtml = '';
  // P0-8: the award is bound to extracting THIS challenge's target, not to an
  // input pattern. The derived target sits in a catalog row the default
  // LIMIT 2 page never shows, so it can only reach this page's output through
  // genuine LIMIT-clause manipulation (negative numbers, comma offsets).
  // A no-op suffix such as "2--x", "+2" or "2.0" runs fine but shows the same
  // page, and a plain numeric limit (even one that reveals the row) earns
  // nothing: the technique must be LIMIT-syntax injection.
  const target = challengeTarget('limit-offset');
  if (!error && target && /[^0-9]/.test(limit) && body.includes(target)) {
    flagHtml = flagBox(award(req, 'sqli', 'limit-offset'));
    flagHtml += fixPanel('sqli', 'limit-offset');
    flagHtml += fixCta('sqli', 'limit-offset');
  }
  res.send(page('Paged Catalog (LIMIT Injection)', shopShell('Catalog', body + flagHtml + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

module.exports = {
  vuln: {
    id: 'limit-offset',
    name: 'LIMIT/OFFSET Injection',
    difficulty: 'Easy',
    est: 'about 5 to 10 minutes',
    hint: 'The page shows only 2 products by default, but the limit parameter is interpolated raw into the LIMIT clause. One catalog row that the default page never shows carries this challenge\'s audit token. Send the request to Burp Repeater and tweak limit: LIMIT accepts more than a plain number.',
    hints: ["The page shows only 2 products, controlled by a limit parameter. Proxy /sqli/paged through Burp and ask where that parameter lands in the SQL. What else can LIMIT do?", "In Repeater, change the limit value: it is interpolated raw into the query. LIMIT accepts negative numbers and comma offsets (LIMIT 0,100), which dump rows beyond the intended page.", "Give the limit parameter values beyond plain positive numbers in Repeater: go below zero, or pass two numbers separated by a comma. Watch how the returned rows shift. A hidden catalog row carries this challenge's audit token: only real LIMIT-clause manipulation pulls it into view, and a plain numeric limit earns nothing."],
    tools: "BZ, B",
    how: 'In Burp Repeater, explore the grammar the LIMIT clause accepts beyond a plain page size, and use it to pull a catalog row into view that the default page never shows.',
    link: '/sqli/paged',
    start: "Browse to /sqli/paged through Burp's proxy, send the page-size request to Repeater, and start tweaking the limit parameter.",
  },
  router,
};
