'use strict';
// ORDER BY Injection: the sort parameter goes straight into ORDER BY, which
// accepts full expressions, including a CASE WHEN boolean oracle.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { shopShell } = require('../shared');

const router = express.Router();

// Strip string literals and SQL comments before looking for the oracle
// keywords. Without this, the flag could be earned by smuggling the words
// "case when" and "users" inside a string literal (e.g.
// sort=(SELECT 'case when users')) or a comment (sort=name /* case when
// users */), with no real boolean oracle ever executing against the users
// table. After stripping, any remaining keywords are live SQL tokens.
function stripSqlNoise(s) {
  return s
    .replace(/'(?:[^']|'')*'/g, ' ')
    .replace(/--[^\n]*/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ');
}

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
  // Keywords are matched against the noise-stripped input so that string
  // literals and comments cannot smuggle them in.
  const probe = stripSqlNoise(sort);
  if (!error && /case\s+when/i.test(probe) && /\busers\b/i.test(probe)) {
    flagHtml = flagBox(award(req, 'sqli', 'order-by'));
    flagHtml += fixPanel('sqli', 'order-by');
    flagHtml += fixCta('sqli', 'order-by');
  }
  res.send(page('Sortable Catalog (ORDER BY Injection)', shopShell('Catalog', body + flagHtml + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

module.exports = {
  vuln: {
    id: 'order-by',
    name: 'ORDER BY Injection',
    difficulty: 'Medium',
    hint: 'The sort parameter goes straight into ORDER BY. ORDER BY accepts full expressions, including CASE WHEN with a subquery against the users table. Watch the row order flip as your condition changes.',
    hints: ["Open /sqli/sort through Burp Proxy, submit the form, and send the request to Repeater. The sort parameter changes the product order. ORDER BY does not just take column names. What else can go there?", "In Repeater, try a sort expression whose result depends on a true or false condition. ORDER BY accepts full expressions, including CASE WHEN with a subquery: pick one column when the condition is true, another when false. The row order becomes your oracle.", "Use Repeater to test one guess, then hand the guesses to Burp Intruder and watch the row order flip as you sweep candidates. Each flip answers yes or no, so the table reads the secret out one position at a time."],
    tools: "BZ, B, C",
    how: 'In Burp Repeater, inject a CASE WHEN oracle into the sort parameter against the users table and read true or false from the product row order. Burp Intruder can sweep the guesses.',
    link: '/sqli/sort',
    start: "Burp Proxy on: open /sqli/sort in the browser, submit the sort form once, then send the GET request to Repeater and probe sort with price DESC.",
  },
  router,
};
