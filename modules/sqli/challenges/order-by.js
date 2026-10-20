'use strict';
// ORDER BY Injection: the sort parameter goes straight into ORDER BY, which
// accepts full expressions, including a CASE WHEN boolean oracle.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { challengeTarget, shopShell, withChallengeTarget } = require('../shared');

const router = express.Router();

router.get('/sort', (req, res) => {
  const sort = req.query.sort !== undefined ? String(req.query.sort) : 'name';
  const db = getDb();
  // VULN: sort expression interpolated directly into the ORDER BY clause.
  const sql = `SELECT id, name, price FROM products ORDER BY ${sort}`;
  let rows = [];
  let error = null;
  try {
    rows = withChallengeTarget('order-by', () => db.prepare(sql).all());
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
      </table></div>
      <form class="clay-card" method="POST" action="/sqli/sort/submit">
        <div class="card-top"><b>Submit the extracted challenge secret</b></div>
        <div class="clay-field">
          <label for="secret">Challenge secret</label>
          <input class="clay-input" id="secret" name="secret" placeholder="PENTRIX{...}" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Submit secret</button>
      </form>`;
  res.send(page('Sortable Catalog (ORDER BY Injection)', shopShell('Catalog', body + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

// P0-8: the flag is bound to this challenge's own derived target. The row
// order is the oracle: extract the secret (exposed to injected SQL as
// sqli_target()) one position at a time with CASE WHEN, then submit it.
// A sort expression that merely mentions oracle keywords earns nothing.
router.post('/sort/submit', (req, res) => {
  const submitted = String(req.body.secret || '').trim();
  const target = challengeTarget('order-by');
  if (target && submitted !== '' && submitted === target) {
    const flag = award(req, 'sqli', 'order-by');
    return res.send(page('Sortable Catalog', shopShell('Catalog', `
      <h1>Secret accepted</h1>
      <p><strong>Correct.</strong> You extracted this challenge's secret through the ORDER BY oracle.</p>
      ${flagBox(flag)}
      ${fixPanel('sqli', 'order-by')}
      ${fixCta('sqli', 'order-by')}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/sort">Back</a></p>
    `)));
  }
  res.send(page('Sortable Catalog', shopShell('Catalog', `
    <h1>Secret rejected</h1>
    <div class="warn"><p><strong>Wrong secret.</strong> Keep reading the row order: each flip answers one yes/no question about the secret.</p></div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/sort">Back to the catalog</a></p>
  `)));
});

module.exports = {
  vuln: {
    id: 'order-by',
    name: 'ORDER BY Injection',
    difficulty: 'Medium',
    hint: 'The sort parameter goes straight into ORDER BY. ORDER BY accepts full expressions, including CASE WHEN with a subquery. This challenge\'s secret is exposed to your SQL as sqli_target(): watch the row order flip as your condition changes, extract the secret, then submit it.',
    hints: ["Open /sqli/sort through Burp Proxy, submit the form, and send the request to Repeater. The sort parameter changes the product order. ORDER BY does not just take column names. What else can go there?", "In Repeater, try a sort expression whose result depends on a true or false condition. ORDER BY accepts full expressions, including CASE WHEN with a subquery: pick one column when the condition is true, another when false. The row order becomes your oracle, and sqli_target() is the value to interrogate.", "Use Repeater to test one guess, then hand the guesses to Burp Intruder and watch the row order flip as you sweep candidates. Each flip answers yes or no, so the table reads this challenge's secret out one position at a time. Submit the full secret in the form below the table."],
    tools: "BZ, B, C",
    how: 'In Burp Repeater, inject a CASE WHEN oracle into the sort parameter against sqli_target() and read true or false from the product row order. Burp Intruder can sweep the guesses; submit the extracted secret in the form.',
    link: '/sqli/sort',
    start: "Burp Proxy on: open /sqli/sort in the browser, submit the sort form once, then send the GET request to Repeater and probe sort with price DESC.",
  },
  router,
};
