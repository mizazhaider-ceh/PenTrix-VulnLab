'use strict';
// GROUP BY Injection: the grouping expression is attacker-controlled and
// echoed back as the group label, so a subquery leaks data through it.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { adminSecret, shopShell } = require('../shared');

const router = express.Router();

router.get('/stats', (req, res) => {
  const by = req.query.by !== undefined ? String(req.query.by) : 'region';
  const db = getDb();
  // VULN: GROUP BY expression interpolated; the grouping key is echoed back.
  const sql = `SELECT ${by} AS grp, COUNT(*) AS n, SUM(amount) AS total FROM sqli_sales GROUP BY ${by}`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.grp))}</td><td>${esc(String(r.n))}</td><td>${esc(String(r.total))}</td></tr>`
  ).join('\n');
  let body = `
    <h1>Sales stats</h1>
    ${brief('Sales Stats', 'Sales grouped by a dimension you choose. The <code>by</code> parameter becomes the <code>GROUP BY</code> expression, and the grouping key is printed in the first column.')}
    <form class="clay-card" method="GET" action="/sqli/stats">
      <div class="card-top"><b>Group sales</b></div>
      <div class="clay-field">
        <label for="by">Group by</label>
        <input class="clay-input" id="by" name="by" value="${esc(by)}" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Group</button>
    </form>
    <div class="note"><p>Try <code>region</code>, <code>product</code>, then something the query was never meant to group by.</p></div>
  `;
  body += error
    ? `<div class="warn"><p><strong>Database error:</strong> ${esc(error)}</p></div>`
    : `<div class="tbl-scroll"><table class="tbl">
        <caption class="sr-only">Sales grouped by ${esc(by)}</caption>
        <thead><tr><th scope="col">Group</th><th scope="col">Rows</th><th scope="col">Total</th></tr></thead>
        <tbody>${table}</tbody>
      </table></div>`;
  let flagHtml = '';
  const secret = adminSecret();
  // The injected GROUP BY expression genuinely returned the admin secret.
  if (!error && secret && rows.some((r) => String(r.grp).includes(secret))) {
    flagHtml = flagBox(award(req, 'sqli', 'groupby-having'));
    flagHtml += fixPanel('sqli', 'groupby-having');
    flagHtml += fixCta('sqli', 'groupby-having');
  }
  res.send(page('Sales Stats (GROUP BY Injection)', shopShell('Insights', body + flagHtml + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

module.exports = {
  vuln: {
    id: 'groupby-having',
    name: 'GROUP BY Injection',
    difficulty: 'Medium',
    hint: 'The stats page groups sales by an expression you control and prints the grouping key back. GROUP BY accepts any expression, including a subquery.',
    hints: ["The stats page groups sales and prints the grouping key. You control the GROUP BY expression. What can an expression be?", "GROUP BY accepts any SQL expression, including a subquery. If the grouping key is (SELECT secret FROM users...), the secret comes back as the group label.", "Set the group parameter to: (SELECT secret FROM users WHERE username='admin') and read the secret from the grouped output."],
    tools: "B, C",
    how: 'Point the GROUP BY expression at the users table so the admin secret comes back as the grouping key.',
    link: '/sqli/stats',
    start: "curl -G 'http://localhost:3000/sqli/stats' --data-urlencode 'by=region'",
  },
  router,
};
