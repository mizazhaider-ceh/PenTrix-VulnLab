'use strict';
// UNION Filter Bypass: a naive case-sensitive blacklist strips the lowercase
// word "union" but knows nothing about mixed case or SQL comments.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { adminSecret, shopShell } = require('../shared');

const router = express.Router();

router.get('/shop', (req, res) => {
  const q = req.query.q !== undefined ? String(req.query.q) : '';
  // VULN: naive case-sensitive blacklist. Only the exact lowercase word is stripped.
  const filtered = q.split('union').join('');
  const db = getDb();
  // VULN: search term interpolated into the query.
  const sql = `SELECT id, name, price, description FROM products WHERE name LIKE '%${filtered}%'`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.id))}</td><td>${esc(String(r.name))}</td><td>${esc(String(r.price))}</td><td>${esc(String(r.description))}</td></tr>`
  ).join('\n');
  let body = `
    <h1>Filtered shop</h1>
    ${brief('Filtered Shop', 'Search the shop. The word <code>union</code> (lowercase) is stripped from your search for "security". Good luck with that.')}
    <form class="clay-card" method="GET" action="/sqli/shop">
      <div class="card-top"><b>Search the shop</b></div>
      <div class="clay-field">
        <label for="q">Search term</label>
        <input class="clay-input" id="q" name="q" value="${esc(q)}" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Search</button>
    </form>
  `;
  if (req.query.q !== undefined) {
    body += error
      ? `<div class="warn"><p><strong>Database error:</strong> ${esc(error)}</p></div>`
      : `<div class="tbl-scroll"><table class="tbl">
          <caption class="sr-only">Matching products</caption>
          <thead><tr><th scope="col">ID</th><th scope="col">Name</th><th scope="col">Price</th><th scope="col">Description</th></tr></thead>
          <tbody>${table}</tbody>
        </table></div>`;
  }
  let html = page('Filtered Shop (UNION Filter Bypass)', shopShell('Shop', body));
  const secret = adminSecret();
  // The bypass genuinely worked when the filter failed to stop the secret
  // from being UNIONed into the output.
  if (!error && secret && html.includes(secret)) {
    const flag = award(req, 'sqli', 'union-filter-bypass');
    html = page('Filtered Shop (UNION Filter Bypass)', shopShell('Shop', body + flagBox(flag) + fixPanel('sqli', 'union-filter-bypass') + fixCta('sqli', 'union-filter-bypass')));
  }
  res.send(html);
});

module.exports = {
  vuln: {
    id: 'union-filter-bypass',
    name: 'UNION Filter Bypass',
    difficulty: 'Medium',
    hint: 'This shop strips the lowercase word "union" from your search. The filter is case-sensitive and knows nothing about SQL comments or mixed case.',
    hints: ["The shop strips the word 'union' from your search. But filters are code, and code has assumptions. What assumptions is this one making?", "The filter is case-sensitive and only strips the exact lowercase word. Try uppercase (UNION), mixed case (UnIoN), or SQL comments (/**/ ) to smuggle the keyword past it.", "Inject with UN/**/ION SELECT or ' UnIoN SELECT id, username, password, secret FROM users --  to bypass the naive blacklist."],
    tools: "B, C",
    how: 'Bypass the naive blacklist (uppercase, mixed case, or /**/ comments) and UNION out the admin secret.',
    link: '/sqli/shop',
    start: "curl -G 'http://localhost:3000/sqli/shop' --data-urlencode 'q=hoodie'",
  },
  router,
};
