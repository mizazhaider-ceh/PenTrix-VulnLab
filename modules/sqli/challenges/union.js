'use strict';
// UNION-based Injection: the product search interpolates the search term into
// a 4-column LIKE query, so a UNION SELECT can append rows from any table.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { adminSecret, shopShell } = require('../shared');

const router = express.Router();

router.get('/products', (req, res) => {
  const q = req.query.q !== undefined ? String(req.query.q) : '';
  const db = getDb();
  // VULN: search term interpolated directly into the LIKE query.
  const sql = `SELECT id, name, price, description FROM products WHERE name LIKE '%${q}%'`;
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
    <h1>Product search</h1>
    ${brief('Product Search', 'Search the product catalog. Your search term is interpolated into the SQL query.')}
    <form class="clay-card" method="GET" action="/sqli/products">
      <div class="card-top"><b>Search products</b></div>
      <div class="clay-field">
        <label for="q">Search term</label>
        <input class="clay-input" id="q" name="q" value="${esc(q)}" placeholder="search products" />
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
  let html = page('Product Search', shopShell('Catalog', body));
  const target = adminSecret();
  if (target && html.includes(target)) {
    const flag = award(req, 'sqli', 'union');
    html = page('Product Search', shopShell('Catalog', body + flagBox(flag) + fixPanel('sqli', 'union') + fixCta('sqli', 'union')));
  }
  res.send(html);
});

module.exports = {
  vuln: {
    id: 'union',
    name: 'UNION-based Injection',
    difficulty: 'Medium',
    hint: 'The product search interpolates your query into a LIKE clause returning 4 columns. Balance the quotes, then UNION in a second SELECT against the users table.',
    hints: ["The search shows products in a table with 4 columns. A UNION SELECT needs the same number of columns. How many does your injected query return?", "Use UNION SELECT to append a second query. Match the 4 columns, then point the SELECT at the users table to pull usernames, passwords, and secrets.", "Close the quote, UNION in a second SELECT that matches the four columns, and point it at the users table. Adjust the shape until the page renders the extra rows, then read the admin secret from them."],
    tools: "B, C",
    how: "Use UNION SELECT to dump the users table (id, username, password, secret) through the product search and recover the admin secret.",
    link: '/sqli/products',
    start: "curl 'http://localhost:3000/sqli/products?q=hoodie'",
  },
  router,
};
