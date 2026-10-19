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
    hint: 'The product search interpolates your query into a LIKE clause returning 4 columns. In Repeater, balance the quotes, then UNION in a second SELECT against the users table.',
    hints: ["In Repeater, run a normal search and watch the 4-column products table render. A UNION SELECT needs the same number of columns. How many columns does your injected SELECT return?", "Use UNION SELECT to append a second query, and aim it at the users table. Match all four columns, then check the response in Repeater to see the extra rows appear.", "Close the quote in the q parameter, UNION in a second SELECT that matches the four columns, and read the admin secret from the extra rows the page renders."],
    tools: "BZ, B, C",
    how: "In Burp Repeater, inject UNION SELECT into the q parameter of the product search to dump the users table (id, username, password, secret) through the rendered results and recover the admin secret.",
    link: '/sqli/products',
    start: "In Burp Proxy, intercept the request to /sqli/products, then send it to Repeater.",
  },
  router,
};
