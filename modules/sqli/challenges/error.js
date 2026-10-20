'use strict';
// Error-based Injection: the detail page interpolates the id straight into
// the query and leaks raw database errors, which is an oracle on its own.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { shopShell } = require('../shared');

const router = express.Router();

router.get('/detail', (req, res) => {
  const id = req.query.id !== undefined ? String(req.query.id) : '';
  let body = `
    <h1>Product detail</h1>
    ${brief('Product Detail', 'View a product by id. Database errors are shown raw on this page.')}
    <form class="clay-card" method="GET" action="/sqli/detail">
      <div class="card-top"><b>Look up a product</b></div>
      <div class="clay-field">
        <label for="id">Product id</label>
        <input class="clay-input" id="id" name="id" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">View</button>
    </form>
  `;
  if (id !== '') {
    const db = getDb();
    // VULN: id interpolated raw into the query; raw sqlite errors leak to the page.
    const sql = `SELECT * FROM products WHERE id=${id}`;
    try {
      const row = db.prepare(sql).get();
      body += row
        ? `<div class="card"><div class="card-top"><b>${esc(row.name)}</b></div><p>Price: ${esc(String(row.price))}</p><p>${esc(row.description)}</p></div>`
        : '<p>Not found.</p>';
    } catch (e) {
      body += `<div class="warn"><p><strong>SQL error:</strong> ${esc(e.message)}</p></div>`; // VULN: raw error reflected
      // SQLite reports a stray quote as "unrecognized token" and other bad
      // input as "syntax error" (parse-time oracle). Bad function calls,
      // malformed JSON, or missing columns fail at runtime instead
      // (runtime oracle). Both prove error-based injection works.
      if (/syntax error|unrecognized token|malformed JSON|wrong number of arguments|no such column|datatype mismatch/i.test(e.message)) {
        const flag = award(req, 'sqli', 'error');
        return res.send(page('Product Detail', shopShell('Catalog', body + flagBox(flag) + fixPanel('sqli', 'error') + fixCta('sqli', 'error'))));
      }
    }
  }
  res.send(page('Product Detail', shopShell('Catalog', body)));
});

module.exports = {
  vuln: {
    id: 'error',
    name: 'Error-based Injection',
    difficulty: 'Easy',
    hint: 'The detail page interpolates your id straight into the query and leaks raw database errors. Send the request to Burp Repeater and tweak the id parameter: a stray quote breaks the syntax, a bad function call or malformed JSON breaks it at runtime. Both are error oracles.',
    hints: ["Proxy the product detail page through Burp and send the request to Repeater. The detail page reflects raw database errors back in the response. Errors are information; read them.", "In Repeater, change the id parameter so the query breaks. One approach breaks the SQL syntax, another breaks a function call or expression at runtime. The error text that comes back proves your input reaches the query.", "Try both error paths in Repeater: break the syntax first, then break a function call or malformed JSON at runtime. Send each broken request and watch the error text in the response."],
    tools: "BZ, B",
    how: "In Burp Repeater, request the product detail page and tweak the id parameter until the response reflects a SQLite error. A stray quote causes a syntax error; a bad function call or malformed JSON causes a runtime error. Either error path proves error-based injection and earns the flag.",
    link: '/sqli/detail',
    start: "Browse to /sqli/detail through Burp's proxy, send the detail request to Repeater, and start tweaking the id parameter.",
  },
  router,
};
