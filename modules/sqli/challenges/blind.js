'use strict';
// Boolean Blind Injection: the product page only answers exists/not-found, but
// that single bit is enough to build a true/false oracle against any table.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, brief, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { adminSecret, shopShell } = require('../shared');

const router = express.Router();

function blindPage(resultHtml) {
  return page('Product Lookup (Blind)', shopShell('Stock lookup', `
    <h1>Stock lookup</h1>
    ${brief('Boolean Blind', 'Look up a product by id. The page only tells you whether the product exists. No data is ever printed back.')}
    <form class="clay-card" method="GET" action="/sqli/product">
      <div class="card-top"><b>Check a product id</b></div>
      <div class="clay-field">
        <label for="id">Product id</label>
        <input class="clay-input" id="id" name="id" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Check</button>
    </form>
    ${resultHtml}
    <form class="clay-card" method="POST" action="/sqli/blind-submit">
      <div class="card-top"><b>Submit extracted admin secret</b></div>
      <div class="clay-field">
        <label for="secret">Admin secret</label>
        <input class="clay-input" id="secret" name="secret" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Submit</button>
    </form>
  `));
}

router.get('/product', (req, res) => {
  const id = req.query.id !== undefined ? String(req.query.id) : '';
  let result = '';
  if (id !== '') {
    const db = getDb();
    // VULN: id interpolated directly into the query; only a true/false oracle is exposed.
    const sql = `SELECT * FROM products WHERE id='${id}'`;
    try {
      const rows = db.prepare(sql).all();
      result = rows.length > 0 ? '<div class="note"><p><strong>Product exists.</strong></p></div>' : '<p>Not found.</p>';
    } catch (e) {
      result = '<p>Not found.</p>';
    }
  }
  res.send(blindPage(result));
});

router.post('/blind-submit', (req, res) => {
  const submitted = String(req.body.secret || '').trim();
  const target = adminSecret();
  if (target && submitted !== '' && submitted === target) {
    const flag = award(req, 'sqli', 'blind');
    return res.send(page('Blind Submission', shopShell('Submission accepted', `
      <h1>Submission accepted</h1>
      <p><strong>Correct.</strong> You extracted the admin secret via boolean blind injection.</p>
      ${flagBox(flag)}
      ${fixPanel('sqli', 'blind')}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/product">Back</a></p>
    `)));
  }
  res.send(page('Blind Submission', shopShell('Submission rejected', `
    <h1>Submission rejected</h1>
    <div class="warn"><p><strong>Incorrect secret.</strong> Keep probing the oracle with boolean conditions.</p></div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/product">Back</a></p>
  `)));
});

module.exports = {
  vuln: {
    id: 'blind',
    name: 'Boolean Blind Injection',
    difficulty: 'Medium',
    hint: 'The product page only tells you whether a row exists. Extract the admin secret one character at a time with true/false conditions, then submit it.',
    hints: ["The product page only tells you if a row exists or not. That's one bit of information. How can one bit leak a whole secret?", "Build a boolean oracle: inject a condition that is true only when your guess about the secret is right (e.g. the first character is 'P'). The page's yes/no answer tells you if you guessed right.", "Extract the admin secret one character at a time with conditions like ' AND (SELECT substr(secret,1,1) FROM users WHERE username='admin')='P' -- , then submit the full secret."],
    tools: "B, C",
    how: "Extract the admin secret via boolean conditions, then submit it in the form on the product page.",
    link: '/sqli/product',
    start: "curl 'http://localhost:3000/sqli/product?id=1'",
  },
  router,
};
