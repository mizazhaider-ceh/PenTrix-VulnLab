'use strict';
// LIKE Wildcard Exfiltration: the match count is the only signal, but a quote
// breakout turns the search into a full boolean oracle against any table.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { adminSecret, shopShell } = require('../shared');

const router = express.Router();

// Reworked (M7): the old lab awarded the flag for a single "%" that dumped the
// catalog. Now the page only reports how many products match, and the admin
// secret is the target. LIKE patterns are never escaped and the query is plain
// string interpolation, so a quote breakout turns the search into a boolean
// oracle against any table: extract the secret character by character.
router.get('/wildcard', (req, res) => {
  const q = req.query.q !== undefined ? String(req.query.q) : '';
  const db = getDb();
  // VULN: q interpolated into LIKE; % and _ are never escaped, and a quote
  // breakout turns the pattern into a full boolean expression.
  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const total = db.prepare('SELECT COUNT(*) AS c FROM products').get().c;
  let body = `
    <h1>Stock checker</h1>
    ${brief('Stock Checker', 'Check how many products in the catalog match a name search. The warehouse team uses the match count to plan shelf space.')}
    <form class="clay-card" method="GET" action="/sqli/wildcard">
      <div class="card-top"><b>Check stock</b></div>
      <div class="clay-field">
        <label for="q">Search term</label>
        <input class="clay-input" id="q" name="q" value="${esc(q)}" placeholder="search products" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Check stock</button>
    </form>
  `;
  if (req.query.q !== undefined) {
    body += error
      ? `<div class="warn"><p><strong>Database error:</strong> ${esc(error)}</p></div>`
      : `<div class="note"><p><b>${rows.length}</b> of ${total} products match. The count is the only
        signal you get. The search term is dropped into a <code>LIKE</code> pattern with no escaping,
        inside a string-interpolated query. The admin secret is not in this catalog, but the query can
        reach the <code>users</code> table. Build a boolean oracle with <code>LIKE</code> and a subquery,
        extract the secret character by character, then submit it below.</p></div>
        <form class="clay-card" method="POST" action="/sqli/wildcard/submit">
          <div class="card-top"><b>Submit admin secret</b></div>
          <div class="clay-field">
            <label for="secret">Admin secret</label>
            <input class="clay-input" id="secret" name="secret" placeholder="PENTRIX{...}" />
          </div>
          <button class="clay-btn clay-btn-primary" type="submit">Submit secret</button>
        </form>`;
  }
  res.send(page('Stock Checker (LIKE Injection)', shopShell('Warehouse', body + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

router.post('/wildcard/submit', (req, res) => {
  const guess = ((req.body && req.body.secret) || '').toString().trim();
  const target = adminSecret();
  if (target && guess === target) {
    const flag = award(req, 'sqli', 'like-wildcard');
    return res.send(page('Stock Checker', shopShell('Warehouse', `
      <h1>Secret accepted</h1>
      <p>The submitted secret matches the admin secret.</p>
      ${flagBox(flag)}
      ${fixPanel('sqli', 'like-wildcard')}
      ${fixCta('sqli', 'like-wildcard')}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>
    `)));
  }
  res.send(page('Stock Checker', shopShell('Warehouse', `
    <h1>Secret rejected</h1>
    <div class="warn"><p><strong>Wrong secret.</strong> Keep extracting with the LIKE oracle.</p></div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/wildcard">Back to the checker</a></p>
  `)));
});

module.exports = {
  vuln: {
    id: 'like-wildcard',
    name: 'LIKE Wildcard Exfiltration',
    difficulty: 'Medium',
    hint: 'The page only tells you how many products match. Your search term is dropped into a LIKE pattern with no escaping, inside a string-interpolated query. A quote breakout plus a subquery against the users table turns the match count into a true/false oracle for each character of the admin secret.',
    hints: ["The stock checker only tells you how many products match. Your search goes into a LIKE pattern. What characters are special in LIKE?", "The % and _ wildcards are never escaped, and the query is string-interpolated. A quote breakout lets you add a subquery: make every product match only when your guess about the secret is right.", "Inject: ' OR (SELECT secret FROM users WHERE username='admin') LIKE 'P%' --  (URL-encoded). If all products match, the secret starts with P. Extract it character by character, then submit."],
    tools: "B, C",
    how: 'Build a boolean oracle with LIKE and a subquery (e.g. make every product match only when the secret starts with your guess), extract the admin secret character by character, then submit it.',
    link: '/sqli/wildcard',
    start: "curl -G 'http://localhost:3000/sqli/wildcard' --data-urlencode 'q=hoodie'",
  },
  router,
};
