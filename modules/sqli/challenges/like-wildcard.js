'use strict';
// LIKE Wildcard Exfiltration: the match count is the only signal, but a quote
// breakout turns the search into a full boolean oracle against any table.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { challengeTarget, shopShell, withChallengeTarget } = require('../shared');

const router = express.Router();

// Reworked (M7): the old lab awarded the flag for a single "%" that dumped the
// catalog. Now the page only reports how many products match, and this
// challenge's own secret is the target. LIKE patterns are never escaped and
// the query is plain string interpolation, so a quote breakout turns the
// search into a boolean oracle against any data: extract the secret
// character by character.
// Reworked (P0-8): the submit box is bound to this challenge's derived
// target (readable in injected SQL as sqli_target()), so the admin secret
// extracted once via UNION no longer replays here.
router.get('/wildcard', (req, res) => {
  const q = req.query.q !== undefined ? String(req.query.q) : '';
  const db = getDb();
  // VULN: q interpolated into LIKE; % and _ are never escaped, and a quote
  // breakout turns the pattern into a full boolean expression.
  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`;
  let rows = [];
  let error = null;
  try {
    rows = withChallengeTarget('like-wildcard', () => db.prepare(sql).all());
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
        inside a string-interpolated query. Build a boolean oracle with <code>LIKE</code> and a subquery,
        extract this challenge's secret (exposed to your SQL as <code>sqli_target()</code>) character
        by character, then submit it below. A secret extracted anywhere else will not match the submit box.</p></div>
        <form class="clay-card" method="POST" action="/sqli/wildcard/submit">
          <div class="card-top"><b>Submit challenge secret</b></div>
          <div class="clay-field">
            <label for="secret">Challenge secret</label>
            <input class="clay-input" id="secret" name="secret" placeholder="PENTRIX{...}" />
          </div>
          <button class="clay-btn clay-btn-primary" type="submit">Submit secret</button>
        </form>`;
  }
  res.send(page('Stock Checker (LIKE Injection)', shopShell('Warehouse', body + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

router.post('/wildcard/submit', (req, res) => {
  const guess = ((req.body && req.body.secret) || '').toString().trim();
  // P0-8: bound to this challenge's own derived target; a secret extracted
  // via another technique (e.g. UNION) does not match.
  const target = challengeTarget('like-wildcard');
  if (target && guess === target) {
    const flag = award(req, 'sqli', 'like-wildcard');
    return res.send(page('Stock Checker', shopShell('Warehouse', `
      <h1>Secret accepted</h1>
      <p>The submitted secret matches this challenge's secret.</p>
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
    hint: 'The page only tells you how many products match. Proxy the search through Burp: your search term is dropped into a LIKE pattern with no escaping, inside a string-interpolated query. A quote breakout plus a subquery turns the match count into a true/false oracle for each character of this challenge\'s secret (your SQL can read it as sqli_target()).',
    hints: ["The stock checker only tells you how many products match. In Burp Proxy, watch the search request: your search goes into a LIKE pattern. What characters are special in LIKE?", "Send the request to Burp Repeater. The % and _ wildcards are never escaped, and the query is string-interpolated. A quote breakout lets you add a subquery: make every product match only when your guess about the secret is right. Aim the subquery at sqli_target(), this challenge's own secret.", "In Repeater, combine a quote breakout with a subquery in the LIKE pattern so the match count flips between all-products and none as your character guess changes. Hand the oracle to Intruder with a character payload set to extract the secret, then submit it in the form. A secret extracted anywhere else will not match."],
    tools: "BZ, B, C",
    how: 'In Burp, build a boolean oracle with LIKE and a subquery in Repeater (e.g. make every product match only when this challenge\'s secret, readable as sqli_target(), starts with your guess), drive the character-by-character extraction with Intruder, then submit the secret in the form.',
    link: '/sqli/wildcard',
    start: "Browse to /sqli/wildcard through Burp's proxy, run one normal search, send the search request to Repeater, and start probing the q parameter.",
  },
  router,
};
