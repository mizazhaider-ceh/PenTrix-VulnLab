'use strict';
// Boolean Blind Injection: the product page only answers exists/not-found, but
// that single bit is enough to build a true/false oracle against any table.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { challengeTarget, shopShell, withChallengeTarget } = require('../shared');

const router = express.Router();

function blindPage(resultHtml) {
  return page('Product Lookup (Blind)', shopShell('Stock lookup', `
    <h1>Stock lookup</h1>
    ${brief('Boolean Blind', 'Look up a product by id. The page only tells you whether the product exists. No data is ever printed back. The submit box wants this challenge\'s own secret, which your injected SQL can read as sqli_target(): a secret extracted anywhere else will not match.')}
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
      <div class="card-top"><b>Submit the extracted challenge secret</b></div>
      <div class="clay-field">
        <label for="secret">Challenge secret</label>
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
      // The query runs bound to this challenge, so injected SQL can read this
      // challenge's own derived target as sqli_target() (P0-8 FLAG BAR).
      const rows = withChallengeTarget('blind', () => db.prepare(sql).all());
      result = rows.length > 0 ? '<div class="note"><p><strong>Product exists.</strong></p></div>' : '<p>Not found.</p>';
    } catch (e) {
      result = '<p>Not found.</p>';
    }
  }
  res.send(blindPage(result));
});

router.post('/blind-submit', (req, res) => {
  const submitted = String(req.body.secret || '').trim();
  // P0-8: the submit box is bound to this challenge's own derived target.
  // The admin secret (or any secret extracted via another technique, e.g. a
  // UNION dump) does not match and earns nothing.
  const target = challengeTarget('blind');
  if (target && submitted !== '' && submitted === target) {
    const flag = award(req, 'sqli', 'blind');
    return res.send(page('Blind Submission', shopShell('Submission accepted', `
      <h1>Submission accepted</h1>
      <p><strong>Correct.</strong> You extracted this challenge's secret via boolean blind injection.</p>
      ${flagBox(flag)}
      ${fixPanel('sqli', 'blind')}
      ${fixCta('sqli', 'blind')}
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
    hint: 'The product page only tells you whether a row exists. In Repeater, compare the two answers, then extract this challenge\'s secret (your injected SQL can read it as sqli_target()) one character at a time with true/false conditions and submit it.',
    hints: ["The product page only tells you if a row exists or not, and Repeater shows those two answers side by side. That one-bit difference is your oracle: what can one bit leak?", "In Repeater, build a boolean oracle: an injected condition that is true only when your guess about the secret is right. This challenge's secret is exposed to your SQL as sqli_target(), so a condition like 0' OR substr(sqli_target(),1,1)='P' --  is answerable. The page flipping between its two answers tells you if you guessed right.", "Extract this challenge's secret one character at a time in Repeater (or hand the oracle to Intruder with a character payload set and read the results with Grep-Match on the true-answer text, Tool Setup Guide section 8), then submit the full secret in the form. A secret extracted anywhere else will not match this submit box."],
    tools: "BZ, B, C",
    est: 'about 30 minutes',
    how: "In Burp, compare the page's yes/no answers in Repeater while probing boolean conditions against sqli_target(), extract this challenge's secret one character at a time, then submit it in the form on the product page.",
    link: '/sqli/product',
    start: "Open the Stock lookup page with Burp Proxy intercepting, send the lookup request to Repeater, and compare the true and false responses.",
  },
  router,
};
