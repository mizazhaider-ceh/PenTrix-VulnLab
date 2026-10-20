'use strict';
// INSERT Injection: the feedback form interpolates input into an INSERT
// statement. Stacked queries are blocked, but VALUES() accepts a subquery.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, emptyState, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { adminSecret, shopShell } = require('../shared');

const router = express.Router();

router.get('/feedback', (req, res) => {
  const db = getDb();
  const rows = db.prepare('SELECT name, message, created_at FROM sqli_feedback ORDER BY id DESC').all();
  const wall = rows.length
    ? `<div class="tbl-scroll"><table class="tbl">
        <caption class="sr-only">Feedback wall</caption>
        <thead><tr><th scope="col">Name</th><th scope="col">Message</th><th scope="col">Posted</th></tr></thead>
        <tbody>${rows.map((r) => `<tr><td>${esc(r.name)}</td><td>${esc(r.message)}</td><td>${esc(r.created_at)}</td></tr>`).join('')}</tbody>
      </table></div>`
    : emptyState('No feedback yet', '<p>Be the first to leave a note for the team.</p>');
  let flagHtml = '';
  const secret = adminSecret();
  // The injected subquery genuinely wrote the admin secret into the table.
  if (secret && rows.some((r) => r.message.includes(secret))) {
    flagHtml = flagBox(award(req, 'sqli', 'insert-inject'));
    flagHtml += fixPanel('sqli', 'insert-inject');
    flagHtml += fixCta('sqli', 'insert-inject');
  }
  res.send(page('Feedback (INSERT Injection)', shopShell('Feedback', `
    <h1>Feedback</h1>
    ${brief('Feedback', 'Leave feedback. Your input is interpolated straight into an <code>INSERT</code> statement. No stacked queries allowed, but who needs them?')}
    <form class="clay-card" method="POST" action="/sqli/feedback">
      <div class="card-top"><b>Leave feedback</b></div>
      <div class="clay-field">
        <label for="name">Name</label>
        <input class="clay-input" id="name" name="name" required />
      </div>
      <div class="clay-field">
        <label for="message">Message</label>
        <textarea class="clay-input" id="message" name="message" rows="3" required></textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Send feedback</button>
    </form>
    ${flagHtml}
    <h2>Feedback wall</h2>
    ${wall}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>
  `)));
});

router.post('/feedback', (req, res) => {
  const name = String(req.body.name || '').slice(0, 80);
  const msg = String(req.body.message || '').slice(0, 500);
  if (!name.trim() || !msg.trim()) {
    return res.status(400).send(page('Feedback', shopShell('Feedback', `
      <h1>Feedback</h1>
      <div class="warn"><p>Name and message are required.</p></div>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/feedback">Back</a></p>
    `)));
  }
  const db = getDb();
  // VULN: interpolated into INSERT; VALUES() accepts a subquery as a value.
  // prepare() is used instead of exec() so that only this one statement can
  // run: stacked queries stay blocked (prepare throws on multi-statement
  // input), while the intended VALUES-subquery injection keeps working.
  const sql = `INSERT INTO sqli_feedback(name, message) VALUES ('${name}', '${msg}')`;
  try {
    db.prepare(sql).run();
  } catch (e) {
    return res.status(400).send(page('Feedback', shopShell('Feedback', `
      <h1>Feedback</h1>
      <div class="warn"><p><strong>Database error:</strong> ${esc(e.message)}</p></div>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/feedback">Back</a></p>
    `)));
  }
  res.redirect('/sqli/feedback');
});

module.exports = {
  vuln: {
    id: 'insert-inject',
    name: 'INSERT Injection',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'The feedback form builds its INSERT with string interpolation. You cannot stack queries here, but VALUES() happily accepts a subquery.',
    hints: ["The feedback form builds an INSERT query by gluing your input into the VALUES list. You cannot stack queries, but VALUES accepts more than plain text. First, send a normal feedback POST through Burp's Proxy and forward it to Repeater.", "In Repeater, tweak the name field: break out of the quoted value, place a subquery where the next value belongs, then close the statement so the INSERT still parses. A 400 with a database error is a useful oracle for getting the syntax right.", "Make the subquery fetch the admin secret, then reload the feedback wall: your own row should now carry the secret."],
    tools: "BZ, B",
    how: 'In Repeater, break out of the quoted value in the name field, slip a subquery into the VALUES list that writes the admin secret into your feedback row, then read the secret back from the feedback wall.',
    link: '/sqli/feedback',
    start: "Open /sqli/feedback in the Burp browser with the Proxy running, submit the feedback form once, then send the captured POST to Repeater to start shaping the VALUES list.",
  },
  router,
};
