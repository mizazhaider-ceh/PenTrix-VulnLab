'use strict';
// Verb Tampering: /http/feedback is documented POST-only, but the GET route
// runs the same submit handler, so the state-changing action fires over GET
// (bookmarkable, loggable, CSRF-able). The flag is awarded on a successful
// GET submission.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');
const {
  page, esc, brief, flagBox, fixPanel, hintLadder, toolsPill,
} = require('../../../lib/page');

const router = express.Router();

// NOTE: created here with IF NOT EXISTS so this challenge file is
// self-contained; router.js used to create it at module load time.
getDb().exec(`CREATE TABLE IF NOT EXISTS http_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  msg TEXT, ts TEXT
)`);

const vuln = {
  id: 'verb-tamper',
  name: 'Verb Tampering',
  difficulty: 'Easy',
  hint: 'The docs say POST-only. Try the exact same request as a GET.',
  hints: ["The docs say POST-only. But what happens if you send a GET?", "The GET route runs the same handler. The action fires.", "The GET route is wired to the same submit handler as POST. Replay the submission over GET, moving the form's parameter into the URL query, and the feedback is recorded without any POST at all."],
  tools: 'B',
  how: 'Submit feedback with GET instead of POST.',
  link: '/http#verb-tamper',
  start: 'curl -s -c jar -b jar "http://localhost:3000/http/feedback?msg=hi"',
};

function feedbackSubmit(req, res) {
  const msg = (req.method === 'GET' ? req.query.msg : req.body.msg || '').toString().slice(0, 500);
  if (!msg.trim()) {
    return res.status(400).send(page('Feedback', `
      <div class="clay-card">
        <h3>Message is required</h3>
        <p>Please write something before sending your feedback.</p>
        <p class="next-steps">
          <a class="clay-btn clay-btn-primary" href="/http/feedback">Back</a>
        </p>
      </div>
    `));
  }
  getDb().prepare('INSERT INTO http_feedback (msg, ts) VALUES (?, ?)').run(msg, new Date().toISOString());
  let extra = '';
  // VULN: documented POST-only, but the GET route runs the same handler, so a
  // state-changing action fires over GET (bookmarkable, loggable, CSRF-able).
  if (req.method === 'GET') {
    const flag = award(req, 'http', 'verb-tamper');
    extra = `<div class="clay-card">
      <h3>Feedback submitted over GET</h3>
      <p>This endpoint is documented as POST-only, but your GET request submitted
      feedback anyway.</p>
      ${flagBox(flag)}${fixPanel('http', 'verb-tamper')}
    </div>`;
  }
  res.send(page('Feedback', `
    <div class="clay-card">
      <h3>Thanks</h3>
      <p>Your feedback was recorded.</p>
      <p class="next-steps">
        <a class="clay-btn clay-btn-secondary" href="/http/feedback">Back</a>
      </p>
    </div>
    ${extra}
  `));
}

// GET /http/feedback -> form when no msg param, submit handler otherwise.
router.get('/feedback', (req, res) => {
  if (req.query.msg === undefined) {
    return res.send(page('Feedback', `
      ${brief('Customer feedback', `
        Per the API docs, feedback is accepted <b>only via POST</b>.
        Tell us how we are doing.`)}
      <div class="clay-card">
        <form method="POST" action="/http/feedback">
          <label for="msg"><b>Your feedback</b></label>
          <textarea id="msg" class="clay-input" name="msg" rows="3" placeholder="your feedback" required></textarea>
          <p class="next-steps">
            <button class="clay-btn clay-btn-primary" type="submit">Send via POST</button>
          </p>
        </form>
      </div>
      ${hintLadder(vuln)}
      ${toolsPill(vuln)}
      <p class="next-steps">
        <a class="clay-btn clay-btn-secondary" href="/http">Module index</a>
      </p>
    `));
  }
  feedbackSubmit(req, res);
});

// POST /http/feedback -> same submit handler (documented verb).
router.post('/feedback', feedbackSubmit);

module.exports = { vuln, router };
