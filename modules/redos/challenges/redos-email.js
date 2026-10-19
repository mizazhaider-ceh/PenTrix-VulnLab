'use strict';
// ReDoS: newsletter signup email validator.
// GET /redos/email runs user input against a catastrophic email regex and
// reports the wall-clock time. Past the threshold, the flag is awarded.
const express = require('express');
const { award } = require('../../../lib/flags');
const { esc, flagBox, appShell, page } = require('../../../lib/page');

const router = express.Router();

const THRESHOLD_MS = 1000;
// Nested quantifier in the local part: a long run of valid characters with
// no @ forces exponential backtracking.
const EMAIL_RE = /^(([a-zA-Z0-9_\-\.]+)+)@([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/;
const MAX_LEN = 33;

function formHtml() {
  return appShell('PenTriX Mail', `
    <h2>Newsletter signup</h2>
    <p class="dim">Join our security newsletter. We validate every address with
    our strict RFC-style checker before adding you to the list.</p>
    <form method="GET" action="/redos/email" class="clay-form">
      <label class="clay-label" for="email">Email address</label>
      <input class="clay-input" type="text" id="email" name="email"
        placeholder="you@example.com" size="50" required />
      <button class="clay-btn clay-btn-primary" type="submit">Subscribe</button>
    </form>
    <p class="note">Max length: ${MAX_LEN} characters. The local part allows
    letters, digits, and <code>. _ -</code>. What input has no @ at all?</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos">Module index</a></p>
  `, { mark: '✉', nav: ['Home', 'Archive', 'Subscribe'] });
}

function resultHtml(req, input, ok, ms) {
  let extra = '';
  if (ms > THRESHOLD_MS) {
    const flag = award(req, 'redos', 'redos-email');
    extra = `<h3>Denial of service demonstrated</h3>
      <p>The check took <b>${ms} ms</b>. On a real server, every request like
      this one blocks the event loop for everyone.</p>${flagBox(flag)}`;
  }
  return appShell('PenTriX Mail', `
    <h2>Validation result</h2>
    <p>Input: <code>${esc(input)}</code></p>
    <p>Pattern: <code>${esc(String(EMAIL_RE))}</code></p>
    <p>Match: <b>${ok ? 'yes' : 'no'}</b> &middot; Time: <b>${ms} ms</b>
    (threshold: ${THRESHOLD_MS} ms)</p>
    ${extra}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos/email">Try another input</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos">Module index</a></p>
  `, { mark: '✉', nav: ['Home', 'Archive', 'Subscribe'] });
}

router.get('/email', (req, res) => {
  const email = req.query.email;
  if (email === undefined) {
    return res.send(page('Email validator', formHtml()));
  }
  const s = String(email).slice(0, 500);
  if (s.length > MAX_LEN) {
    return res.status(400).send(page('Too long', appShell('PenTriX Mail',
      '<p>Max 33 characters.</p><p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos/email">Back</a></p>',
      { mark: '✉', nav: ['Home', 'Archive', 'Subscribe'] })));
  }
  const t0 = Date.now();
  const ok = EMAIL_RE.test(s);
  const ms = Date.now() - t0;
  res.send(page('Email validator', resultHtml(req, s, ok, ms)));
});

module.exports = {
  vuln: {
    id: 'redos-email',
    name: 'Catastrophic Email Regex',
    difficulty: 'Medium',
    hint: 'The local part is ((...+)+): nested quantifiers. Send a long run of valid characters with no @ anywhere.',
    hints: ["The email regex has nested quantifiers. What input makes it backtrack?", "A long valid run followed by a bad tail. The engine tries all splits.", "Build input that is almost valid: a long run of valid characters, then a tail that breaks the match so the engine must retry every split. Time the response."],
    tools: "B, C",
    how: 'Submit 30 a\'s followed by a non-matching character as the email (add a few more, up to the length cap, if your machine is very fast).',
    link: '/redos#redos-email',
    start: 'curl -s "http://localhost:3000/redos/email" | head -c 200',
  },
  router,
};
