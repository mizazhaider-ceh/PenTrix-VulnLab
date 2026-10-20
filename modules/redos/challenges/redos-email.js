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
// VULN: the email validator nests a quantifier inside a quantifier, so a
// crafted input makes the match take exponentially longer (ReDoS).
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
    est: 'about 10 to 25 minutes',
    hint: 'The local part nests a quantifier inside a quantifier. A near-miss input forces the engine to retry every way of splitting it before the match can fail.',
    hints: ["Send the /redos/email request to Burp Repeater. The page prints the exact regex: nested quantifiers in the local part. Which input forces the engine to retry every split?", "In Repeater, build a long run of valid local-part characters that never contains an @, then end it with a character that breaks the match. Watch the response time in the Repeater timer.", "Grow the run a few characters at a time (Intruder can do this with one payload position). Each added character multiplies the backtracking. You win when the timer crosses the 1000 ms threshold."],
    tools: "BZ, B",
    how: 'In Burp Repeater, find the near-miss input shape that makes this nested-quantifier validator backtrack: an input that almost matches, grown until the check crosses the 1000 ms threshold.',
    link: '/redos#redos-email',
    start: 'In your browser with Burp Proxy intercepting, open /redos/email, then right-click the signup request and send it to Repeater. Add an email parameter to the URL and send.',
  },
  router,
};
