'use strict';
// ReDoS: username availability checker.
// GET /redos/username tests input against the classic catastrophic pattern
// ^(a+)+$ and reports the wall-clock time. Past the threshold, the flag is
// awarded.
const express = require('express');
const { award } = require('../../../lib/flags');
const { esc, flagBox, appShell, page } = require('../../../lib/page');

const router = express.Router();

const THRESHOLD_MS = 1000;
// The textbook catastrophic pattern: every partition of the a-run is tried
// before the trailing mismatch fails the match.
const USER_RE = /^(a+)+$/;
const MAX_LEN = 30;

function formHtml() {
  return appShell('Account Hub', `
    <h2>Pick a username</h2>
    <p class="dim">Choose a unique username for your new account. We check
    availability and format in one fast step.</p>
    <form method="GET" action="/redos/username" class="clay-form">
      <label class="clay-label" for="username">Desired username</label>
      <input class="clay-input" type="text" id="username" name="username"
        placeholder="cooluser" size="50" required />
      <button class="clay-btn clay-btn-primary" type="submit">Check availability</button>
    </form>
    <p class="note">Max length: ${MAX_LEN} characters. The pattern is
    <code>^(a+)+$</code>. Feed it many a&#39;s, then break the match at the end.</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos">Module index</a></p>
  `, { mark: '◉', nav: ['Home', 'Plans', 'Sign in'] });
}

function resultHtml(req, input, ok, ms) {
  let extra = '';
  if (ms > THRESHOLD_MS) {
    const flag = award(req, 'redos', 'redos-username');
    extra = `<h3>Denial of service demonstrated</h3>
      <p>The check took <b>${ms} ms</b>. On a real server, every request like
      this one blocks the event loop for everyone.</p>${flagBox(flag)}`;
  }
  return appShell('Account Hub', `
    <h2>Availability result</h2>
    <p>Input: <code>${esc(input)}</code></p>
    <p>Pattern: <code>${esc(String(USER_RE))}</code></p>
    <p>Match: <b>${ok ? 'yes' : 'no'}</b> &middot; Time: <b>${ms} ms</b>
    (threshold: ${THRESHOLD_MS} ms)</p>
    ${extra}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos/username">Try another input</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos">Module index</a></p>
  `, { mark: '◉', nav: ['Home', 'Plans', 'Sign in'] });
}

router.get('/username', (req, res) => {
  const username = req.query.username;
  if (username === undefined) {
    return res.send(page('Username checker', formHtml()));
  }
  const s = String(username).slice(0, 500);
  if (s.length > MAX_LEN) {
    return res.status(400).send(page('Too long', appShell('Account Hub',
      '<p>Max 30 characters.</p><p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos/username">Back</a></p>',
      { mark: '◉', nav: ['Home', 'Plans', 'Sign in'] })));
  }
  const t0 = Date.now();
  const ok = USER_RE.test(s);
  const ms = Date.now() - t0;
  res.send(page('Username checker', resultHtml(req, s, ok, ms)));
});

module.exports = {
  vuln: {
    id: 'redos-username',
    name: 'Nested Quantifier Username',
    difficulty: 'Easy',
    hint: 'The pattern is shown on the page: ^(a+)+$. Give it what it wants, then take it away at the last character.',
    hints: ["The pattern is (a+)+. Classic catastrophic backtracking.", "Each 'a' can be grouped many ways. Exponential.", "Submit 'aaaaaaaaaaaaaaaaaaaaaaaa!' and time it."],
    tools: "B, C",
    how: 'Submit 27 a\'s plus a trailing character that breaks the match (add a few more, up to the length cap, if your machine is very fast).',
    link: '/redos#redos-username',
    start: 'curl -s "http://localhost:3000/redos/username" | head -c 200',
  },
  router,
};
