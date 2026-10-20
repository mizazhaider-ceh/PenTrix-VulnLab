'use strict';
// ReDoS: one crafted string to block the event loop. Four endpoints validate
// user input with catastrophic regular expressions.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');
const { THRESHOLD_MS } = require('./shared');

const challenges = [
  require('./challenges/redos-email'),
  require('./challenges/redos-username'),
  require('./challenges/redos-url'),
  require('./challenges/redos-search'),
];

const router = express.Router();

// Router-scoped form parsing only (app-level middleware is out of scope).
// Needed so POST /redos/search can read req.body.q.
router.use(express.urlencoded({ extended: false }));

// GET /redos -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('redos', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'redos', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('ReDoS', `
    ${brief('Module briefing', `
      <p><b>What is ReDoS?</b> A regular expression with nested quantifiers
      (like <code>(a+)+</code>) can take exponential time on certain inputs:
      the engine tries every way to split the input before giving up. One
      crafted string ties up the server's single thread, denying service to
      everyone.</p>
      <p><b>How this lab works:</b> each endpoint runs your input against a
      vulnerable regex and reports the milliseconds it took. Push the check past
      <b>${THRESHOLD_MS} ms</b> and the flag is awarded. Inputs are length-capped
      so the worst case is seconds, not minutes. Watch the reported time on the
      page, or the response timer in Burp Repeater.</p>`)}
    ${trackBanner(module.exports)}

    <h2>Endpoints</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">ReDoS endpoints</caption>
      <thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Description</th></tr></thead>
      <tbody>
        <tr><td>GET</td><td><code>/redos/email</code></td><td>Newsletter signup: email validator</td></tr>
        <tr><td>GET</td><td><code>/redos/username</code></td><td>Username availability checker</td></tr>
        <tr><td>GET</td><td><code>/redos/url</code></td><td>Bookmark saver: URL validator</td></tr>
        <tr><td>GET / POST</td><td><code>/redos/search</code></td><td>Site search (query is compiled into a pattern)</td></tr>
      </tbody>
    </table></div>

    <h2>Challenges</h2>
    <p>Four catastrophic patterns hide in the endpoints above. Each challenge
    card has a hint ladder: level 1 nudges, level 2 teaches the technique,
    level 3 shows the payload shape.</p>
    ${cards}
  ${fixSection('redos', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'redos',
  name: 'ReDoS',
  tagline: 'One crafted string to block the event loop.',
  description: 'Four endpoints validate user input with catastrophic regular expressions. Find the evil input shape for each pattern, push the check past 1000 ms, and watch a single request deny service.',
  difficulty: 'Intermediate',
  track: 'Advanced',
  prerequisites: ['Injection track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
