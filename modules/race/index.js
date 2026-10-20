'use strict';
// Race Conditions: intentionally vulnerable check-then-act training targets.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');
const shared = require('./shared');

const challenges = [
  require('./challenges/race-coupon'),
  require('./challenges/race-balance'),
  require('./challenges/race-vote'),
  require('./challenges/race-referral'),
  require('./challenges/race-register'),
  require('./challenges/race-upload-scan'),
  require('./challenges/race-ratelimit'),
  require('./challenges/race-stock'),
];

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// POST /race/reset -> wipe ONLY the requesting session's race lab state
// back to its initial values (P1-1, P1-2). This used to be an unauthenticated
// GET that wiped the process-global state for every student at once, and
// being a GET made it CSRF-able. As a POST scoped to the caller's session it
// can neither be triggered cross-site by a bare link nor disturb anyone else.
// Module-level helper route, not part of any single challenge.
router.post('/reset', (req, res) => {
  shared.resetRace(req);
  res.send(page('Race lab reset', `
    <h2>State reset</h2>
    <p>Your race state is back to its initial values. No other student's lab was touched.</p>
    <p><a href="/race">Back to the Race Conditions module</a></p>
  `));
});

// GET /race -> module index page (briefing plus the eight challenge cards).
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('race', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'race', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Race Conditions', `
    ${brief('Race Conditions', `Check-then-act flaws: win the race between the check and the use. Send many identical requests in parallel and watch the invariant break.`)}
    ${trackBanner(module.exports)}

    <h2>What is a race condition?</h2>
    <p>The server checks something ("is this coupon unused?"), then acts on it
    ("redeem it") as two separate steps. If two requests arrive at the same
    time, both can pass the check before either one acts, and the invariant the
    check was protecting gets violated.</p>

    <h2>How to attack these labs</h2>
    <p>Send many identical requests <b>in parallel</b>. A single request at a
    time behaves correctly; twenty at once do not. The Burp way: send the
    request to <b>Repeater</b> (Ctrl+R), duplicate the tab as many times as
    you need (right-click the tab, <b>Duplicate tab</b>), select all the tabs,
    right-click and choose <b>Send group in parallel</b>. Every tab fires
    near-simultaneously, the single-packet attack. Honest note: Community
    <b>Intruder</b> is throttled and cannot reliably land many requests inside
    these short windows, so the Repeater group, not Intruder, is the race tool
    for this module. (The full walkthrough lives in the
    <a href="/setup-guide">Tool Setup Guide</a>, section 3.)</p>
    <p>Script alternative (not the default):</p>
    <pre><code>seq 1 20 | xargs -P20 -I{} curl -s -X POST http://<your-lab-address>/race/coupon/redeem</code></pre>
    <p>Use the <b>Reset lab state</b> button before each attempt so you start from
    a clean slate. Flags are awarded only when the invariant is actually
    broken.</p>

    <h2>Challenges</h2>
    <p>Eight time-of-check to time-of-use labs hide below. Each challenge card
    has a hint ladder: level 1 nudges, level 2 teaches the technique, level 3
    shows the payload shape.</p>
    ${cards}

    <h2>Lab state</h2>
    <form method="POST" action="/race/reset" style="display:inline"><button type="submit" class="clay-btn clay-btn-secondary clay-btn-sm">Reset lab state</button></form>
    <span class="dim">Resets your own coupons, balances, votes, accounts, uploads, limits and stock (nobody else's).</span>
  ${fixSection('race', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'race',
  name: 'Race Conditions',
  tagline: 'Check-then-act flaws: win the race between the check and the use.',
  description: 'Eight time-of-check to time-of-use vulnerabilities. Each handler pauses briefly between verifying a condition and acting on it, so parallel requests interleave and break the invariant: single-use coupons redeemed twice, negative balances, double votes, duplicate accounts, a file fetched before the AV scan deletes it, a burst through a rate limit, and oversold stock.',
  difficulty: 'Advanced',
  track: 'Advanced',
  prerequisites: ['Auth and Sessions track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
