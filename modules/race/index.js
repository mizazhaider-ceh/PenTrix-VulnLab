'use strict';
// Race Conditions: intentionally vulnerable check-then-act training targets.
const express = require('express');
const { fixCta, brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill  } = require('../../lib/page');
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

// GET /race/reset -> wipe all race lab state back to its initial values.
// Module-level helper route, not part of any single challenge.
router.get('/reset', (req, res) => {
  shared.resetRace();
  res.send(page('Race lab reset', `
    <h2>State reset</h2>
    <p>All race state is back to its initial values.</p>
    <p><a href="/race">Back to the Race Conditions module</a></p>
  `));
});

// GET /race -> module index page (briefing plus the eight challenge cards).
router.get('/', (req, res) => {
  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('race', c.vuln.id)).join('')}
    </section>`;
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
    time behaves correctly; twenty at once do not. Each challenge page tells
    you the exact command, e.g.</p>
    <pre><code>seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/coupon/redeem</code></pre>
    <p>Use the <b>Reset lab state</b> link before each attempt so you start from
    a clean slate. Flags are awarded only when the invariant is actually
    broken.</p>

    <h2>Challenges</h2>
    <p>Eight time-of-check to time-of-use labs hide below. Each challenge card
    has a hint ladder: level 1 nudges, level 2 teaches the technique, level 3
    shows the payload shape.</p>
    ${cards}

    <h2>Lab state</h2>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race/reset">Reset lab state</a>
    <span class="dim">Resets coupons, balances, votes, accounts, uploads, limits and stock.</span></p>
  ${fixSectionHtml}
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
