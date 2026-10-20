'use strict';
// Burst Through the Rate Limit: the limiter allows 5 requests, but each request
// is counted only after an async gap. A parallel burst all reads the old
// counter value, so more than 5 requests get through in one window.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
// Module-level race plumbing lives in ../shared.js (see final report): the
// shared state getter, the check-to-use sleep window, and the back link.
const { sleep, WINDOW, raceState, backLink } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'race-ratelimit',
  name: 'Burst Through the Rate Limit',
  difficulty: 'Medium',
  path: 'ratelimit',
  hint: 'The limiter allows 5 requests, but it counts each request only after an async gap. A parallel burst all reads "0 used" at once.',
  hints: ["Send one POST /race/ratelimit/hit to Burp Repeater and replay it: the counter goes up by exactly one each time.", "Now make Repeater fire many at once: duplicate the request tab 20 times, select all the tabs, and right-click to choose Send group in parallel. Community Intruder is throttled, so its spaced-out requests would just hit the limit one by one.", "A burst of 20 parallel requests all reads the counter before it increments. An accepted count above 5 proves the bypass."],
  tools: 'BZ, P, C',
  est: 'about 10 minutes',
  how: 'A rate limiter that counts a request only after an async gap lets a whole parallel burst read the same not-yet-updated counter.',
  link: '/race#race-ratelimit',
  start: 'Proxy the Rate-limited API page in Burp, send one POST /race/ratelimit/hit to Repeater, duplicate the tab 20 times, then Send group in parallel. Watch the accepted count climb past 5.',
};

// GET /race/ratelimit -> the API console showing the current window count.
router.get('/ratelimit', (req, res) => {
  const R = raceState(req);
  res.send(page('Rate-limited API', `
    ${brief('The scenario', `
      <p>The <b>Metrics API</b> at this company is protected by a rate limiter:
      each window allows <b>5 requests</b>. The limiter checks the count, then
      waits briefly (simulating an async accounting write), and only then
      increments the counter.</p>
      <p>Your goal: get <b>more than 5</b> requests accepted inside a single
      window. One click at a time always behaves. Twenty requests at the exact
      same instant do not.</p>`)}
    <section class="clay-card">
      <h2>API endpoint (limit: 5 requests)</h2>
      <p>Accepted in this window: <b>${R.ratelimit.count}</b> · Rejected in this window: <b>${R.ratelimit.rejected || 0}</b></p>
      <p class="dim">Reload this page after a burst to check the result here: an accepted count above 5 proves the burst beat the limiter.</p>
      <form method="POST" action="/race/ratelimit/hit">
        <button class="clay-btn clay-btn-primary" type="submit">Send one request</button>
      </form>
    </section>
    <section class="clay-card">
      <h3>Break it</h3>
      <p>Click once and you are counted. Send 20 at the exact same instant and
      the counter cannot keep up: Proxy this page in Burp, send
      <code>POST /race/ratelimit/hit</code> to Repeater, duplicate the tab 20
      times, select the group, and choose Send group in parallel. Watch the
      accepted count climb past 5.</p>
    </section>
    ${hintLadder(vuln)}
    ${backLink}
  `));
});

// POST /race/ratelimit/hit -> one counted request against the limiter.
router.post('/ratelimit/hit', async (req, res) => {
  const R = raceState(req);
  // VULN: the "under the limit?" check runs, then an await, and only then is
  // the counter incremented; a parallel burst all reads the old counter value.
  if (R.ratelimit.count >= 5) {
    R.ratelimit.rejected = (R.ratelimit.rejected || 0) + 1;
    return res.status(429).send(page('Rate limited', `
      <section class="clay-card">
        <h2>429: too many requests</h2>
        <p>The limit of 5 requests was reached.</p>
        <p>Accepted in this window: <b>${R.ratelimit.count}</b> · Rejected in this window: <b>${R.ratelimit.rejected}</b></p>
      </section>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.ratelimit.count += 1;

  let flagHtml = '';
  if (R.ratelimit.count > 5 && !captured(req, 'race', 'race-ratelimit')) {
    flagHtml = flagBox(award(req, 'race', 'race-ratelimit'));
    flagHtml += fixPanel('race', 'race-ratelimit');
  }
  res.send(page('API response', `
    <section class="clay-card">
      <h2>200: request allowed (#${R.ratelimit.count})</h2>
      <p>Accepted in this window: <b>${R.ratelimit.count}</b> · Rejected in this window: <b>${R.ratelimit.rejected || 0}</b></p>
      ${R.ratelimit.count > 5 ? '<p><b>More than 5 requests were allowed in one window.</b> The burst beat the counter.</p>' : ''}
      ${flagHtml}
    </section>
    ${backLink}
  `));
});

module.exports = {
  vuln,
  router,
};
