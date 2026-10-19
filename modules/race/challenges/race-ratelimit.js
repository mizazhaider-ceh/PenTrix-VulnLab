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
  hints: ["The limit is 5 per window. But windows are checked per-request, not atomically.", "Burst 20 parallel requests. The counter doesn't keep up.", "Fire 20 parallel requests. Count > 5 proves the bypass."],
  tools: 'P, C',
  how: 'Hit POST /race/ratelimit/hit with 20 parallel requests so more than 5 are allowed in one window.',
  link: '/race#race-ratelimit',
  start: 'curl -s http://localhost:3000/race/ratelimit\nseq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/ratelimit/hit',
};

// GET /race/ratelimit -> the API console showing the current window count.
router.get('/ratelimit', (req, res) => {
  const R = raceState();
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
      <p>Requests counted in this window: <b>${R.ratelimit.count}</b></p>
      <form method="POST" action="/race/ratelimit/hit">
        <button class="clay-btn clay-btn-primary" type="submit">Send one request</button>
      </form>
    </section>
    <section class="clay-card">
      <h3>Break it</h3>
      <p>Click once and you are counted. Send 20 at the same instant and the
      counter cannot keep up:</p>
      <pre><code>seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/ratelimit/hit</code></pre>
    </section>
    ${hintLadder(vuln)}
    ${backLink}
  `));
});

// POST /race/ratelimit/hit -> one counted request against the limiter.
router.post('/ratelimit/hit', async (req, res) => {
  const R = raceState();
  // VULN: the "under the limit?" check runs, then an await, and only then is
  // the counter incremented; a parallel burst all reads the old counter value.
  if (R.ratelimit.count >= 5) {
    return res.status(429).send(page('Rate limited', `
      <section class="clay-card">
        <h2>429: too many requests</h2>
        <p>The limit of 5 requests was reached.</p>
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
