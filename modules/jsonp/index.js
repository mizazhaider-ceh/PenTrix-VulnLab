'use strict';
// JSONP Injection: intentionally vulnerable JSONP endpoints for training.
const express = require('express');
const { award } = require('../../lib/flags');
const { fixCta, brief, esc, flagBox, page, payloadBlock, hintLadder, toolsPill, trackBanner, difficultyPill } = require('../../lib/page');
const { jsonpConsumeNonce } = require('./shared');

const challenges = [
  require('./challenges/callback-xss'),
  require('./challenges/csrf-data'),
  require('./challenges/filter-bypass'),
  require('./challenges/array-hijack'),
  require('./challenges/mimetype'),
];

const router = express.Router();

// GET /jsonp/beacon-xss -> shared beacon for the three reflection labs
// (callback-xss, filter-bypass, mimetype). The injected script echoes the
// per-session token back here; that echo proves the payload really executed
// with the JSONP response data. Tokens are single-use. Module-level route,
// not part of any single challenge.
router.get('/beacon-xss', (req, res) => {
  const v = String(req.query.v || '');
  const n = String(req.query.n || '');
  const ids = ['callback-xss', 'filter-bypass', 'mimetype'];
  let ok = ids.includes(v) && jsonpConsumeNonce(req, v, n);
  // The filter-bypass and mimetype labs teach a specific payload shape; the
  // endpoint records the attempt, the nonce echo proves it executed.
  if (ok && v === 'filter-bypass') ok = req.session.jsonpFbAttempt === true;
  if (ok && v === 'mimetype') ok = req.session.jsonpMimeAttempt === true;
  if (ok) {
    const flag = award(req, 'jsonp', v);
    return res.send(page('Payload executed', `
      <h2>Payload executed</h2>
      <p>The injected script ran with the JSONP response data and echoed the
      page-bound token back for vuln <b>${esc(v)}</b>. Flag awarded:</p>
      ${flagBox(flag)}
      <p><a href="/jsonp">Back to the JSONP module</a></p>
    `));
  }
  res.status(400).send(page('Beacon', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when the injected script really executed:
    the beacon must echo the per-session token (<code>n</code>) that the JSONP
    endpoint embedded in its response data. Load the JSONP URL as a script and
    let your payload fire the beacon.</p>
    <p><a href="/jsonp">Back to the JSONP module</a></p>
  `));
});

// GET /jsonp -> module index page.
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
      ${challenges.map((c) => fixCta('jsonp', c.vuln.id)).join('')}
    </section>`;
  res.send(page('JSONP Injection', `
    ${brief('JSONP Injection', `
      Before CORS, sites shared data cross-origin with "JSON with padding":
      the server wraps JSON in a caller-chosen JavaScript function, e.g.
      <code>callback({"user":"alice"})</code>, and any page loads it with a
      <code>&lt;script&gt;</code> tag. Classic <code>script</code> tags are
      exempt from the Same-Origin Policy, so <b>any site can read JSONP</b>.
      Your goals: break out of the callback into executable JavaScript, steal
      JSONP data cross-origin via an attacker page, bypass a naive callback
      blocklist, replay the historic Array-constructor hijack, and abuse a
      <code>text/html</code> MIME type. The reflection labs embed a per-session
      token in the JSONP response data: your injected script must echo that
      token back to <code>/jsonp/beacon-xss</code>, and only an executed beacon
      captures the flag. Demo attacker pages live at
      <code>/jsonp/attacker</code> and <code>/jsonp/array-attacker</code>.`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Five flaws hide in the feeds below. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'jsonp',
  name: 'JSONP Injection',
  tagline: 'Callback reflection, cross-origin theft, and MIME trickery.',
  description: 'Five flaws in the JSONP pattern: unvalidated callback reflection, sensitive data readable cross-origin via script tags, a naive "alert" blocklist, the historic Array-constructor hijack against a legacy endpoint, and JSONP served with a text/html MIME type.',
  difficulty: 'Intermediate',
  track: 'Advanced',
  prerequisites: ['xss', 'cors'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
