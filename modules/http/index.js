'use strict';
// HTTP Layer Flaws: thin aggregator over the per-challenge files. Module-level
// middleware (form parsing, _method verb override) and the module index page
// live here; the challenge routes live in modules/http/challenges/*.js.
const express = require('express');
const { fixCta, brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill  } = require('../../lib/page');

const challenges = [
  require('./challenges/crlf-log'),
  require('./challenges/verb-tamper'),
  require('./challenges/cache-deception'),
];

const router = express.Router();

// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// VULN: the app honors a _method body parameter to rewrite the HTTP verb, so a
// plain POST can reach routes that only listen for another verb.
router.use((req, res, next) => {
  if (req.body && typeof req.body._method === 'string' && req.body._method.trim()) {
    req.httpOverride = req.body._method.trim();
    req.method = req.httpOverride.toUpperCase();
  }
  next();
});

// Where each challenge starts; used for the module index links.
const START_ROUTES = {
  'crlf-log': '/http/track',
  'verb-tamper': '/http/feedback',
  'cache-deception': '/http/cache',
};

// GET /http -> module index page.
router.get('/', (req, res) => {
  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="${esc(START_ROUTES[v.id])}">${esc(v.name)}</a> ${difficultyPill(v.difficulty)}</h3>
      <p><i>Attack:</i> ${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('http', c.vuln.id)).join('')}
    </section>`;
  res.send(page('HTTP Layer Flaws', `
    ${brief('Module briefing', `
      <p><b>What lives at the HTTP layer?</b> Before your application code even runs,
      the request passes through verbs, headers, and caches. This module attacks those:
      log forging with CR/LF bytes (confirmed in the log viewer, not on input),
      verb confusion (GET-vs-POST), and a naive cache keyed on the URL path alone.</p>
      <p><b>Heads up:</b> the cache-deception flag is returned in an <code>X-Flag</code>
      response header (the response is CSS, not HTML),
      and every capture is also saved to your scoreboard.</p>`)}
    ${trackBanner(module.exports)}
    <h2>Challenges</h2>
    <p>Three flaws hide in the protocol layer below the app. Each challenge card
    has a hint ladder: level 1 nudges, level 2 teaches the technique, level 3
    shows the payload shape.</p>
    ${cards}
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'http',
  name: 'HTTP Layer Flaws',
  tagline: 'Verbs, headers, and caches: attack the protocol before the app.',
  description: 'Three flaws in the HTTP layer itself: CRLF log injection with a forged line confirmed in the log viewer, GET-vs-POST verb tampering, and cache deception via a path-only cache key.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['misconfig'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
