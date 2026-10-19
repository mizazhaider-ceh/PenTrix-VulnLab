'use strict';
// Cross-Site Scripting: nine challenges that end in a beacon to /xss/collect
// (or, for DOM clobbering, an admin page that checks the stored markup).
const express = require('express');
const {
  briefPanel, difficultyPill, errorPage, esc, fixPanel, flagBox, hintLadder, page, payloadBlock, toolsPill, trackBanner,
} = require('../../lib/page');
const { award, captured } = require('../../lib/flags');
const { EXFIL_PAYLOAD, xssConsumeNonce } = require('./shared');

const challenges = [
  require('./challenges/reflected'),
  require('./challenges/stored'),
  require('./challenges/dom'),
  require('./challenges/xss-attr-breakout'),
  require('./challenges/xss-js-context'),
  require('./challenges/xss-svg-upload'),
  require('./challenges/xss-markdown'),
  require('./challenges/xss-dom-clobber'),
  require('./challenges/xss-backtick'),
];

// Ids accepted by the shared beacon collector and the claim-status widget.
// The DOM clobbering page never issues a token, so a beacon for it is always rejected.
const VULN_IDS = challenges.map((c) => c.vuln.id);

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const BRIEF_HTML = `
<p><b>What is XSS?</b> The app takes attacker-controlled input and renders it in the
browser as HTML or JavaScript without neutralizing it. Your script then runs in the
victim's browser, in their session.</p>
<p><b>The goal in this module:</b> steal the session cookie. This lab deliberately
sets the session cookie with <code>httpOnly:false</code>, so JavaScript can read
<code>document.cookie</code>.</p>
<p><b>How flags are awarded:</b> your payload phones home to
<code>/xss/collect</code> with the stolen data and the one-time token the page
rendered as <code>window.__px</code>. Each challenge page shows a claim box with the
payload shape for that page and a live status widget.</p>`;

// Module index page.
router.get('/', (req, res) => {
  const cards = challenges.map(({ vuln: v }) => {
    const done = captured(req, 'xss', v.id);
    return `
      <article class="vuln-card" id="${esc(v.id)}">
        <h3><a href="${esc(v.link)}">${esc(v.name)}</a>
          ${difficultyPill(v.difficulty)}
          ${done ? '<span class="captured">Flag captured</span>' : ''}
        </h3>
        <p>${esc(v.how)}</p>
        ${v.start ? payloadBlock('Starting point', v.start) : ''}
        ${hintLadder(v)}
        ${toolsPill(v)}
        <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(v.link)}">Open challenge</a></p>
      </article>`;
  }).join('\n');

  const anyCaptured = challenges.some((c) => captured(req, 'xss', c.vuln.id));

  res.send(page('Cross-Site Scripting', `
    ${briefPanel('Module briefing', BRIEF_HTML)}
    ${trackBanner(module.exports)}
    ${payloadBlock('Collector URL shape', '/xss/collect?c=<stolen data>&v=<vuln id>&n=<page token>')}
    ${payloadBlock('Canonical payload (for the reflected challenge)', EXFIL_PAYLOAD)}
    <h2>Challenges</h2>
    ${anyCaptured ? '' : '<p class="dim">Nothing captured yet. Every challenge below links its own target page.</p>'}
    ${cards}
    <h2>Cookie thief endpoint</h2>
    <p>Payloads phone home to <code>/xss/collect</code>. Each challenge page renders a
    one-time token as <code>window.__px</code>; the beacon must echo it back. The flag is
    awarded only when the beacon arrives with data and a valid token for that challenge,
    so a forged beacon with no page load earns nothing.</p>
  `));
});

// Module-level routes below belong to no single challenge: the claim-status
// widget and the beacon collector are shared by every beacon-style challenge.

// Lightweight claim-status endpoint for the live widget. Returns whether the
// flag for a vuln id has been captured in this session. Never returns a flag
// value.
router.get('/claim-status', (req, res) => {
  const v = (req.query.v || '').toString();
  if (!VULN_IDS.includes(v)) return res.status(400).json({ error: 'unknown vuln' });
  res.json({ captured: captured(req, 'xss', v) });
});

router.get('/collect', (req, res) => {
  const c = (req.query.c || '').toString();
  const v = (req.query.v || '').toString();
  const n = (req.query.n || '').toString();
  // Award only when a real beacon arrives: non-empty stolen data, a known vuln
  // id, AND the page-bound nonce for that vuln. The nonce is issued when the
  // challenge page loads and rendered into the page as window.__px, so the
  // beacon proves the payload executed in the page (or at least that the
  // challenge page was loaded in this session). Nonces are single-use.
  if (c.length > 0 && VULN_IDS.includes(v) && xssConsumeNonce(req, v, n)) {
    const flag = award(req, 'xss', v);
    return res.send(page('Cookie collector', `
      <h2>Beacon received</h2>
      <p>Captured <b>${c.length}</b> characters of data for vuln
      <b>${esc(v)}</b>, with a valid page-bound token. Flag awarded:</p>
      ${flagBox(flag)}
      ${fixPanel('xss', v)}
      <p><a href="/xss">Back to the XSS module</a></p>
    `));
  }
  res.status(400).send(page('Cookie collector', errorPage(400, 'No flag', `
    <p>This endpoint only awards a flag when a real exfiltration beacon arrives
    with non-empty data (<code>c</code>), a valid vuln id (<code>v</code>), and
    the page-bound token (<code>n</code>, which is <code>window.__px</code> rendered
    into the challenge page). Loading the challenge page issues the token; a bare
    curl of this endpoint earns nothing.</p>
    ${payloadBlock('The intended payload', EXFIL_PAYLOAD)}`)));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'xss',
  name: 'Cross-Site Scripting',
  tagline: 'Inject JavaScript, steal the session cookie, capture nine flags.',
  description: 'Nine cross-site scripting flaws: a reflected search box, a stored guestbook, and a DOM-based fragment sink, plus attribute and JavaScript-string breakouts, a malicious SVG upload, a naive markdown renderer, DOM clobbering, and template-literal injection.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['misconfig'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
