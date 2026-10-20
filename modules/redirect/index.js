'use strict';
// Open Redirect: five labs built around one idea: the server decides where the
// browser goes next, but lets the attacker choose the destination. Covers
// protocol-relative URLs, dangerous schemes in the Location header, a naive
// allowlist beaten by backslashes, and parameter pollution where the last
// ?next= value wins.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/redirect-double-slash'),
  require('./challenges/redirect-javascript'),
  require('./challenges/redirect-data'),
  require('./challenges/redirect-backslash'),
  require('./challenges/redirect-pollution'),
];

const router = express.Router();

const BRIEF_HTML = `
<p><b>What is an open redirect?</b> After an action like login, the app sends the
browser to a URL taken from user input (often <code>?next=</code>) without
validating it. Attackers love it for phishing: the link shows the trusted
domain, but the victim lands on the attacker's page.</p>
<p><b>How to verify in this module:</b> every lab answers with a real HTTP 302.
Use <code>curl -i</code> and read the <code>Location</code> header. That header is
the proof of where the browser would go. A flag is awarded only when the evil
destination is genuinely honored.</p>`;

// GET /redirect -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('redirect', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'redirect', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Open Redirect', `
    ${brief('Module briefing', BRIEF_HTML)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Five labs, one idea: the server decides where the browser goes next, but
    lets the attacker choose the destination. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSection('redirect', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'redirect',
  name: 'Open Redirect',
  tagline: 'Five open-redirect flaws: protocol-relative URLs, dangerous schemes, backslash allowlist tricks, parameter pollution.',
  description: 'Five open-redirect labs: an unvalidated next parameter abused with protocol-relative URLs, javascript: and data: schemes, a naive string-prefix allowlist beaten by backslash separators, and parameter pollution where the last ?next= value wins. All flags are awarded server-side on real exploitation.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['misconfig'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
