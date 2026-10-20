'use strict';
// Security Misconfiguration: debug pages, backup dumps, and directory listings
// that give away the keys. Thin aggregator: every challenge lives in its own
// file under ./challenges, this file only wires them together and renders the
// module index page.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/debug'),
  require('./challenges/backup'),
  require('./challenges/listing'),
  require('./challenges/git'),
  require('./challenges/swp'),
  require('./challenges/trace'),
  require('./challenges/env'),
  require('./challenges/manager'),
  require('./challenges/robots'),
  require('./challenges/put'),
];

const router = express.Router();

// GET /misconfig -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('misconfig', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'misconfig', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Security Misconfiguration', `
    ${brief('Security Misconfiguration', `
      Defaults kill. This module collects the classics: <b>debug mode left on</b>
      in a deployed app, a <b>database backup</b> sitting where the web server can
      serve it, a <b>directory listing</b> that hands out files nobody was supposed
      to see, plus an exposed <b>.git directory</b>, a <b>vim swap file</b>, an
      enabled <b>TRACE method</b>, a public <b>.env</b>, <b>default
      credentials</b>, a chatty <b>robots.txt</b>, and an unauthenticated
      <b>PUT</b> upload. Ten flags, one lesson: <span class="dim">harden every
      environment like it is production.</span>`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Ten deployment mistakes hide below. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSection('misconfig', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'misconfig',
  name: 'Security Misconfiguration',
  tagline: 'Debug pages, backup dumps, and directory listings that give away the keys.',
  description:
    'The vulnerability is not in the code logic but in how the app is deployed: verbose error pages, backups left under the web root, directory listings that expose internal files, an exposed .git directory, swap files, TRACE, .env leaks, default credentials, robots.txt disclosure, and unauthenticated PUT uploads. Ten flags for the sharp-eyed.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: [],
  vulns: challenges.map((c) => c.vuln),
  router,
};
