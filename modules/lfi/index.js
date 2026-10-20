'use strict';
// LFI module: Path Traversal / Local File Inclusion.
// Nine labs on a fictional document portal (PenDocs): plain traversal, a
// naive single-pass "../" blacklist, absolute paths, double encoding,
// nested-filter bypass, a parameter the filter never checked, a log
// poisoning chain, a /proc/self/environ leak, and a planted secret config.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/traversal'),
  require('./challenges/filter-bypass'),
  require('./challenges/absolute'),
  require('./challenges/double-encode'),
  require('./challenges/nested-deep'),
  require('./challenges/lang'),
  require('./challenges/log-poison'),
  require('./challenges/proc-self'),
  require('./challenges/config-read'),
];

const router = express.Router();
// Router-scoped form parsing only (app-level middleware already covers GET
// query strings; kept for parity with the pre-split router).
router.use(express.urlencoded({ extended: false }));

// ---- module index ----
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('lfi', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="${esc(v.link)}">${esc(v.name)}</a> ${difficultyPill(v.difficulty)} ${capturedPill(req, 'lfi', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  res.send(page('Path Traversal / LFI', `
    ${brief('Path Traversal / LFI',
      `Files are read from disk using a name taken straight from the URL.
       Some endpoints filter nothing at all, others filter once and hope for
       the best. Find <code>${esc('secret.txt')}</code> and read its contents
       to capture the flags.`)}
    ${trackBanner(module.exports)}
    <h2>Challenges</h2>
    ${cards}
  ${fixSection('lfi', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'lfi',
  name: 'Path Traversal / LFI',
  tagline: 'Break out of the docs folder and read the secret file.',
  description: 'A document viewer and downloader hand your filename straight to the filesystem, behind filters of very different strength: none at all, a single-pass strip, one decode, and more. Nine labs deepen the craft: plain and nested traversal, absolute paths, double encoding, an unchecked language parameter, log poisoning, /proc leaks, and a planted secret config.',
  difficulty: 'Intermediate',
  track: 'Injection',
  prerequisites: ['sqli'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
