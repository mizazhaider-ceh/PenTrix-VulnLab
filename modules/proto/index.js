'use strict';
// Prototype Pollution: a naive recursive merge folds attacker input into
// config objects without filtering keys. Six challenges, each abusing a
// different way to smuggle __proto__ / constructor / prototype past the merge.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/proto-query'),
  require('./challenges/proto-json'),
  require('./challenges/proto-constructor'),
  require('./challenges/proto-dos'),
  require('./challenges/proto-client'),
  require('./challenges/proto-unicode-bypass'),
];

const router = express.Router();

// Router-scoped body parsing (moved from router.js; the challenge files rely
// on these at the module level). urlencoded and json for the merge consoles,
// text/plain for the unicode lab: the app-level json parser would already have
// decoded \uXXXX escapes, destroying the raw evidence.
router.use(express.urlencoded({ extended: false }));
router.use(express.json());
router.use(express.text({ type: 'text/plain' }));

const BRIEF_HTML = `
<p><b>What is prototype pollution?</b> Every JavaScript object inherits from
<code>Object.prototype</code>. A recursive <i>merge</i> that copies attacker
keys without filtering lets an attacker write to <code>__proto__</code>,
<code>constructor.prototype</code>, and friends, silently changing the
behaviour of <b>every object</b> in the process.</p>
<p><b>The pattern in this module:</b> each challenge merges your input into an
object with the naive <code>merge()</code> shared by the challenges. Your job
is to smuggle a magic key through, pollute <code>Object.prototype</code>, and
then make a "fresh" <code>{}</code> fail (or pass) a check it should never pass.</p>
<p>Each challenge page links its own admin check. Pollute first, then open the check.</p>`;

// GET /proto -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('proto', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'proto', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Prototype Pollution', `
    ${brief('Module briefing', BRIEF_HTML)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Six ways to smuggle a magic key through the same naive merge: query
    strings, JSON bodies, a constructor blacklist bypass, a toString denial of
    service, client-side pollution, and a unicode escape blacklist bypass.</p>
    ${cards}
    <p class="note">Tip: pollution is process-wide once it lands. If a check
    passes "for free", restart the lab server for a clean slate.</p>
  ${fixSection('proto', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'proto',
  name: 'Prototype Pollution',
  tagline: 'Smuggle magic keys through a naive recursive merge and turn Object.prototype into a privilege escalation.',
  description: 'A hand-rolled deep merge folds attacker input into config objects without filtering keys. Pollute Object.prototype through query strings, JSON bodies, constructor.prototype, unicode escapes, and even in the victim browser, then watch fresh objects inherit your values.',
  difficulty: 'Advanced',
  track: 'Advanced',
  prerequisites: ['xss', 'sqli'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
