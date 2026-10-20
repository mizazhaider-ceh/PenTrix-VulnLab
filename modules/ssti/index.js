'use strict';
// Server-Side Template Injection: a greeting card that eval()s your name.
// Nine labs on the same homemade engine: prove evaluation with {{7*7}},
// then beat a series of naive filters (words, underscores, brackets, dots,
// single-strip braces, quotes) and finish by turning SSTI into real RCE.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/basic'),
  require('./challenges/rce'),
  require('./challenges/ssti-wordfilter'),
  require('./challenges/ssti-nounderscore'),
  require('./challenges/ssti-nobrackets'),
  require('./challenges/ssti-dotblock'),
  require('./challenges/ssti-curly'),
  require('./challenges/ssti-noquotes'),
  require('./challenges/ssti-rce'),
];

const router = express.Router();

// GET /ssti -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('ssti', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'ssti', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Server-Side Template Injection', `
    ${brief('Server-Side Template Injection', `
      <p>This greeting card renders your name through a <strong>homemade template engine</strong>:
      it takes the string <code>Hello &lt;your name&gt;!</code> and evaluates anything inside
      <code>{{ }}</code> as code.</p>
      <p><strong>Escalation path:</strong> first prove evaluation works with <code>{{7*7}}</code>
      (you should see <strong>49</strong> in the greeting), then probe the template scope:
      the expression runs with server-side variables in scope, so try reading candidate
      variable names (what would a developer call a variable that holds a flag?) until one
      renders a value. The later labs add naive filters you must bypass, and the
      final lab turns the template engine into a real shell.</p>`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Nine flaws hide in the gadgets below. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSection('ssti', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'ssti',
  name: 'Server-Side Template Injection',
  tagline: 'A greeting card that eval()s your name. Prove it with {{7*7}}, then steal the flag.',
  description: 'The /ssti/greet endpoint renders your name through a naive homemade template engine that evaluates anything inside {{ }} as server-side code. Prove expression evaluation with arithmetic, then escalate to read a secret variable from the template scope.',
  difficulty: 'Intermediate',
  track: 'Injection',
  prerequisites: ['sqli', 'xss'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
