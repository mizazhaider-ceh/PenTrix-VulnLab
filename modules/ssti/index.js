'use strict';
// Server-Side Template Injection: a greeting card that eval()s your name.
// Nine labs on the same homemade engine: prove evaluation with {{7*7}},
// then beat a series of naive filters (words, underscores, brackets, dots,
// single-strip braces, quotes) and finish by turning SSTI into real RCE.
const express = require('express');
const { fixCta, brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill  } = require('../../lib/page');

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
      ${challenges.map((c) => fixCta('ssti', c.vuln.id)).join('')}
    </section>`;
  res.send(page('Server-Side Template Injection', `
    ${brief('Server-Side Template Injection', `
      <p>This greeting card renders your name through a <strong>homemade template engine</strong>:
      it takes the string <code>Hello &lt;your name&gt;!</code> and evaluates anything inside
      <code>{{ }}</code> as code.</p>
      <p><strong>Escalation path:</strong> first prove evaluation works with <code>{{7*7}}</code>
      (you should see <strong>49</strong> in the greeting), then look for variables in scope and
      try <code>{{secretFlag}}</code>. The later labs add naive filters you must bypass, and the
      final lab turns the template engine into a real shell.</p>`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Nine flaws hide in the gadgets below. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSectionHtml}
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
