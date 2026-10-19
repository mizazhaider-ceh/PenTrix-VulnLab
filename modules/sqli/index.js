'use strict';
// SQL Injection module: eleven classic SQLi challenges against a product
// catalog backed by better-sqlite3, from a plain login bypass through
// second-order injection and filter bypasses.
const express = require('express');
const { fixCta, brief, difficultyPill, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner  } = require('../../lib/page');
const { captured } = require('../../lib/flags');

const challenges = [
  require('./challenges/login-bypass'),
  require('./challenges/union'),
  require('./challenges/blind'),
  require('./challenges/error'),
  require('./challenges/order-by'),
  require('./challenges/second-order'),
  require('./challenges/like-wildcard'),
  require('./challenges/limit-offset'),
  require('./challenges/groupby-having'),
  require('./challenges/union-filter-bypass'),
  require('./challenges/insert-inject'),
];

const router = express.Router();

// ---------- Module index ----------
router.get('/', (req, res) => {
  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="${esc(v.link)}">${esc(v.name)}</a> ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${captured(req, 'sqli', v.id) ? '<p><b>Flag captured.</b></p>' : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('\n');

  // M11 break-then-fix: per-challenge fix CTAs (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">You broke it. Now repair it. Fix mode hands you the vulnerable code, you write the patch, and the runner checks that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => `
        <article class="vuln-card fix-card">
          <h3>${esc(c.vuln.name)}</h3>
          ${fixCta('sqli', c.vuln.id)}
        </article>`).join('')}
    </section>`;
  res.send(page('SQL Injection', `
    ${brief('SQL Injection', 'This module targets a product catalog backed by SQLite. Eleven challenges walk you from a trivial login bypass through second-order injection, filter bypasses, and error-based extraction. Every flag is earned by a real query injection, never by guessing.')}
    ${trackBanner(module.exports)}
    <h2>Challenges</h2>
    ${cards}
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'sqli',
  name: 'SQL Injection',
  tagline: 'From login bypass to error-based extraction: eleven classic SQLi challenges.',
  description: 'An intentionally vulnerable product catalog and login backed by SQLite. Break string-interpolated queries, chain UNION SELECTs, build a boolean oracle, and provoke verbose database errors to capture the admin secret.',
  difficulty: 'Intermediate',
  track: 'Injection',
  prerequisites: ['Foundations track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
