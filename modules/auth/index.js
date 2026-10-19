'use strict';
// Broken Authentication: eight intentionally exploitable login, reset and session flaws.
const express = require('express');
const { fixCta,
  brief, esc, difficultyPill, fixPanel, flagBox, hintLadder, page, payloadBlock, toolsPill, trackBanner,
 } = require('../../lib/page');
const { captured, flagFor } = require('../../lib/flags');
const shared = require('./shared');

const challenges = [
  require('./challenges/brute-force'),
  require('./challenges/reset'),
  require('./challenges/user-enum'),
  require('./challenges/otp-bruteforce'),
  require('./challenges/reset-predictable'),
  require('./challenges/security-question'),
  require('./challenges/change-pass-noverify'),
  require('./challenges/support-impersonate'),
];

const router = express.Router();

// GET /auth -> module index page: every challenge card links to its entry page.
router.get('/', (req, res) => {
  const me = shared.authSessionUser(req);
  const cards = challenges.map(({ vuln: v }) => {
    const flag = captured(req, 'auth', v.id)
      ? flagBox(flagFor('auth', v.id)) + fixPanel('auth', v.id)
      : '';
    return `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${flag}
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(v.link)}">Open challenge</a></p>
    </article>`;
  }).join('');

  const rows = challenges.map(({ vuln: v }) =>
    `<tr><th scope="row"><a href="#${esc(v.id)}">${esc(v.name)}</a></th><td>${difficultyPill(v.difficulty)}</td><td><a href="${esc(v.link)}">${esc(v.link)}</a></td></tr>`
  ).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('auth', c.vuln.id)).join('')}
    </section>`;
  res.send(page('Broken Authentication', `
    ${brief('Broken Authentication', `
      Northwind Accounts is a small fictional product with weak sign-in, reset
      and recovery flows. Each challenge below is its own page with a form you
      can attack directly. The lab remembers who you are signed in as across
      challenges (currently <b>${me ? esc(me) : 'nobody'}</b>).`)}
    ${trackBanner(module.exports)}

    <h2>Entry points</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">Broken Authentication challenges and their entry pages</caption>
      <thead><tr><th scope="col">Challenge</th><th scope="col">Difficulty</th><th scope="col">Entry page</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>

    <h2>Challenges</h2>
    <p>Each card has a hint ladder: level 1 nudges, level 2 teaches the
    technique, level 3 shows the shape of the attack. Flags appear on the page
    where you succeed.</p>
    ${cards}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/">Back to all modules</a></p>
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'auth',
  name: 'Broken Authentication',
  tagline: 'No lockouts, predictable resets, and OTPs anyone can brute-force.',
  description:
    'Authentication the way it happens when nobody threat-models: a login page that lets you guess forever, password reset tokens anyone can predict, and one-time codes with no lockout.',
  difficulty: 'Intermediate',
  track: 'Auth and Sessions',
  prerequisites: ['Foundations track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
