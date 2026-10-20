'use strict';
// Session Management (session): six session-layer flaws: fixation (pre-login
// sid kept), logout that never kills the server-side session, sequential
// predictable session ids, sid in the URL leaking through a proxy log, sessions
// that never expire, and session ids leaking through a verbose debug log.
const express = require('express');
const { brief, difficultyPill, esc, hintLadder, page, toolsPill, trackBanner, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/fixation'),
  require('./challenges/logout'),
  require('./challenges/predictable'),
  require('./challenges/url'),
  require('./challenges/never-expires'),
  require('./challenges/log-leak'),
];

const router = express.Router();

// Router-scoped form parsing only (app-level middleware is out of scope).
// The challenge routers serve HTML forms, so form bodies must parse here.
router.use(express.urlencoded({ extended: false }));

// GET /session -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('session', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'session', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Session Management', `
    ${brief('Session Management', `
      <p><b>What is session management?</b> After you log in, the server hands your
      browser a session id (usually a cookie). Every later request carries that id,
      and the server trusts it as proof of who you are.</p>
      <p><b>The goal in this module:</b> break that trust. Each challenge gives you a
      login and a flawed session mechanism; your job is to end up holding a session
      the server believes belongs to <b>admin</b>. Work in Burp Repeater, where you
      can set the <code>lab_sid</code> cookie on each request by hand.</p>
      <p>All labs use the cookie name <code>lab_sid</code>, but each lab keeps its
      own session store.</p>`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Six ways login state breaks. Each challenge card has a hint ladder: level 1
    nudges, level 2 teaches the technique, level 3 shows the payload shape.</p>
    ${cards}
  ${fixSection('session', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'session',
  name: 'Session Management',
  tagline: 'Fixate, predict, steal, and replay sessions: six ways login state breaks.',
  description: 'Authentication does not end at the login form. These six labs attack the session layer itself: fixation, broken logout, predictable ids, ids in URLs and logs, and sessions that never die.',
  difficulty: 'Intermediate',
  track: 'Auth and Sessions',
  prerequisites: ['auth'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
