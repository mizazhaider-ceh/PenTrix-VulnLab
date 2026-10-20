'use strict';
// postMessage Flaws: intentionally vulnerable postMessage training targets.
const express = require('express');
const { brief, esc, flagBox, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const challenges = [
  require('./challenges/no-check'),
  require('./challenges/wildcard'),
  require('./challenges/data-xss'),
  require('./challenges/substring'),
  require('./challenges/csrf-action'),
];

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

const VULN_IDS = ['no-check', 'wildcard', 'data-xss', 'substring', 'csrf-action'];

// ---------------------------------------------------------------------------
// Module-level routes: these belong to the module as a whole, not to a single
// challenge. The victim pages' JavaScript calls them from inside the browser.
// ---------------------------------------------------------------------------

// GET /postmsg/claim-status -> claim-status for the live claim widgets on
// the attacker pages.
router.get('/claim-status', (req, res) => {
  const v = (req.query.v || '').toString();
  if (!VULN_IDS.includes(v)) return res.status(400).json({ error: 'unknown vuln' });
  res.json({ captured: captured(req, 'postmsg', v) });
});

// GET /postmsg/beacon -> flag capture beacon. Awards only when the victim
// page's own JavaScript fired with lab-specific data: every victim handler
// prefixes its beacon payload, and two labs additionally require real lab
// state (the exfiltrated secret, the deleted account). The prefix-match
// labs, csrf-action included, additionally require the page-bound token:
// csrf-action also requires that the deletion in this session was driven
// by the victim page's script (its delete request presented the same
// token), so a bare delete plus a bare beacon call earns nothing.
router.get('/beacon', (req, res) => {
  const v = String(req.query.v || '');
  const d = String(req.query.d || '');
  let ok = false;
  if (VULN_IDS.includes(v) && d) {
    if (v === 'wildcard') {
      ok = !!req.session.pm_secret && d.includes(req.session.pm_secret);
    } else {
      // Bound to the victim page: the beacon must echo the one-time token the
      // victim page rendered when it loaded in this session.
      const n = String(req.query.n || '');
      const m = req.session.pmNonce;
      const cur = m && Object.prototype.hasOwnProperty.call(m, v) ? m[v] : null;
      ok = d.startsWith(v + ':') && !!cur && cur === n;
      if (ok && v === 'csrf-action') {
        ok = req.session.pm_deleted === true && req.session.pm_msg_deleted === true;
      }
      if (ok) delete m[v]; // single-use
    }
  }
  if (ok) {
    const flag = award(req, 'postmsg', v);
    return res.send(page('Exploit confirmed', `
      <h2>Exploit confirmed</h2>
      <p>The victim page's message handler fired with attacker-controlled data
      for vuln <b>${esc(v)}</b>.</p>
      ${flagBox(flag)}
      <p><a href="/postmsg">Back to the postMessage module</a></p>
    `));
  }
  res.status(400).send(page('Beacon', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when the victim page's JavaScript fires it
    with the expected payload (<code>v</code> = no-check, wildcard, data-xss,
    substring, or csrf-action, plus lab-specific data). Open a lab's attacker page
    in your browser and fire the payload from there.</p>
    <p><a href="/postmsg">Back to the postMessage module</a></p>
  `));
});

// GET /postmsg -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('postmsg', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'postmsg', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('postMessage Flaws', `
    ${brief('postMessage Flaws', `
      <p><b>postMessage in 30 seconds:</b> web pages can send each other messages with
      <code>window.postMessage(data, targetOrigin)</code>, and receive them with a
      <code>message</code> event listener. The receiver is supposed to verify
      <code>event.origin</code> before acting on the data, and the sender is supposed to
      name a specific <code>targetOrigin</code> instead of <code>'*'</code>.</p>
      <p><b>The pattern in this module:</b> each lab has a <b>victim page</b> with a broken
      message handler and an <b>attacker page</b> that drives it. When the flaw triggers,
      the victim page itself calls <code>/postmsg/beacon?v=&lt;lab&gt;&amp;d=...</code>,
      which awards the flag. Open each attacker page in your browser and fire the payload
      from there.</p>`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Five flaws hide in the postMessage labs above. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSection('postmsg', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'postmsg',
  name: 'postMessage Flaws',
  tagline: 'Missing origin checks turn postMessage into a remote control.',
  description: 'Five labs on the postMessage API: a handler with no origin check, a secret leaked via wildcard targetOrigin, unsanitized message data rendered as HTML, a naive substring origin check, and a privileged action driven by forged messages. Each lab pairs a victim page with an in-lab attacker page.',
  difficulty: 'Intermediate',
  track: 'Advanced',
  prerequisites: ['xss', 'cors'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
