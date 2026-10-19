'use strict';
// PenTrix VulnLab module: Client-Side Template Injection (csti)
// The server stores templates; the browser evaluates them with a deliberately
// naive {{ expression }} interpolator built on Function. Five labs: basic
// evaluation, a blacklist bypass via an alternative delimiter, reaching
// Function through the exposed constructor, CSTI inside an HTML attribute,
// and a stored template evaluated on every view. Local lab use only.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { fixCta, brief, esc, flagBox, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const challenges = [
  require('./challenges/basic'),
  require('./challenges/filter-bypass'),
  require('./challenges/constructor'),
  require('./challenges/attr'),
  require('./challenges/stored'),
];

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

const VULN_IDS = ['basic', 'filter-bypass', 'constructor', 'attr', 'stored'];

const db = getDb();
db.exec('CREATE TABLE IF NOT EXISTS csti_profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)');
if (db.prepare('SELECT COUNT(*) AS c FROM csti_profiles').get().c === 0) {
  db.prepare('INSERT INTO csti_profiles (name) VALUES (?)').run('alice');
}

// ---------------------------------------------------------------------------
// Per-session, per-vuln token issued when the lab page loads and rendered into
// the page as CSTI_NONCE. The beacon must echo it back, so only a template
// that really evaluated in the page (or a client that loaded the page) can
// claim the flag. Single-use: consumed on award. A bare curl of the beacon
// with no page load earns no flag.
// ---------------------------------------------------------------------------
function cstiConsumeNonce(req, v, n) {
  const m = req.session.cstiNonce;
  // hasOwnProperty: one lab is literally named 'constructor', which exists on
  // Object.prototype - a plain truthiness check would return the Object
  // function instead of the issued token.
  const cur = m && Object.prototype.hasOwnProperty.call(m, v) ? m[v] : null;
  const ok = !!cur && cur === n && n.length > 0;
  if (ok) delete m[v]; // single-use
  return ok;
}

// ---------------------------------------------------------------------------
// Flag capture beacon. The victim page's own JavaScript fires it once the
// template actually evaluated (labs 1, 2, 4, 5 auto-beacon when the rendered
// output contains the attacker's expected result; lab 3's payload beacons
// manually after achieving code execution). Every beacon must also echo the
// page-bound token.
// ---------------------------------------------------------------------------
// Claim-status for the live widget. Returns whether the flag is captured.
router.get('/claim-status', (req, res) => {
  const v = (req.query.v || '').toString();
  if (!VULN_IDS.includes(v)) return res.status(400).json({ error: 'unknown vuln' });
  res.json({ captured: captured(req, 'csti', v) });
});

router.get('/beacon', (req, res) => {
  const v = String(req.query.v || '');
  const d = String(req.query.d || '');
  const n = String(req.query.n || '');
  let ok = false;
  if (VULN_IDS.includes(v)) {
    ok = (v === 'constructor') ? d.length > 0 : d === '49';
    ok = ok && cstiConsumeNonce(req, v, n);
  }
  if (ok) {
    const flag = award(req, 'csti', v);
    return res.send(page('Template executed', `
      <h2>Template executed</h2>
      <p>The client-side template engine evaluated attacker input for vuln
      <b>${esc(v)}</b>.</p>
      ${flagBox(flag)}
      <p><a href="/csti">Back to the CSTI module</a></p>
    `));
  }
  res.status(400).send(page('Beacon', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when the template engine really evaluated
    your expression (<code>v</code> = basic, filter-bypass, constructor, attr, or stored,
    with the expected result data) <b>and</b> the beacon echoes the page-bound token
    (<code>n</code> = <code>CSTI_NONCE</code> rendered into the lab page). Work through
    the lab page in your browser.</p>
    <p><a href="/csti">Back to the CSTI module</a></p>
  `));
});

for (const c of challenges) router.use(c.router);

// GET /csti -> module index page.
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
      ${challenges.map((c) => fixCta('csti', c.vuln.id)).join('')}
    </section>`;
  res.send(page('Client-Side Template Injection', `
    ${brief('Module briefing', `
      <p><b>CSTI in 30 seconds:</b> some apps let the <i>browser</i> evaluate templates with a
      JavaScript engine instead of rendering them on the server. If that engine runs user input
      through <code>Function</code> (or <code>eval</code>), every <code>{{ expression }}</code>
      is live JavaScript in the victim's browser.</p>
      <p><b>The engine in this module</b> (view source on any lab page) replaces
      <code>{{ ... }}</code> and <code>[[ ... ]]</code> by compiling the inside with
      <code>Function</code> and exposing <code>constructor</code> (which is <code>Object</code>)
      to every expression. The server only <i>stores</i> your template; the browser does the
      evaluating. Each lab page beacons <code>/csti/beacon</code> once your expression really
      evaluates: <code>v</code> names the lab, <code>d</code> carries the evaluated result
      (<code>49</code>, or any data for the constructor breakout), and <code>n</code> echoes the
      one-time <code>CSTI_NONCE</code> token rendered into the page.</p>`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Five labs hide in the pages below. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSectionHtml}
`));
});

module.exports = {
  id: 'csti',
  name: 'Client-Side Template Injection',
  tagline: 'Your template engine runs whatever the user types.',
  description: 'A deliberately naive client-side {{ expression }} interpolator built on Function. Five labs: basic evaluation, a blacklist bypass through an alternative delimiter, breaking out to code execution via constructor.constructor, CSTI inside an HTML attribute, and a stored template evaluated on every view.',
  difficulty: 'Intermediate',
  track: 'Injection',
  prerequisites: ['xss', 'ssti'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
