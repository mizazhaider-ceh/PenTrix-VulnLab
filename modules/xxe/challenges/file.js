'use strict';
// XXE File Read: the shared XML importer expands external entities with no
// allowlist, so a SYSTEM "file://..." entity makes the server read a local
// file into the import result. This challenge shares the /import endpoint
// with the "SSRF via XXE" challenge (both map to the import page).
const express = require('express');
const { award } = require('../../../lib/flags');
const { appShell, esc, fixPanel, flagBox, page, payloadBlock } = require('../../../lib/page');
// Entity expander lives in the module shared file (copied verbatim from
// router.js by the finisher): expandEntities, with its helpers fetchUrl and
// resolveEntity. This file does not redeclare them.
const { expandEntities } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'file',
  name: 'XXE File Read',
  difficulty: 'Medium',
  hint: "Declare an external entity with a file:// URI pointing at the module's secret.txt (absolute path), then reference &name; inside <data>.",
  hints: [
    "The app parses your XML. Does it resolve external entities?",
    "Proxy the importer in Burp and send the POST to Repeater. A DOCTYPE can declare a general entity whose SYSTEM identifier is a local file URI, and the parser reads that file and substitutes the entity reference wherever it appears in the output.",
    "Your DOCTYPE must declare an external file-reading entity, then plant the entity reference where the import result renders. Key insight: the file path must be absolute, and the success response shows you exactly where injected content echoes back. In Repeater, change only the xml form field, submit, and find that echo location first, then aim the reference there.",
  ],
  tools: 'BZ, B, C',
  how: 'In Repeater, inject an XML external entity (SYSTEM "file://...") and get the server to read a local file into the import result.',
  link: '/xxe#file',
  start: 'Open Burp, proxy your browser to it, and visit the XML importer at /xxe/import. Submit the form once with plain XML like <data>hello</data>, send that POST to Repeater, then replace only the xml form field with your DOCTYPE payload and submit again.',
};

// Fictional app chrome for the shared importer (neutral: no mention of flaws).
const APP_NAME = 'DataBridge Import Console';
const APP_NAV = ['Dashboard', 'Imports', 'Settings'];

// GET /xxe/import -> XML importer form (shared with the SSRF via XXE challenge).
router.get('/import', (req, res) => {
  const body = appShell(APP_NAME, `
    <h2>XML Importer</h2>
    <p class="dim">Paste XML below. External entities are expanded server-side before the import runs.</p>
    <form method="POST" action="/xxe/import" class="clay-card">
      <div class="clay-field">
        <label for="xml">XML document</label>
        <textarea id="xml" name="xml" rows="12" placeholder="&lt;data&gt;hello&lt;/data&gt;"></textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Import XML</button>
    </form>`, { nav: APP_NAV, mark: '🗂', crumb: 'Imports / New import' });
  res.send(page('XML Importer', body));
});

// POST /xxe/import -> expand entities, show <data> content, award on markers.
router.post('/import', async (req, res) => {
  const xml = req.body.xml || '';
  // VULN: external entities (file:// and http://) are expanded with no allowlist.
  const expanded = await expandEntities(xml);

  // Show the text content of <data>...</data> if present, else the whole expanded XML.
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;

  let flags = '';
  // VULN: success of the attack is measured on the raw expanded output.
  if (expanded.includes('XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'file'));
    flags += fixPanel('xxe', 'file');
  }
  if (expanded.includes('SSRF-INTERNAL-9921')) {
    flags += flagBox(award(req, 'xxe', 'ssrf'));
    flags += fixPanel('xxe', 'ssrf');
  }

  const body = appShell(APP_NAME, `
    <h2>Import result</h2>
    ${flags}
    <h3>Parsed content</h3>
    ${payloadBlock('Parsed content', shown)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe/import">&larr; Import more XML</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to module</a></p>`,
    { nav: APP_NAV, mark: '🗂', crumb: 'Imports / Result' });
  res.send(page('Import result', body));
});

module.exports = { vuln, router };
