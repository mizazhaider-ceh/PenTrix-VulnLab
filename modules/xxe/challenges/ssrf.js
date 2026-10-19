'use strict';
// SSRF via XXE: the same shared XML importer also fetches http:// external
// entities server-side, so pointing an entity at an internal URL makes the
// server request it and splice the response into the import result. This
// challenge shares the /import endpoint with the "XXE File Read" challenge
// (both map to the import page).
const express = require('express');
const { award } = require('../../../lib/flags');
const { appShell, esc, fixPanel, flagBox, page, payloadBlock } = require('../../../lib/page');
// Entity expander lives in the module shared file (copied verbatim from
// router.js by the finisher): expandEntities, with its helpers fetchUrl and
// resolveEntity. This file does not redeclare them.
const { expandEntities } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'ssrf',
  name: 'SSRF via XXE',
  difficulty: 'Hard',
  hint: "The same expander also fetches http:// URLs. Point an entity at the SSRF module's internal secret endpoint and chain it: XXE \u2192 SSRF \u2192 internal secret.",
  hints: [
    "Entities can have http:// URLs too. What happens when the parser fetches one?",
    "An external entity with SYSTEM \"http://127.0.0.1:PORT/...\" makes the server request that URL. It's SSRF via XML.",
    "Use <!ENTITY xxe SYSTEM \"http://127.0.0.1:PORT/xxe/internal\"> and reference &xxe;.",
  ],
  tools: 'C',
  how: 'Use an XML external entity with an http:// SYSTEM URI to make the server request an internal endpoint and leak its response.',
  link: '/xxe#ssrf',
  start: 'curl -s http://localhost:3000/xxe/import\ncurl -s --data-urlencode "xml=<data>hello</data>" http://localhost:3000/xxe/import',
};

// Fictional app chrome for the shared importer (neutral: no mention of flaws).
const APP_NAME = 'DataBridge Import Console';
const APP_NAV = ['Dashboard', 'Imports', 'Settings'];

// GET /xxe/import -> XML importer form (shared with the XXE File Read challenge).
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
