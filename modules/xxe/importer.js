'use strict';
// XXE module: the shared XML importer endpoint (GET/POST /xxe/import).
//
// The "XXE File Read" and "SSRF via XXE" challenges share this one console:
// the same entity expansion reads local files (file://) and fetches internal
// URLs (http://) server-side. The route used to be copy-pasted into both
// challenge files, so the second copy was silently shadowed (Express runs
// only the first matching handler) and free to rot. It lives here exactly
// once now, owned by the file.js challenge entry; ssrf.js keeps no routes.
const express = require('express');
const { award } = require('../../lib/flags');
const { appShell, fixPanel, flagBox, page, payloadBlock } = require('../../lib/page');
// Entity expander lives in the module shared file: expandEntities, with its
// helpers fetchUrl and resolveEntity.
const { expandEntities, markerProven } = require('./shared');

const router = express.Router();

// Fictional app chrome for the shared importer (neutral: no mention of flaws).
const APP_NAME = 'DataBridge Import Console';
const APP_NAV = ['Dashboard', 'Imports', 'Settings'];

// GET /xxe/import -> XML importer form (shared by the file-read and SSRF challenges).
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

// POST /xxe/import -> expand entities, show <data> content, award only on
// proof of real entity resolution (marker in the expanded output, absent
// from the raw input, with an entity declaration in the submission).
router.post('/import', async (req, res) => {
  const xml = req.body.xml || '';
  // VULN: external entities (file:// and http://) are expanded with no allowlist.
  const expanded = await expandEntities(xml);

  // Show the text content of <data>...</data> if present, else the whole expanded XML.
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;

  let flags = '';
  if (markerProven(xml, expanded, 'XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'file'));
    flags += fixPanel('xxe', 'file');
  }
  if (markerProven(xml, expanded, 'SSRF-INTERNAL-9921')) {
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

module.exports = router;
