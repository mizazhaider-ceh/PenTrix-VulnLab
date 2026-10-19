'use strict';
// Language Parameter Traversal: the lang parameter is concatenated into a
// filesystem path with no validation, so it is just another filename input.
const express = require('express');
const path = require('path');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { docsDir, SECRET_MARKER, docsPage, showCaptured, readFileCapped } = require('../shared');

const router = express.Router();

// ---- v6: lang parameter traversal ----
router.get('/lang', (req, res) => {
  const lang = req.query.lang || 'en';
  // VULN: the lang parameter is concatenated into a filesystem path with no validation.
  const target = path.join(docsDir, 'lang', lang + '.txt');
  let body = `
    <p>Choose your language:</p>
    <form class="clay-card" method="get" action="/lfi/lang">
      <div class="clay-field">
        <label for="lfi-lang-select">Language</label>
        <select class="clay-select" id="lfi-lang-select" name="lang">
          <option value="en"${lang === 'en' ? ' selected' : ''}>English</option>
          <option value="fr"${lang === 'fr' ? ' selected' : ''}>Francais</option>
        </select>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Switch language</button>
    </form>
    ${showCaptured(req, 'lang')}
  `;
  try {
    const r = readFileCapped(target);
    if (!r.ok) throw new Error(r.error);
    const data = r.data;
    body += `<h2>Language file <code>${esc(lang)}</code></h2><pre>${esc(data)}</pre>`;
    // Real success only: the secret was reached through the lang parameter.
    if (data.includes(SECRET_MARKER) && lang.includes('..')) {
      const flag = award(req, 'lfi', 'lang');
      body += flagBox(flag) + fixPanel('lfi', 'lang');
    }
  } catch (e) {
    body += `<h2>Error reading language <code>${esc(lang)}</code></h2><pre>${esc(e.message)}</pre>`;
  }
  res.send(page('LFI - Language File', docsPage('Settings / Localized Viewer', `<h1>Localized Viewer</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'lang', name: 'Language Parameter Traversal', difficulty: 'Easy',
    hint: 'The <code>lang</code> parameter picks a file from <code>docs/lang/</code> with no validation. It is just another filename: climb one level and name the secret.',
    hints: ["The language parameter picks a file. Is it validated?", "The lang parameter is another file path. Traversal works there too.", "The lang parameter picks a file from docs/lang/ with no validation. Climb out of that folder and name the secret the same way you would in the main viewer."],
    tools: "B, C",
    how: 'Traverse out of docs/lang/ via the lang parameter on /lfi/lang.',
    link: '/lfi/lang?lang=en',
    start: 'curl "http://localhost:3000/lfi/lang?lang=en"',
  },
  router,
};
