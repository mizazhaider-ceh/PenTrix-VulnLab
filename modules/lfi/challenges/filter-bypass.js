'use strict';
// Naive Filter Bypass: the download endpoint strips "../" exactly once, so a
// nested sequence like "....//" collapses back into "../" after the strip.
const express = require('express');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { SECRET_MARKER, docLinks, readTarget, showCaptured, docsPage } = require('../shared');

const router = express.Router();

// ---- v2: naive filter that strips "../" exactly once ----
router.get('/download', (req, res) => {
  const raw = req.query.file || '';
  // VULN: single-pass blacklist; stripping once can create new "../" sequences.
  const file = raw.replace('../', '');
  let body = `
    <p>Pick a document to download, or pass your own file name.
       Traversal sequences are filtered, so this one should be safe.</p>
    <form class="clay-card" method="get" action="/lfi/download">
      <div class="clay-field">
        <label for="lfi-download-file">File name</label>
        <input class="clay-input" type="text" id="lfi-download-file" name="file" placeholder="about.txt" value="${esc(raw)}">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Download</button>
    </form>
    <h2>Library</h2>
    ${docLinks('/lfi/download')}
    ${showCaptured(req, 'filter-bypass')}
  `;

  if (file) {
    const r = readTarget(file);
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      // Real success only: the secret shows while the post-filter file still
      // carries "..", i.e. the single-pass strip was actually bypassed
      // (....// collapses to ../). A plain ../secret.txt is stripped to a
      // plain in-docs name and must not award this challenge.
      if (r.data.includes(SECRET_MARKER) && file.includes('..')) {
        const flag = award(req, 'lfi', 'filter-bypass');
        body += flagBox(flag) + fixPanel('lfi', 'filter-bypass');
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Document Download', docsPage('Downloads', `<h1>Document Download</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'filter-bypass', name: 'Naive Filter Bypass', difficulty: 'Medium',
    hint: 'The download endpoint strips <code>../</code> only once. A filter that edits your input hands you a puzzle: what input survives its own edit as a working traversal?',
    hints: ["The filter strips ../ once. Send a normal download request to Burp Repeater first so you can iterate quickly, then watch exactly what a plain traversal becomes after the filter touches it.", "In Repeater, try a plain traversal and confirm it gets stripped. Then think recursively: the filter removes a pattern, so what happens when the pattern appears inside itself? Read the 'Contents of' line to see what the filter left behind.", "Shape: work out on paper what a single removal does to a pattern nested inside itself, then put the surviving string in the file parameter in Repeater and aim it at the docs folder."],
    tools: "BZ, B, C",
    est: 'about 10 to 20 minutes',
    how: 'A filter that deletes a pattern once can be beaten by input whose deleted form is the pattern itself.',
    link: '/lfi/download?file=about.txt',
    start: 'In Burp, open /lfi/download?file=about.txt, intercept the request in the Proxy, send it to Repeater, and watch how the file parameter changes after the filter.',
  },
  router,
};
