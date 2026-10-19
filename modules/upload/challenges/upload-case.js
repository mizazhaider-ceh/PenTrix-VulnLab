'use strict';
// Case-sensitive blacklist bypass: POST /upload/ext-blacklist blocks ".svg",
// ".html" and ".htm" by exact case-sensitive match on the final extension, so
// "evil.SVG" passes the check and is still served as active content.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { esc, fixPanel, flagBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
// Module-level upload plumbing (provided by modules/upload/shared.js):
// rawUpload (express.raw), cleanFilename, UPLOADS_DIR.
const { rawUpload, cleanFilename, UPLOADS_DIR } = require('../shared');

const router = express.Router();

// ---- v3: SVG/HTML extension blacklist (case-sensitive, final extension only) ----
const EXT_BLACKLIST = ['.svg', '.html', '.htm'];

router.post('/ext-blacklist', rawUpload, (req, res) => {
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Missing or invalid <code>?filename=</code> query parameter. Allowed characters: <code>a-z A-Z 0-9 . _ -</code></p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  const ext = path.extname(clean); // deliberately NOT lowercased
  // VULN: the blacklist compares the raw case-sensitive final extension
  // only. "evil.SVG" dodges the ".svg" entry, and "shell.svg.jpg" has a
  // final extension of ".jpg", while the file is still served as SVG/HTML
  // by /upload/view/:name below.
  if (EXT_BLACKLIST.includes(ext)) {
    return res.status(400).send(page('Blocked', `<h2>Blocked</h2><p>The extension <code>${esc(ext)}</code> is blacklisted. Try a different name.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received. Upload the file bytes as the raw request body.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const viewUrl = '/upload/view/' + encodeURIComponent(clean);
  let flagHtml = '';
  if (['.svg', '.html', '.htm'].includes(ext.toLowerCase())) {
    // VULN: case-sensitive blacklist bypassed , ".SVG" is still SVG.
    flagHtml += flagBox(award(req, 'upload', 'upload-case')) + fixPanel('upload', 'upload-case') + `<p class="dim">Case bypass: <code>${esc(clean)}</code> was stored and is served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  }
  if (/\.(svg|html?)\./i.test(clean)) {
    // VULN: double extension , the final ".jpg" passed, but the file is
    // served as SVG/HTML because of the earlier extension.
    // NOTE: this route is shared with the upload-double-ext challenge (a
    // sibling challenge file); the handler is kept identical so both flags
    // behave exactly as in router.js. The finisher dedupes the route.
    flagHtml += flagBox(award(req, 'upload', 'upload-double-ext')) + fixPanel('upload', 'upload-double-ext') + `<p class="dim">Double extension bypass: <code>${esc(clean)}</code> passed as <code>${esc(ext)}</code> but is served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  }
  if (!flagHtml) flagHtml = `<p class="dim">Stored. Neither a case variant nor a double extension was used, so nothing was bypassed.</p>`;
  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> , view it at <a href="${viewUrl}">${viewUrl}</a></p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

module.exports = {
  vuln: {
    id: 'upload-case',
    name: 'Case-sensitive blacklist bypass',
    difficulty: 'Easy',
    hint: 'The v3 blacklist compares the extension exactly as written. Filesystems and browsers do not care about case.',
    hints: [
      "The blacklist has '.svg' but the check is case-sensitive. What about '.SVG'?",
      "Path.extname returns the case as-is. '.SVG' !== '.svg', so it passes, but the file is still served as SVG.",
      "KEY INSIGHT: a case-sensitive check can be beaten by changing the case of the blocked extension, since the viewer still recognises it as SVG. Upload a file whose extension is a case-variant of the blacklisted one, carrying SVG plus script, to the ext-blacklist endpoint.",
    ],
    tools: "C",
    how: 'Upload evil.SVG (uppercase) to POST /upload/ext-blacklist?filename=... so the ".svg" entry misses it.',
    link: '/upload#upload-case',
    start: 'curl --data-binary @evil.SVG "http://localhost:3000/upload/ext-blacklist?filename=evil.SVG"',
  },
  router,
};
