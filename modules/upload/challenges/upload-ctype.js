'use strict';
// Content-Type header spoofing: POST /upload/mime-check "validates" uploads by
// reading only the client-supplied Content-Type request header, never the file
// bytes, so an .html file with "Content-Type: image/png" is accepted.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { esc, fixPanel, flagBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
// Module-level upload plumbing (provided by modules/upload/shared.js):
// rawUpload (express.raw), cleanFilename, UPLOADS_DIR.
const { rawUpload, cleanFilename, UPLOADS_DIR } = require('../shared');

const router = express.Router();

// ---- v4: Content-Type header "validation" ----
router.post('/mime-check', rawUpload, (req, res) => {
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Missing or invalid <code>?filename=</code> query parameter.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  const ctype = String(req.get('content-type') || '');
  // VULN: the only "validation" is the client-supplied Content-Type header;
  // the file bytes are never inspected, so the header can simply be lied about.
  if (!ctype.toLowerCase().startsWith('image/')) {
    return res.status(400).send(page('Blocked', `<h2>Blocked</h2><p>Only images may be uploaded (detected via the <code>Content-Type</code> header: <code>${esc(ctype) || '(none)'}</code>).</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const ext = path.extname(clean).toLowerCase();
  const viewUrl = '/upload/view/' + encodeURIComponent(clean);
  let flagHtml = '';
  if (['.html', '.htm', '.svg'].includes(ext)) {
    // VULN: the header claimed image/*, so an HTML/SVG file was accepted and
    // stored; it is served back as active content.
    flagHtml = flagBox(award(req, 'upload', 'upload-ctype')) + fixPanel('upload', 'upload-ctype') + `<p class="dim">Header spoofed: <code>${esc(clean)}</code> was accepted as <code>${esc(ctype)}</code> and is served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored as an image. To beat this check, the filename must still end in <code>.html</code> or <code>.svg</code>.</p>`;
  }
  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> with Content-Type <code>${esc(ctype)}</code>.</p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

module.exports = {
  vuln: {
    id: 'upload-ctype',
    name: 'Content-Type header spoofing',
    difficulty: 'Easy',
    hint: 'v4 decides "is this an image" from the Content-Type request header alone. Headers are attacker-controlled.',
    hints: [
      "The uploader checks the Content-Type header. Who sets that header?",
      "You do. It's just a request header. Send an HTML file with Content-Type: image/png.",
      "KEY INSIGHT: the Content-Type header is attacker-controlled, so the real file type is never inspected. Upload an HTML file to the mime-check endpoint while setting the header to the image value the checker expects.",
    ],
    tools: "C",
    how: 'Upload an .html file to POST /upload/mime-check?filename=... with -H "Content-Type: image/png".',
    link: '/upload#upload-ctype',
    start: 'curl --data-binary @evil.html -H "Content-Type: image/png" "http://localhost:3000/upload/mime-check?filename=evil.html"',
  },
  router,
};
