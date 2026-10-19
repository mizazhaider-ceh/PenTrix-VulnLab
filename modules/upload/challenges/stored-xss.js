'use strict';
// Stored XSS via file upload (upload/stored-xss): the plain upload endpoint
// POST /upload?filename= stores the raw request bytes with no content
// validation, and /uploads serves .html/.svg files inline, so embedded
// JavaScript runs in the browser of whoever opens the stored file.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { appShell, esc, flagBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

// ---------------------------------------------------------------------------
// MODULE-LEVEL DEPENDENCIES (provided by the finisher in
// modules/upload/index.js / shared.js; NOT defined or required here):
//   1. Binary body parsing: the finisher applies
//      express.raw({ type: '*/*', limit: '2mb' }) to the module router BEFORE
//      mounting this challenge router, so req.body is a Buffer on the POST
//      route below (in router.js every upload POST used this rawUpload
//      middleware; applying it at module level is behavior-identical).
//   2. req.uploadShared = { dir, clean }, attached by finisher middleware:
//        dir   : absolute path of the project-root uploads/ directory
//                (created at module load; served inline by app.js at /uploads)
//        clean : cleanFilename(name): strip directories, allow only the
//                characters [a-zA-Z0-9._-], reject '.' and '..', return null
//                for anything else.
// ---------------------------------------------------------------------------
function uploadShared(req) {
  return req.uploadShared || {};
}

// Fictional app chrome for this lab: PixelDrop, a tiny file-drop service.
function dropPage(title, bodyHtml) {
  return page(title, appShell('PixelDrop', bodyHtml, {
    nav: ['Upload', 'Gallery', 'Account'],
    crumb: 'File drop',
    mark: '📤',
  }));
}

function backBtn() {
  return '<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to module</a></p>';
}

// POST /upload?filename= : plain upload, no content validation (v1).
router.post('/', (req, res) => {
  const { dir: UPLOADS_DIR, clean: cleanFilename } = uploadShared(req);
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(dropPage('Upload failed',
      `<div class="clay-card"><div class="card-top"><b>Upload failed</b></div>
      <p class="dim">Missing or invalid <code>?filename=</code> query parameter. Allowed characters: <code>a-z A-Z 0-9 . _ -</code></p>
      ${backBtn()}</div>`));
  }
  const ext = path.extname(clean).toLowerCase();

  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(dropPage('Upload failed',
      `<div class="clay-card"><div class="card-top"><b>Empty file</b></div>
      <p class="dim">No request body received. Upload the file bytes as the raw request body.</p>
      ${backBtn()}</div>`));
  }

  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const url = '/uploads/' + encodeURIComponent(clean);

  let flagHtml = '';
  // v1: .html/.svg stored as-is and served inline -> stored XSS when visited
  if (ext === '.html' || ext === '.svg') {
    // VULN: uploaded HTML/SVG is never sanitized, and /uploads serves it inline,
    // so visiting the stored file executes the attacker's script (stored XSS).
    const flag = award(req, 'upload', 'stored-xss');
    flagHtml = flagBox(flag) + `<p class="dim">Stored XSS captured: your file is served inline at <a href="${url}">${url}</a> , open it to see the payload run.</p>`;
  }

  res.send(dropPage('Uploaded',
    `<div class="clay-card"><div class="card-top"><b>File stored</b><span class="clay-pill">v1 plain upload</span></div>
    <p>Saved as <code>${esc(clean)}</code> , served at <a href="${url}">${url}</a></p>
    ${flagHtml}
    ${backBtn()}</div>`));
});

module.exports = {
  vuln: {
    id: 'stored-xss',
    name: 'Stored XSS via file upload',
    difficulty: 'Easy',
    hint: 'The server accepts .html and .svg files and serves them inline, unchanged. What happens when a browser renders a file you control?',
    hints: [
      'You can upload HTML files and they are served back. With what Content-Type?',
      'Uploaded HTML/SVG is served inline (not as a download). Your script runs when the file is opened.',
      'Upload an HTML file with <script>alert(1)</script>, then open its /uploads/ link.',
    ],
    tools: 'B, C',
    how: 'Upload an .html or .svg file containing JavaScript to POST /upload?filename=..., then open its /uploads/ link.',
    link: '/upload#stored-xss',
    start: 'curl --data-binary @evil.html "http://localhost:3000/upload?filename=evil.html"',
  },
  router,
};
