'use strict';
// Path traversal on write: POST /traverse joins the ?filename= value straight
// onto the uploads directory with no basename or containment check, so
// "../" segments escape the directory. GET /traversed reads back with the
// same missing check, so escaped files are retrievable.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { appShell, esc, fixPanel, flagBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

// NOTE (for the module finisher): this challenge relies on the module-level
// raw body parser express.raw({ type: '*/*', limit: '2mb' }) being applied to
// the POST route before this router is mounted, plus the router-level 413
// handler for the body limit. UPLOADS_DIR resolves to the same project-root
// uploads/ dir as router.js.
const UPLOADS_DIR = path.join(__dirname, '..', '..', '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const backToModule = '<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to module</a></p>';

function dropbox(title, bodyHtml) {
  return page(title, appShell('FileDrop', bodyHtml, { mark: '⤓', nav: ['Dropbox', 'Shared', 'Account'], crumb: 'FileDrop / Shared dropbox' }));
}

// POST /traverse -> store the raw request body under the given filename.
router.post('/traverse', (req, res) => {
  const raw = String(req.query.filename || '');
  if (!raw || raw === '.' || raw === '..') {
    return res.status(400).send(dropbox('Upload failed', `
      <h2>Upload failed</h2>
      <p class="dim">Give your file a name with <code>?filename=</code>. The dropbox stores it under exactly that name.</p>
      ${backToModule}`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(dropbox('Upload failed', `
      <h2>Empty file</h2>
      <p class="dim">No request body received. Send the file bytes as the raw request body.</p>
      ${backToModule}`));
  }
  // VULN: the filename is joined to the uploads dir with no basename or
  // containment check, so "../" segments escape the uploads directory.
  const target = path.normalize(path.join(UPLOADS_DIR, raw));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, req.body);
  const outside = !target.startsWith(UPLOADS_DIR + path.sep);
  let flagHtml = '';
  if (outside && fs.existsSync(target)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-traversal')) + fixPanel('upload', 'upload-traversal') + `<p class="dim">That name resolved outside the dropbox folder. Read it back at <a href="/upload/traversed?f=${encodeURIComponent(raw)}"><code>/upload/traversed?f=${esc(raw)}</code></a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored inside the dropbox folder. To land somewhere else, the filename must resolve outside of it.</p>`;
  }
  res.send(dropbox('Uploaded', `
    <h2>File stored</h2>
    <p>Saved as <code>${esc(raw)}</code>.</p>
    ${flagHtml}
    ${backToModule}`));
});

// GET /traversed -> retrieval surface for the traversal lab: reads relative to
// the uploads dir with the same missing containment check.
router.get('/traversed', (req, res) => {
  const f = String(req.query.f || '');
  // VULN: same missing containment check on read, so escaped files are retrievable.
  let target;
  try {
    target = path.normalize(path.join(UPLOADS_DIR, f));
    if (!f || !fs.existsSync(target) || !fs.statSync(target).isFile()) throw new Error('nope');
  } catch (e) {
    return res.status(404).send(dropbox('Not found', `
      <h2>Not found</h2>
      <p class="dim">No stored file matches that name.</p>
      ${backToModule}`));
  }
  res.type('text/plain');
  res.send(fs.readFileSync(target));
});

module.exports = {
  vuln: {
    id: 'upload-traversal',
    name: 'Path traversal on write',
    difficulty: 'Medium',
    hint: 'v7 joins your filename to the uploads dir with no basename or containment check. Where does "../pwn.txt" resolve?',
    hints: [
      'The filename is joined to the uploads directory. Is there a basename check?',
      'No. A filename like ../pwn.txt escapes the uploads dir and writes elsewhere.',
      'Upload to /upload/traverse?filename=../pwn.txt, then read it via /upload/traversed?f=../pwn.txt.',
    ],
    tools: 'C',
    how: 'Upload to POST /upload/traverse?filename=../pwn.txt so the file lands outside the uploads dir, then read it back via /upload/traversed?f=../pwn.txt.',
    link: '/upload#upload-traversal',
    start: 'curl --data-binary @pwn.txt "http://localhost:3000/upload/traverse?filename=../pwn.txt"\ncurl "http://localhost:3000/upload/traversed?f=../pwn.txt"',
  },
  router,
};
