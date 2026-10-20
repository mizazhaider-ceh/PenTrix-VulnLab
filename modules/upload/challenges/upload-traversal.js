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
const crypto = require('crypto');

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
  // Writing outside arms the proof only; the flag fires when the escaped
  // file is read back through GET /upload/traverse-prove, proving the write
  // really landed outside the dropbox folder.
  let flagHtml = '';
  if (outside && fs.existsSync(target)) {
    req.session = req.session || {};
    req.session.uploadTravPending = {
      name: raw,
      sha: crypto.createHash('sha256').update(req.body).digest('hex'),
      at: Date.now(),
    };
    flagHtml = `<p class="dim">That name resolved outside the dropbox folder. Prove it by reading the file back through <a href="/upload/traverse-prove?f=${encodeURIComponent(raw)}"><code>/upload/traverse-prove?f=${esc(raw)}</code></a>: the flag fires when the escaped file is actually served back.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored inside the dropbox folder. To land somewhere else, the filename must resolve outside of it.</p>`;
  }
  res.send(dropbox('Uploaded', `
    <h2>File stored</h2>
    <p>Saved as <code>${esc(raw)}</code>.</p>
    ${flagHtml}
    ${backToModule}`));
});

// GET /traverse-prove -> awards only when the escaped file recorded at
// upload time is read back, byte-identical, through the same vulnerable
// resolution logic. A bare ../ in a name is not enough: the proof is the
// round trip.
router.get('/traverse-prove', (req, res) => {
  const f = String(req.query.f || '');
  const pending = (req.session && req.session.uploadTravPending) || {};
  let ok = false;
  let target = '';
  if (f && pending.name === f) {
    // VULN: same missing containment check on read, so escaped files are retrievable.
    target = path.normalize(path.join(UPLOADS_DIR, f));
    const outside = !target.startsWith(UPLOADS_DIR + path.sep);
    try {
      const buf = fs.readFileSync(target);
      ok = outside && crypto.createHash('sha256').update(buf).digest('hex') === pending.sha;
    } catch (e) { ok = false; }
  }
  if (!ok) {
    return res.status(403).send(dropbox('Not proven', `
      <h2>No proof</h2>
      <p class="dim">The traversal was not proven: either nothing was stored outside the dropbox in this session, or the read-back did not match.</p>
      ${backToModule}`));
  }
  delete req.session.uploadTravPending;
  const flag = award(req, 'upload', 'upload-traversal');
  res.send(dropbox('Proven', `
    <h2>Traversal proven</h2>
    <p>The file <code>${esc(f)}</code> was written outside the dropbox folder and read back byte-identical.</p>
    ${flagBox(flag)}${fixPanel('upload', 'upload-traversal')}
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
      'Proxy a plain upload in Burp. The filename is joined straight to the uploads dir: do you see any basename check?',
      "In Repeater, try a filename with '../' segments. Where does the stored file land relative to the uploads folder?",
      'KEY INSIGHT: the filename is joined to the uploads directory with no basename or containment check. In Repeater, upload with a filename that climbs out of the uploads dir, then fetch it back through the /upload/traversed read endpoint.',
    ],
    tools: 'BZ, C',
    how: 'In Burp Repeater, POST to /upload/traverse with a filename containing ../ segments so the file lands outside the uploads dir. Then GET /upload/traverse-prove?f= with the same name: the flag fires only when the escaped file is read back byte-identical, proving the write really escaped.',
    link: '/upload#upload-traversal',
    start: 'In Burp Repeater, POST to /upload/traverse?filename=../pwn.txt with the file bytes as the raw body, then send a GET to /upload/traverse-prove?f=../pwn.txt and read the result.',
  },
  router,
};
