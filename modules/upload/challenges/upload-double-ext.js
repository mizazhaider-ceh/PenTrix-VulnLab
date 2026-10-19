'use strict';
// Extension blacklist bypass (upload/upload-double-ext): the v3 endpoint
// POST /upload/ext-blacklist blocks .svg/.html/.htm by exact, case-sensitive
// final extension only, and GET /upload/view/:name guesses the served content
// type from a substring of the filename. "shell.svg.jpg" passes the blacklist
// (its final extension is ".jpg") but is served back as SVG, so embedded
// script executes in the browser (stored XSS).
const express = require('express');
const fs = require('fs');
const path = require('path');
const { appShell, esc, flagBox, fixPanel, page } = require('../../../lib/page');
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

// v3: SVG/HTML extension blacklist (case-sensitive, final extension only).
// Kept here because it belongs to this challenge's feature, not to the module.
const EXT_BLACKLIST = ['.svg', '.html', '.htm'];

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

// POST /upload/ext-blacklist?filename= : v3 blacklist upload.
// NOTE: this single route serves two challenges (upload-case and
// upload-double-ext); the handler below is the complete original, with both
// award branches verbatim, so module behavior is identical to router.js no
// matter which challenge file is mounted first.
router.post('/ext-blacklist', (req, res) => {
  const { dir: UPLOADS_DIR, clean: cleanFilename } = uploadShared(req);
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(dropPage('Upload failed',
      `<div class="clay-card"><div class="card-top"><b>Upload failed</b></div>
      <p class="dim">Missing or invalid <code>?filename=</code> query parameter. Allowed characters: <code>a-z A-Z 0-9 . _ -</code></p>
      ${backBtn()}</div>`));
  }
  const ext = path.extname(clean); // deliberately NOT lowercased
  // VULN: the blacklist compares the raw case-sensitive final extension
  // only. "evil.SVG" dodges the ".svg" entry, and "shell.svg.jpg" has a
  // final extension of ".jpg", while the file is still served as SVG/HTML
  // by /upload/view/:name below.
  if (EXT_BLACKLIST.includes(ext)) {
    return res.status(400).send(dropPage('Blocked',
      `<div class="clay-card"><div class="card-top"><b>Blocked</b><span class="clay-pill">extension blacklist</span></div>
      <p>The extension <code>${esc(ext)}</code> is blacklisted. Try a different name.</p>
      ${backBtn()}</div>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(dropPage('Upload failed',
      `<div class="clay-card"><div class="card-top"><b>Empty file</b></div>
      <p class="dim">No request body received. Upload the file bytes as the raw request body.</p>
      ${backBtn()}</div>`));
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
    flagHtml += flagBox(award(req, 'upload', 'upload-double-ext')) + fixPanel('upload', 'upload-double-ext') + `<p class="dim">Double extension bypass: <code>${esc(clean)}</code> passed as <code>${esc(ext)}</code> but is served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  }
  if (!flagHtml) flagHtml = `<p class="dim">Stored. Neither a case variant nor a double extension was used, so nothing was bypassed.</p>`;
  res.send(dropPage('Uploaded',
    `<div class="clay-card"><div class="card-top"><b>File stored</b><span class="clay-pill">v3 blacklist upload</span></div>
    <p>Saved as <code>${esc(clean)}</code> , view it at <a href="${viewUrl}">${viewUrl}</a></p>
    ${flagHtml}
    ${backBtn()}</div>`));
});

// GET /upload/view/:name : serves the stored file, guessing the content type
// from a substring of the filename (the v3 lab viewer).
router.get('/view/:name', (req, res) => {
  const { dir: UPLOADS_DIR } = uploadShared(req);
  const name = path.basename(String(req.params.name || ''));
  const fp = path.join(UPLOADS_DIR, name);
  if (!name || !fs.existsSync(fp)) {
    return res.status(404).send(dropPage('Not found',
      `<div class="clay-card"><div class="card-top"><b>Not found</b></div>
      <p class="dim">No such stored file.</p>
      ${backBtn()}</div>`));
  }
  const lower = name.toLowerCase();
  // VULN: substring-based type detection , "shell.svg.jpg" contains ".svg"
  // and is served as SVG, turning the blacklist bypass into stored XSS.
  if (lower.includes('.svg')) res.type('image/svg+xml');
  else if (lower.includes('.html') || lower.includes('.htm')) res.type('text/html');
  else res.type('application/octet-stream');
  res.send(fs.readFileSync(fp));
});

module.exports = {
  vuln: {
    id: 'upload-double-ext',
    name: 'Extension blacklist bypass',
    difficulty: 'Medium',
    hint: 'The filter blocks .svg/.html by exact final extension only, and the viewer guesses the content type from the filename. What does path.extname("shell.svg.jpg") return? The same idea beats any exact-match blacklist: smuggle the dangerous extension inside the name (shell.php.jpg) or use an unlisted one (.phtml).',
    hints: [
      "The filter blocks .svg by exact final extension. What does path.extname('shell.svg.jpg') return?",
      'The check sees \'.jpg\' and allows it, but the viewer guesses the content type from the full name and serves it as SVG.',
      'KEY INSIGHT: the blocklist only inspects the final extension, while the viewer guesses the type from the whole name. Upload a file whose final extension is allowed but whose full name still resolves to SVG, carrying SVG plus script, to the ext-blacklist endpoint, then open its view link.',
    ],
    tools: 'C',
    how: 'Upload shell.svg.jpg to POST /upload/ext-blacklist?filename=..., then open its /upload/view/ link to see it served as SVG. The same bypass shape defeats exact-match extension blacklists generally.',
    link: '/upload#upload-double-ext',
    start: 'curl --data-binary @evil.svg.jpg "http://localhost:3000/upload/ext-blacklist?filename=evil.svg.jpg"',
  },
  router,
};
