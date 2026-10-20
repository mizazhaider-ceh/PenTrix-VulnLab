'use strict';
// Stored XSS via file upload (upload/stored-xss): the plain upload endpoint
// POST /upload?filename= stores the raw request bytes with no content
// validation, and /uploads serves .html/.svg files inline, so embedded
// JavaScript runs in the browser of whoever opens the stored file.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { appShell, esc, page, payloadBlock } = require('../../../lib/page');
const { issueBeaconToken, recordPendingUpload, beaconSnippet } = require('../shared');

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

  // VULN: uploaded bytes are stored verbatim under an attacker-chosen name
  // and later served inline, so an .html or .svg upload executes as script
  // in the lab origin (stored XSS via file upload).
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const url = '/uploads/' + encodeURIComponent(clean);

  // Storing the file is only step one: the flag fires only when the stored
  // file is later served inline with an executable content type AND its
  // script actually runs and phones home through the beacon. Nothing below
  // awards for the upload itself.
  const token = issueBeaconToken(req, 'stored-xss');
  let flagHtml = '';
  if (ext === '.html' || ext === '.svg') {
    recordPendingUpload(req, 'stored-xss', clean);
    flagHtml = `<p class="dim">Stored. The flag only fires when this file is
      served inline as HTML/SVG and its script calls the beacon below. Open
      <a href="${url}">${url}</a> in your proxied browser with a payload that
      contains this beacon snippet:</p>
      ${payloadBlock('Beacon snippet for this file', beaconSnippet('stored-xss', clean, token))}`;
  } else {
    flagHtml = `<p class="dim">Stored, but a <code>${esc(ext) || '(no)'}</code> file is not served inline as active content, so the beacon can never fire from it. Upload an <code>.html</code> or <code>.svg</code> file instead.</p>`;
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
    hint: 'The server accepts .html and .svg files and serves them inline, unchanged. What happens when a browser renders a file you control? Storing is not enough: the flag fires only when the served file\'s script phones home through the beacon, so bake the beacon snippet from the module page into your payload.',
    hints: [
      'Intercept the upload in Burp Proxy. The filename arrives in a ?filename= query parameter, not in the body. Try naming the file with a .html extension.',
      'Send the upload request to Burp Repeater and swap the body bytes for your own HTML page. The server stores whatever bytes you send, unchanged.',
      'KEY INSIGHT: the stored file is served back inline (not as a download), so your browser executes the script inside it, and the payload\'s beacon call is what earns the flag. Build an HTML page that runs the beacon snippet when it opens, send it through Repeater, then open its /uploads/ link in your proxied browser.',
    ],
    tools: 'BZ, B, C',
    how: 'In Burp Repeater, POST your own HTML or SVG bytes (carrying the beacon snippet for this challenge) as the raw body of /upload?filename=evil.html, then open its /uploads/ link in your proxied browser so the script runs and beacons.',
    link: '/upload#stored-xss',
    start: 'Start Burp Proxy, open the PixelDrop upload page in your proxied browser, and send the POST /upload?filename= request to Repeater. Replace the body with your HTML file bytes (beacon snippet included), name the file .html, and send.',
  },
  router,
};
