'use strict';
// GIF/HTML polyglot: the "image validation" only checks the 6 magic bytes,
// so a file that starts with GIF89a but continues with real HTML/JS passes
// validation and is later served as text/html by /upload/poly/:name. Shared
// storage config, the filename cleaner and the raw-body uploader live in
// ../shared.js (created by the module finisher).
const express = require('express');
const fs = require('fs');
const {
  appShell, brief, esc, page, payloadBlock, hintLadder, toolsPill,
} = require('../../../lib/page');
const { cleanFilename, rawUpload, UPLOADS_DIR, issueBeaconToken, recordPendingUpload, beaconSnippet, trackStoredUpload } = require('../shared');

const path = require('path');

const router = express.Router();

const vuln = {
  id: 'upload-polyglot',
  name: 'GIF/HTML polyglot',
  difficulty: 'Hard',
  est: 'about 20 to 40 minutes',
  hint: 'v9 validates only the 6 GIF magic bytes, then serves the file as text/html. A file can be a valid GIF header and valid HTML at once. Storing is not enough: the flag fires only when the served file\'s script phones home through the beacon snippet.',
  hints: [
    "The uploader checks magic bytes. What are the first 6 bytes of a GIF?",
    "In Burp Repeater, send a raw request body that starts with those 6 magic bytes and continues with HTML containing the beacon snippet for this challenge.",
    "KEY INSIGHT: a polyglot must satisfy both parsers at once. The magic-byte check only reads the first bytes (the 6-byte GIF header), so build a file that passes that check while the browser parses the rest as HTML with the beacon snippet inside, then open its render URL so the script phones home.",
  ],
  tools: 'BZ, C',
  how: 'Build a GIF/HTML polyglot (the 6 GIF magic bytes, then scriptable HTML carrying the beacon snippet) and POST the raw bytes to /upload/polyglot?filename=... from Burp Repeater, then open its /upload/poly/ render URL in the browser so the script runs and beacons.',
  link: '/upload#upload-polyglot',
  start: 'In Burp Repeater, POST a raw body that satisfies the image check while remaining scriptable markup, then visit the returned render link.',
};

const APP_NAME = 'GifCheck';
const APP_NAV = ['Validate', 'Gallery', 'Docs'];

// Fetch-based upload widget (raw request body, same as the curl form), so the
// page works like the real image validator it pretends to be.
const uploadWidget = `
<div class="clay-card">
  <h3>Validate an image</h3>
  <form id="polyForm">
    <div class="clay-field">
      <label for="nameInput">Filename</label>
      <input class="clay-input" id="nameInput" name="filename" value="x.gif" maxlength="64" autocomplete="off" />
    </div>
    <div class="clay-field">
      <label for="fileInput">Image file</label>
      <input class="clay-input" id="fileInput" type="file" />
    </div>
    <button class="clay-btn clay-btn-primary" type="submit">Upload image</button>
  </form>
  <div id="uploadOut"></div>
</div>
<script>
document.getElementById('polyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = document.getElementById('uploadOut');
  const file = document.getElementById('fileInput').files[0];
  const fname = document.getElementById('nameInput').value;
  if (!file) { out.innerHTML = '<p class="clay-err">Pick a file first.</p>'; return; }
  try {
    const r = await fetch('/upload/polyglot?filename=' + encodeURIComponent(fname), { method: 'POST', body: file });
    out.innerHTML = await r.text();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (err) { out.innerHTML = '<p class="clay-err">Upload failed: ' + err.message + '</p>'; }
});
</script>`;

function failPage(status, title, heading, messageHtml) {
  return page(title, appShell(APP_NAME, `
    <div class="clay-card">
      <h2>${esc(heading)}</h2>
      <p class="dim">${messageHtml}</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to module</a></p>
    </div>`, { crumb: 'Validator / ' + vuln.name, nav: APP_NAV }));
}

// POST /upload/polyglot -> the result page for this challenge.
function polyglotResultPage(clean, polyUrl, flagHtml) {
  const body = `
    ${brief('Image validator', `
      <p><b>${esc(APP_NAME)}</b> checks that uploaded pictures are really
      GIFs by sniffing the first 6 magic bytes, then publishes the validated
      image at its own render URL.</p>`)}
    ${uploadWidget}
    <div class="clay-card">
      <h2>File stored</h2>
      <p>Saved as <code>${esc(clean)}</code> , rendered at <a href="${polyUrl}" target="_blank" rel="noopener">${polyUrl}</a></p>
      ${flagHtml}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to module</a></p>
    </div>
    ${payloadBlock('Starting point', vuln.start)}
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}`;
  return page(vuln.name, appShell(APP_NAME, body, { crumb: 'Validator / ' + vuln.name, nav: APP_NAV }));
}

// POST /upload/polyglot -> v9: magic-byte check only, served back as HTML.
router.post('/polyglot', rawUpload, (req, res) => {
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(failPage(400, 'Upload failed', 'Upload failed',
      'Missing or invalid <code>?filename=</code> query parameter.'));
  }
  const head = Buffer.isBuffer(req.body) ? req.body.slice(0, 6).toString('ascii') : '';
  // VULN: the "image validation" only checks the 6 magic bytes; everything
  // after them can be arbitrary HTML, and the file is later served as HTML.
  if (head !== 'GIF89a' && head !== 'GIF87a') {
    return res.status(400).send(failPage(400, 'Blocked', 'Blocked',
      'Only GIF images pass validation (magic-byte check).'));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  trackStoredUpload(req, clean);
  const text = req.body.toString('utf8');
  const polyUrl = '/upload/poly/' + encodeURIComponent(clean);
  let flagHtml = '';
  if (/<script[\s>]|on\w+\s*=/i.test(text)) {
    // Storing the polyglot arms the beacon only; the flag fires when the
    // file is served as text/html and its script phones home.
    recordPendingUpload(req, 'upload-polyglot', clean);
    const token = issueBeaconToken(req, 'upload-polyglot');
    flagHtml = `<p class="dim">Magic bytes passed, scriptable HTML survived. Open <a href="${polyUrl}" target="_blank" rel="noopener">${polyUrl}</a> in your browser with this file carrying the beacon snippet, and the flag fires when its script phones home.</p>${payloadBlock('Beacon snippet (upload-polyglot)', beaconSnippet('upload-polyglot', clean, token))}`;
  } else {
    flagHtml = `<p class="dim">Stored, but no scriptable HTML was found. The lab wants a GIF header plus real HTML/JS after it.</p>`;
  }
  res.send(polyglotResultPage(clean, polyUrl, flagHtml));
});

// GET /upload/poly/:name -> serves the "validated image" as text/html, so the
// polyglot's HTML half executes in the browser.
router.get('/poly/:name', (req, res) => {
  const name = path.basename(String(req.params.name || ''));
  const fp = path.join(UPLOADS_DIR, name);
  if (!name || !fs.existsSync(fp)) {
    return res.status(404).send(failPage(404, 'Not found', 'Not found',
      'No such stored file.'));
  }
  // VULN: the "validated image" is served as text/html with no
  // X-Content-Type-Options, so the polyglot's HTML half executes in the browser.
  res.set('Content-Type', 'text/html');
  res.send(fs.readFileSync(fp));
});

module.exports = { vuln, router };
