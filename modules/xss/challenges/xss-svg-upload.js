'use strict';
// Stored XSS via SVG upload: uploaded SVG is served inline as image/svg+xml.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { DB_PATH } = require('../../../lib/db');
const { page, esc, errorPage, claimBox } = require('../../../lib/page');
const { xssNonce, xssNonceTag, siteFrame, backLinks } = require('../shared');

const router = express.Router();

// Uploads live beside the database (the writable data directory), never in the source tree.
const UPLOAD_DIR = path.join(path.dirname(DB_PATH), 'xss-uploads');
function ensureUploadDir() {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const SVG_PAYLOAD = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script><![CDATA[fetch('/xss/collect?c='+document.cookie+'&v=xss-svg-upload&n='+new URLSearchParams(location.search).get('n'))]]></script></svg>";

router.get('/svg', (req, res) => {
  let files = [];
  try {
    files = fs.readdirSync(UPLOAD_DIR)
      .filter((f) => f.endsWith('.svg'))
      .map((f) => ({ f, t: fs.statSync(path.join(UPLOAD_DIR, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t)
      .slice(0, 20);
  } catch (e) { /* no uploads yet */ }
  // The uploaded SVG opens as its own document, so it cannot see window.__px.
  // The file links carry the page-bound nonce in the query string instead, and
  // the payload reads it from location.search when it executes.
  const svgNonce = xssNonce(req, 'xss-svg-upload');
  const rows = files.map(({ f, t }) => `<tr>
      <td>${esc(f)}</td><td>${esc(new Date(t).toISOString().slice(0, 16).replace('T', ' '))}</td>
      <td><a href="/xss/uploads/${esc(f)}?n=${svgNonce}">Open</a></td></tr>`).join('');
  const list = rows
    ? `<div class="tbl-scroll"><table class="tbl">
        <caption class="sr-only">Uploaded avatars</caption>
        <thead><tr><th scope="col">File</th><th scope="col">Uploaded (UTC)</th><th scope="col">Link</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`
    : '<p class="dim">No avatars uploaded yet.</p>';
  res.send(page('Avatars Â· Pixelpond', `
    <h2>Pixelpond</h2>
    ${xssNonceTag(req, 'xss-svg-upload')}
    ${siteFrame('Pixelpond', ['Gallery', 'Avatars', 'Settings'], `
      <p>Upload a vector avatar. Paste your SVG markup, we store it and serve it back as <code>image/svg+xml</code>.</p>
      <form method="POST" action="/xss/svg">
        <div class="clay-field">
          <label for="name">File name</label>
          <input class="clay-input" type="text" id="name" name="name" placeholder="avatar" maxlength="32" autocomplete="off">
        </div>
        <div class="clay-field">
          <label for="svg">SVG markup</label>
          <textarea class="clay-input" id="svg" name="svg" rows="8" placeholder="&lt;svg xmlns=&quot;http://www.w3.org/2000/svg&quot;&gt;...&lt;/svg&gt;" required></textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Upload SVG</button>
      </form>
      <h3>Recent avatars</h3>
      ${list}`)}
    ${claimBox({ vulnId: 'xss-svg-upload', payload: esc(SVG_PAYLOAD), statusUrl: '/xss/claim-status?v=xss-svg-upload', beaconInfo: 'The SVG opens as its own document, so window.__px is not defined there. The file link carries the token in ?n=; read it with new URLSearchParams(location.search).get(&quot;n&quot;). The file is parsed as XML, so a bare &amp; in the script would break parsing: keep the code inside a CDATA section.' })}
    ${backLinks('xss-svg-upload')}
  `));
});

router.post('/svg', (req, res) => {
  const raw = String(req.body.svg || '').slice(0, 20000);
  const name = String(req.body.name || 'pic').replace(/[^a-z0-9_-]/gi, '').slice(0, 32) || 'pic';
  if (!/<svg[\s>]/i.test(raw)) {
    return res.status(400).send(page('Avatars Â· Pixelpond', errorPage(400, 'That is not SVG markup',
      '<p>The upload must contain an <code>&lt;svg&gt;</code> element.</p><p><a href="/xss/svg">Back to uploads</a></p>')));
  }
  const file = `${name}-${Date.now()}.svg`;
  ensureUploadDir();
  // VULN: attacker-controlled SVG is stored and served as image/svg+xml, so embedded scripts run on direct visit.
  fs.writeFileSync(path.join(UPLOAD_DIR, file), raw);
  res.redirect('/xss/uploads/' + file + '?n=' + xssNonce(req, 'xss-svg-upload'));
});

router.get('/uploads/:file', (req, res) => {
  const file = req.params.file;
  if (!/^[a-zA-Z0-9_-]+\.svg$/.test(file)) return res.status(400).send('bad filename');
  const full = path.join(UPLOAD_DIR, file);
  if (!full.startsWith(UPLOAD_DIR) || !fs.existsSync(full)) return res.status(404).send('not found');
  res.set('Content-Type', 'image/svg+xml');
  res.send(fs.readFileSync(full, 'utf8'));
});

module.exports = {
  vuln: {
    id: 'xss-svg-upload',
    name: 'Stored XSS via SVG Upload',
    difficulty: 'Medium',
    hint: 'Uploaded SVGs are served as image/svg+xml. An SVG is XML, and XML can carry a script tag that runs when the file is opened directly.',
    hints: [
      'You can upload SVG files and they are served as image/svg+xml. What is an SVG file, really?',
      'SVG is XML, and XML can contain <script> tags. When the browser opens the SVG directly (not as an <img>), the script runs.',
      'Upload an SVG whose <script> calls /xss/collect (parameters c, v=xss-svg-upload and n). The SVG is its own document, so read the token from the n parameter of the file URL instead of window.__px, then open the file link. Remember the SVG is parsed as XML: a bare & must not appear outside a CDATA section.',
    ],
    tools: 'B, C',
    how: 'Upload an SVG containing a script with the exfiltration payload (v=xss-svg-upload), then open the file URL.',
    link: '/xss/svg',
    start: 'curl -s http://localhost:3000/xss/svg | grep -n "<form"',
  },
  router,
};
