'use strict';
// Case-sensitive blacklist bypass: POST /upload/ext-blacklist blocks ".svg",
// ".html" and ".htm" by exact case-sensitive match on the final extension, so
// "evil.SVG" passes the check and is still served as active content.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { esc, page, payloadBlock } = require('../../../lib/page');
// Module-level upload plumbing (provided by modules/upload/shared.js):
// rawUpload (express.raw), cleanFilename, UPLOADS_DIR.
const { rawUpload, cleanFilename, UPLOADS_DIR, issueBeaconToken, recordPendingUpload, beaconSnippet } = require('../shared');

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
  // Storing proves nothing on its own: each bypass only arms its own
  // challenge's beacon. The matching flag fires later, when the stored file
  // is served as active content and its script phones home (see
  // modules/upload/index.js POST /upload/beacon). One POST can therefore
  // never award both challenge ids: the beacon re-checks the bypass shape
  // for the specific id being claimed.
  let flagHtml = '';
  if (['.svg', '.html', '.htm'].includes(ext.toLowerCase())) {
    // VULN: case-sensitive blacklist bypassed , ".SVG" is still SVG.
    recordPendingUpload(req, 'upload-case', clean);
    const token = issueBeaconToken(req, 'upload-case');
    flagHtml += `<p class="dim">Case bypass stored: <code>${esc(clean)}</code>. Open <a href="${viewUrl}">${viewUrl}</a> in your proxied browser with this file carrying the case-bypass beacon snippet, and the flag fires when its script phones home.</p>${payloadBlock('Beacon snippet (upload-case)', beaconSnippet('upload-case', clean, token))}`;
  }
  if (/\.(svg|html?)\./i.test(clean)) {
    // VULN: double extension , the final ".jpg" passed, but the file is
    // served as SVG/HTML because of the earlier extension.
    // NOTE: this route is shared with the upload-double-ext challenge (a
    // sibling challenge file); the handler is kept identical so both
    // challenges behave exactly the same.
    recordPendingUpload(req, 'upload-double-ext', clean);
    const token = issueBeaconToken(req, 'upload-double-ext');
    flagHtml += `<p class="dim">Double extension stored: <code>${esc(clean)}</code> passed as <code>${esc(ext)}</code>. Open <a href="${viewUrl}">${viewUrl}</a> in your proxied browser with this file carrying the double-extension beacon snippet, and the flag fires when its script phones home.</p>${payloadBlock('Beacon snippet (upload-double-ext)', beaconSnippet('upload-double-ext', clean, token))}`;
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
    hint: 'The v3 blacklist compares the extension exactly as written. Filesystems and browsers do not care about case. Storing is not enough: the flag fires only when the stored file is served as active content and its script phones home through the beacon snippet.',
    hints: [
      "Intercept the upload request in Burp Proxy and forward it to Repeater. Then try changing only the case of the filename extension.",
      "Path.extname returns the case as-is. '.SVG' !== '.svg', so it passes, but the file is still served as SVG.",
      "KEY INSIGHT: a case-sensitive check can be beaten by changing the case of the blocked extension, since the viewer still recognises it as SVG. Upload a file whose extension is a case-variant of the blacklisted one, with the file carrying the beacon snippet for this challenge, to the ext-blacklist endpoint, then open its /upload/view/ link in your proxied browser.",
    ],
    tools: "BZ",
    how: 'In Burp Proxy, intercept the upload POST to /upload/ext-blacklist?filename=..., then send it to Repeater and change the filename case to a blocked-extension variant like evil.SVG, with the file carrying this challenge\'s beacon snippet. The ".svg" entry misses it and the file is served as active content; the flag fires when the served script phones home.',
    link: '/upload#upload-case',
    start: 'Proxy the site in Burp, open the upload form, intercept the upload request in the Proxy, then right-click and send it to Repeater. Bake the case-bypass beacon snippet into the file, then open the /upload/view/ link in your browser.',
  },
  router,
};
