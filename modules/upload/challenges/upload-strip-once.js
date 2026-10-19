'use strict';
// Strip-once sanitizer: POST /filter removes each dangerous extension
// (.svg, .html, .htm) exactly ONCE with a non-global replace, so a nested
// name like "evil.s.svgvg" becomes "evil.svg" after the single strip. The
// filter never re-scans, so the rebuilt dangerous extension is stored.
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
// uploads/ dir as router.js. cleanFilename is the same lab-hygiene helper
// from router.js (not the vuln); it may be centralized in shared.js later.
const UPLOADS_DIR = path.join(__dirname, '..', '..', '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function cleanFilename(name) {
  const base = path.basename(String(name || ''));
  if (!/^[a-zA-Z0-9._-]+$/.test(base)) return null;
  if (base === '.' || base === '..') return null;
  return base;
}

const STRIP_BAD = ['.svg', '.html', '.htm'];

const backToModule = '<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to module</a></p>';

function dropbox(title, bodyHtml) {
  return page(title, appShell('FileDrop', bodyHtml, { mark: '⤓', nav: ['Dropbox', 'Shared', 'Account'], crumb: 'FileDrop / Shared dropbox' }));
}

// POST /filter -> strip each dangerous extension once, then store.
router.post('/filter', (req, res) => {
  let name = String(req.query.filename || '');
  // VULN: the sanitizer strips each dangerous extension only ONCE with a
  // non-global replace, so a nested name like "evil.s.svgvg" becomes "evil.svg".
  for (const bad of STRIP_BAD) name = name.replace(bad, '');
  const clean = cleanFilename(name);
  if (!clean) {
    return res.status(400).send(dropbox('Upload failed', `
      <h2>Upload failed</h2>
      <p class="dim">The filename was not usable after filtering.</p>
      ${backToModule}`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(dropbox('Upload failed', `
      <h2>Empty file</h2>
      <p class="dim">No request body received. Send the file bytes as the raw request body.</p>
      ${backToModule}`));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const ext = path.extname(clean).toLowerCase();
  const viewUrl = '/upload/view/' + encodeURIComponent(clean);
  let flagHtml = '';
  if (['.svg', '.html', '.htm'].includes(ext)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-strip-once')) + fixPanel('upload', 'upload-strip-once') + `<p class="dim">One filter pass was not enough: the stored name <code>${esc(clean)}</code> still has an active extension. View it at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored as <code>${esc(clean)}</code>. The filter removed the dangerous extension, so the file was saved harmlessly.</p>`;
  }
  res.send(dropbox('Uploaded', `
    <h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> , view it at <a href="${viewUrl}">${viewUrl}</a></p>
    ${flagHtml}
    ${backToModule}`));
});

module.exports = {
  vuln: {
    id: 'upload-strip-once',
    name: 'Strip-once filter bypass',
    difficulty: 'Medium',
    hint: 'v6 removes each dangerous extension exactly once with a non-global replace. Nest the extension inside itself so one removal rebuilds it.',
    hints: [
      "Proxy your browsing of /upload in Burp, then send a plain '.svg' upload to Repeater and watch the filter strip the extension once.",
      "In Repeater, try nesting the blocked extension inside itself in the filename query parameter. What does one removal leave behind?",
      'KEY INSIGHT: the filter strips the dangerous substring exactly once and never re-scans. Nest the blocked extension inside itself in Repeater so that one removal rebuilds it, then send to the filter endpoint and check the stored name in the response.',
    ],
    tools: 'BZ, C',
    how: 'POST to /upload/filter in Burp Repeater with a filename that nests the blocked extension inside itself. The single strip rebuilds the live extension, so the stored file stays active and the flag appears in the response.',
    link: '/upload#upload-strip-once',
    start: 'In Burp Repeater, build a POST to /upload/filter?filename=evil.s.svgvg with the SVG file bytes as the raw body, then send it and read the stored name in the response.',
  },
  router,
};
