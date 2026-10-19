'use strict';
// Unrestricted File Upload: intentionally vulnerable upload endpoints.
// Binary body parsing, the shared storage plumbing and the friendly 413
// page live at module level (ported from the legacy router.js); each
// challenge file owns only its own routes.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { fixCta, brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill  } = require('../../lib/page');
const { rawUpload, cleanFilename, UPLOADS_DIR } = require('./shared');

const challenges = [
  require('./challenges/stored-xss'),
  require('./challenges/upload-double-ext'),
  require('./challenges/upload-case'),
  require('./challenges/upload-ctype'),
  require('./challenges/upload-traversal'),
  require('./challenges/upload-strip-once'),
  require('./challenges/upload-overwrite'),
  require('./challenges/upload-polyglot'),
];

const router = express.Router();

// Module-level binary body parsing: behavior-identical to the per-route
// rawUpload middleware the legacy router applied to every upload POST
// (body-parser skips re-parsing where a challenge applies it per route too).
router.use(rawUpload);

// Module-level dependency for the stored-xss and upload-double-ext
// challenge files, which read { dir, clean } from req.uploadShared.
router.use((req, res, next) => {
  req.uploadShared = { dir: UPLOADS_DIR, clean: cleanFilename };
  next();
});

function storedFiles() {
  try {
    return fs.readdirSync(UPLOADS_DIR).filter((f) => {
      try { return fs.statSync(path.join(UPLOADS_DIR, f)).isFile(); } catch { return false; }
    });
  } catch { return []; }
}

// Browser upload widget for the v1 endpoint (ported from the legacy page).
const uploadScript = `
<script>
async function sendFile(inputId, target, outId) {
  const file = document.getElementById(inputId).files[0];
  const out = document.getElementById(outId);
  if (!file) { out.innerHTML = '<p class="warn">Pick a file first.</p>'; return; }
  const url = target + '?filename=' + encodeURIComponent(file.name);
  try {
    const r = await fetch(url, { method: 'POST', body: file });
    out.innerHTML = await r.text();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (e) { out.innerHTML = '<p class="warn">Upload failed: ' + e.message + '</p>'; }
}
</script>`;

// Module-level endpoint reference (ported from the legacy index page).
const ENDPOINTS = [
  {
    title: 'v1, plain upload', pill: 'POST /upload?filename=',
    desc: 'No content checks at all. Files are served inline, so HTML/SVG files render in the browser.',
    curl: 'curl --data-binary @evil.html "http://localhost:3000/upload?filename=evil.html"',
    widget: true,
  },
  {
    title: 'v3, SVG/HTML blacklist', pill: 'POST /upload/ext-blacklist?filename=',
    desc: 'Blocks <code>.svg</code>, <code>.html</code>, <code>.htm</code> by exact, case-sensitive final extension. Served back via <code>/upload/view/:name</code>, which guesses the content type from the filename.',
    curl: 'curl --data-binary @evil.svg.jpg "http://localhost:3000/upload/ext-blacklist?filename=evil.svg.jpg"',
  },
  {
    title: 'v4, Content-Type check', pill: 'POST /upload/mime-check?filename=',
    desc: '"Only images allowed", but the check reads only the <code>Content-Type</code> request header, never the bytes.',
    curl: 'curl --data-binary @evil.html -H "Content-Type: image/png" "http://localhost:3000/upload/mime-check?filename=evil.html"',
  },
  {
    title: 'v6, strip-once filter', pill: 'POST /upload/filter?filename=',
    desc: 'Strips <code>.svg</code>/<code>.html</code>/<code>.htm</code> from the filename exactly once, then stores whatever is left.',
    curl: 'curl --data-binary @evil.svg "http://localhost:3000/upload/filter?filename=evil.s.svgvg"',
  },
  {
    title: 'v7, traversal upload', pill: 'POST /upload/traverse?filename=',
    desc: 'No basename, no containment check: <code>../</code> in the filename escapes the uploads directory. Read escaped files at <code>/upload/traversed?f=</code>.',
    curl: 'curl --data-binary @pwn.txt "http://localhost:3000/upload/traverse?filename=../pwn.txt"',
  },
  {
    title: 'v8, user avatars', pill: 'POST /upload/avatar?user=',
    desc: 'Avatars live at predictable paths (<code>avatar-&lt;user&gt;.png</code>) and anyone can write any user\'s file. Victim <code>bob</code> already has one: <a href="/upload/avatar/bob">/upload/avatar/bob</a>.',
    curl: 'curl --data-binary @evil.png "http://localhost:3000/upload/avatar?user=bob"',
  },
  {
    title: 'v9, GIF magic-byte check', pill: 'POST /upload/polyglot?filename=',
    desc: '"Image validation" checks only the 6 GIF magic bytes. The file is later served as <code>text/html</code> at <code>/upload/poly/:name</code>.',
    curl: 'printf \'GIF89a<script>alert(1)</script>\' | curl --data-binary @- "http://localhost:3000/upload/polyglot?filename=x.gif"',
  },
];

// GET /upload -> module index page.
router.get('/', (req, res) => {
  const files = storedFiles();
  const fileRows = files.length
    ? files.map((f) => {
        const url = '/uploads/' + encodeURIComponent(f);
        return `<tr><td><code>${esc(f)}</code></td><td><a href="${url}" target="_blank" rel="noopener">${url}</a></td></tr>`;
      }).join('')
    : '<tr><td colspan="2" class="dim">No files uploaded yet.</td></tr>';

  const endpointCards = ENDPOINTS.map((e, i) => `
    <div class="card">
      <h3>${esc(e.title)} <span class="pill">${esc(e.pill)}</span></h3>
      <p class="dim">${e.desc}</p>
      ${e.widget ? `<p><input class="clay-input" type="file" id="file${i}"> <button class="clay-btn clay-btn-primary clay-btn-sm" onclick="sendFile('file${i}','/upload','out${i}')">Upload to v1</button></p><div id="out${i}"></div>` : ''}
      <p class="dim">curl version:</p>
      <pre>${esc(e.curl)}</pre>
    </div>`).join('');

  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('upload', c.vuln.id)).join('')}
    </section>`;
  res.send(page('Unrestricted File Upload', uploadScript + brief('Unrestricted File Upload', `
      <p>An avatar-upload feature that never asks <i>what</i> the file actually is.
      Store a file, get a public link under <code>/uploads/</code>, and see what happens
      when the server serves it back to a browser untouched.</p>`) + trackBanner(module.exports) + `
    <h2>Upload endpoints</h2>
    <div class="grid">${endpointCards}</div>

    <h2>Challenges</h2>
    ${cards}

    <h2>Stored files</h2>
    <table class="tbl"><tr><th>Filename</th><th>Public link</th></tr>${fileRows}</table>${fixSectionHtml}
`));
});

// stored-xss owns POST /upload?filename= (v1). The legacy router placed the
// friendly 413 page right after this route, so the error handler keeps that
// exact position to stay behavior-identical.
router.use(challenges[0].router);
router.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).send(page('Too large', `<h2>File too large</h2><p class="dim">Uploads are capped at 2 MB.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  next(err);
});
for (const c of challenges.slice(1)) router.use(c.router);

module.exports = {
  id: 'upload',
  name: 'Unrestricted File Upload',
  tagline: 'Upload a file, get a link. What could go wrong?',
  description: 'The uploader stores whatever you send and serves it back inline under /uploads/. Poison the stored file and bypass the naive extension blacklist.',
  difficulty: 'Intermediate',
  track: 'Injection',
  prerequisites: ['xss'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
