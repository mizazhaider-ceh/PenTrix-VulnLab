'use strict';
// Unrestricted File Upload: intentionally vulnerable upload endpoints.
// Binary body parsing, the shared storage plumbing and the friendly 413
// page live at module level (ported from the legacy router.js); each
// challenge file owns only its own routes.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill, flagBox, fixPanel } = require('../../lib/page');
const { award } = require('../../lib/flags');
const { rawUpload, cleanFilename, UPLOADS_DIR, enforceUploadQuota, issueBeaconToken, beaconSnippet, verifyBeacon } = require('./shared');

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
// Also enforces the per-session upload quota for the requesting session
// only (see shared.js; handlers record ownership at store time there).
router.use((req, res, next) => {
  req.uploadShared = { dir: UPLOADS_DIR, clean: cleanFilename };
  enforceUploadQuota(req);
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
  if (!file) { out.innerHTML = '<p class="warn">Pick a file first: use the file picker above, then press the upload button again.</p>'; return; }
  const url = target + '?filename=' + encodeURIComponent(file.name);
  try {
    const r = await fetch(url, { method: 'POST', body: file });
    out.innerHTML = await r.text();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (e) { out.innerHTML = '<p class="warn">Upload failed: ' + e.message + '. Check that the lab is still running, then try again.</p>'; }
}
</script>`;

// Module-level endpoint reference (ported from the legacy index page).
const ENDPOINTS = [
  {
    title: 'v1, plain upload', pill: 'POST /upload?filename=',
    desc: 'No content checks at all. Files are served inline, so HTML/SVG files render in the browser.',
    curl: 'curl --data-binary @evil.html "http://<your-lab-address>/upload?filename=evil.html"',
    widget: true,
  },
  {
    title: 'v3, SVG/HTML blacklist', pill: 'POST /upload/ext-blacklist?filename=',
    desc: 'Blocks <code>.svg</code>, <code>.html</code>, <code>.htm</code> by exact, case-sensitive final extension. Served back via <code>/upload/view/:name</code>, which guesses the content type from the filename.',
    curl: 'curl --data-binary @evil.svg.jpg "http://<your-lab-address>/upload/ext-blacklist?filename=evil.svg.jpg"',
  },
  {
    title: 'v4, Content-Type check', pill: 'POST /upload/mime-check?filename=',
    desc: '"Only images allowed", but the check reads only the <code>Content-Type</code> request header, never the bytes.',
    curl: 'curl --data-binary @evil.html -H "Content-Type: image/png" "http://<your-lab-address>/upload/mime-check?filename=evil.html"',
  },
  {
    title: 'v6, strip-once filter', pill: 'POST /upload/filter?filename=',
    desc: 'Strips <code>.svg</code>/<code>.html</code>/<code>.htm</code> from the filename exactly once, then stores whatever is left.',
    curl: 'curl --data-binary @evil.svg "http://<your-lab-address>/upload/filter?filename=evil.s.svgvg"',
  },
  {
    title: 'v7, traversal upload', pill: 'POST /upload/traverse?filename=',
    desc: 'No basename, no containment check: <code>../</code> in the filename escapes the uploads directory. Read escaped files at <code>/upload/traversed?f=</code>.',
    curl: 'curl --data-binary @pwn.txt "http://<your-lab-address>/upload/traverse?filename=../pwn.txt"',
  },
  {
    title: 'v8, user avatars', pill: 'POST /upload/avatar?user=',
    desc: 'Avatars live at predictable paths (<code>avatar-&lt;user&gt;.png</code>) and anyone can write any user\'s file. Victim <code>bob</code> already has one: <a href="/upload/avatar/bob">/upload/avatar/bob</a>.',
    curl: 'curl --data-binary @evil.png "http://<your-lab-address>/upload/avatar?user=bob"',
  },
  {
    title: 'v9, GIF magic-byte check', pill: 'POST /upload/polyglot?filename=',
    desc: '"Image validation" checks only the 6 GIF magic bytes. The file is later served as <code>text/html</code> at <code>/upload/poly/:name</code>.',
    curl: 'printf \'GIF89a<script>alert(1)</script>\' | curl --data-binary @- "http://<your-lab-address>/upload/polyglot?filename=x.gif"',
  },
];

// Console for each upload challenge card (P4-4): the endpoint widget above
// is the challenge's console, and the copyable command is the endpoint's
// curl, made port-agnostic by reusing the <your-lab-address> placeholder.
function epConsole(i) {
  return {
    href: '#endpoint-' + i,
    cmd: ENDPOINTS[i].curl.replace(/http:\/\/localhost:3000/g, 'http://<your-lab-address>'),
  };
}
const UPLOAD_CONSOLES = {
  'stored-xss': epConsole(0),
  'upload-double-ext': epConsole(1),
  'upload-case': epConsole(1),
  'upload-ctype': epConsole(2),
  'upload-strip-once': epConsole(3),
  'upload-traversal': epConsole(4),
  'upload-overwrite': epConsole(5),
  'upload-polyglot': epConsole(6),
};

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
    <div class="card" id="endpoint-${i}">
      <h3>${esc(e.title)} <span class="pill">${esc(e.pill)}</span></h3>
      <p class="dim">${e.desc}</p>
      ${e.widget ? `<p><label for="file${i}">Choose a file for ${esc(e.title)}</label><br><input class="clay-input" type="file" id="file${i}" aria-describedby="out${i}"> <button class="clay-btn clay-btn-primary clay-btn-sm" onclick="sendFile('file${i}','/upload','out${i}')">Upload to v1</button></p><div id="out${i}" role="status" aria-live="polite"></div>` : ''}
      <p class="dim">curl version:</p>
      <pre>${esc(e.curl)}</pre>
    </div>`).join('');

  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('upload', ordered, UPLOAD_CONSOLES);
  // Prove block (flag integrity): every challenge shows its per-session
  // beacon token plus the snippet the payload must run, so a student can
  // bake the token in before uploading. Storing alone never awards.
  const proveFor = (v) => {
    if (v.id === 'upload-traversal') {
      return `<p class="dim"><b>Prove it:</b> after uploading, read the escaped file back through <code>/upload/traverse-prove?f=YOUR-FILENAME</code>. The flag fires only on the read-back.</p>`;
    }
    const token = issueBeaconToken(req, v.id);
    const fileHint = v.id === 'upload-overwrite' ? 'bob' : 'YOUR-FILENAME';
    return `<p class="dim"><b>Prove it:</b> beacon token for this challenge: <code data-beacon="${esc(v.id)}">${token}</code>. Bake it into the payload with this snippet so the served file phones home when its script runs:</p>${payloadBlock('Beacon snippet', beaconSnippet(v.id, fileHint, token))}`;
  };
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'upload', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${proveFor(v)}
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Unrestricted File Upload', uploadScript + brief('Unrestricted File Upload', `
      <p>An avatar-upload feature that never asks <i>what</i> the file actually is.
      Store a file, get a public link under <code>/uploads/</code>, and see what happens
      when the server serves it back to a browser untouched.</p>`) + trackBanner(module.exports) + `
    <h2>Upload endpoints</h2>
    <div class="grid">${endpointCards}</div>

    <h2>Challenges</h2>
    ${cards}

    <h2>Stored files</h2>
    <table class="tbl"><tr><th>Filename</th><th>Public link</th></tr>${fileRows}</table>${fixSection('upload', challenges)}
`));
});

// POST /upload/beacon -> the execution-proof endpoint for all 8 challenges.
// Awarding NEVER happens at upload time; it happens here, and only when
// verifyBeacon confirms every check against this session and the stored
// artifact: the posted token matches the per-session token issued for that
// challenge, a pending upload was recorded through that challenge's own
// endpoint and the posted file name matches it, the stored file is still
// present, the challenge's bypass shape is satisfied, the file is served
// with an executable content type, an executable script is present in the
// file bytes, and the per-session token is embedded in the file bytes. A
// direct POST is accepted only when all of those checks pass.
router.post('/beacon', (req, res) => {
  // The app applies express.json() globally, so a JSON beacon body may
  // arrive already parsed as an object; the module's raw parser may leave it
  // as a Buffer instead. Accept both.
  let data = {};
  if (Buffer.isBuffer(req.body)) {
    try { data = JSON.parse(req.body.toString('utf8')); } catch (e) { /* rejected below */ }
  } else if (req.body && typeof req.body === 'object') {
    data = req.body;
  }
  const vulnId = String((data && data.id) || '');
  const file = String((data && data.file) || '');
  const token = String((data && data.token) || '');
  const known = challenges.some((c) => c.vuln.id === vulnId);
  const verdict = known ? verifyBeacon(req, vulnId, token, file) : { ok: false, reason: 'unknown challenge id' };
  if (!verdict.ok) {
    return res.status(403).send(page('Beacon rejected', `
      <h1>Beacon rejected</h1>
      <p>No flag. ${esc(verdict.reason || 'the beacon could not be verified')}.</p>
      <p class="dim">Open the stored file in a real browser so its script runs,
      make sure the file carries the beacon snippet for this challenge, and try
      again.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to the module</a></p>
    `));
  }
  const flag = award(req, 'upload', vulnId);
  res.send(page('Executed', `
    <h1>Payload executed</h1>
    ${flagBox(flag)}
    ${fixPanel('upload', vulnId)}
    <p class="dim">The stored file was served as executable content and its script phoned home through the beacon.</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to the module</a></p>
  `));
});

// stored-xss owns POST /upload?filename= (v1). The legacy router placed the
// friendly 413 page right after this route, so the error handler keeps that
// exact position to stay behavior-identical.
router.use(challenges[0].router);
router.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).send(page('Too large', `<h2>File too large</h2><p class="dim">Uploads are capped at 2 MB. Pick a smaller file and try again.</p><p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to the module</a></p>`));
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
