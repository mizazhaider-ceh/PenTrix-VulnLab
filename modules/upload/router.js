// PenTrix VulnLab module: Unrestricted File Upload
// No new npm deps; raw binary uploads via express.raw() mounted only in this router.

const express = require('express');
const fs = require('fs');
const path = require('path');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();

// The project-root uploads/ dir, served inline by app.js at /uploads
const UPLOADS_DIR = path.join(__dirname, '..', '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// VULN: no content validation is performed on uploaded files anywhere in this module.
// HTML/SVG files are stored byte-for-byte and served inline by /uploads, so any
// embedded JavaScript executes in the browser of whoever visits the file.

const rawUpload = express.raw({ type: '*/*', limit: '2mb' });

const BLACKLIST = ['.php', '.exe', '.sh'];

// Safe filename handling (lab hygiene, not part of the vulns): strip directories,
// allow only a safe character set, reject anything else.
function cleanFilename(name) {
  const base = path.basename(String(name || ''));
  if (!/^[a-zA-Z0-9._-]+$/.test(base)) return null;
  if (base === '.' || base === '..') return null;
  return base;
}

function storedFiles() {
  try {
    return fs.readdirSync(UPLOADS_DIR).filter((f) => {
      try { return fs.statSync(path.join(UPLOADS_DIR, f)).isFile(); } catch { return false; }
    });
  } catch { return []; }
}

// Shared storage logic. If applyBlacklist is true, v2 rules apply.
function handleUpload(req, res, applyBlacklist) {
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Missing or invalid <code>?filename=</code> query parameter. Allowed characters: <code>a-z A-Z 0-9 . _ -</code></p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  const ext = path.extname(clean).toLowerCase();

  if (applyBlacklist) {
    // VULN: the blacklist only rejects an EXACT extension match on the lowercased
    // extension. A name like shell.php.jpg has extname ".jpg" and passes, while a
    // name like evil.phtml is not in the list at all — yet both keep a dangerous
    // extension inside the filename.
    if (BLACKLIST.includes(ext)) {
      return res.status(400).send(page('Blocked', `<h2>Blocked</h2><p>The extension <code>${esc(ext)}</code> is blacklisted. Try a different name.</p><p><a class="btn" href="/upload">Back</a></p>`));
    }
  }

  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received. Upload the file bytes as the raw request body.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }

  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const url = '/uploads/' + encodeURIComponent(clean);

  let flagHtml = '';
  // v1: .html/.svg stored as-is and served inline -> stored XSS when visited
  if ((ext === '.html' || ext === '.svg') && !applyBlacklist) {
    // VULN: uploaded HTML/SVG is never sanitized, and /uploads serves it inline,
    // so visiting the stored file executes the attacker's script (stored XSS).
    const flag = award(req, 'upload', 'stored-xss');
    flagHtml = flagBox(flag) + `<p class="dim">Stored XSS captured: your file is served inline at <a href="${url}">${url}</a> — open it to see the payload run.</p>`;
  }
  // v2: blacklisted extension survived inside the filename anyway
  if (applyBlacklist && /(php|phtml|phar|exe|sh)/i.test(clean)) {
    // VULN: the exact-extname blacklist was bypassed (double extension or an
    // unlisted dangerous extension such as .phtml), so a dangerous file was stored.
    const flag = award(req, 'upload', 'blacklist-bypass');
    flagHtml = flagBox(flag) + `<p class="dim">Blacklist bypassed: <code>${esc(clean)}</code> was stored even though it contains a dangerous extension.</p>`;
  }

  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> — served at <a href="${url}">${url}</a></p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
}

// ---- routes ----
// v1: plain upload, no content validation
router.post('/', rawUpload, (req, res) => handleUpload(req, res, false));
// v2: naive exact-extension blacklist
router.post('/blacklist', rawUpload, (req, res) => handleUpload(req, res, true));

// Friendly 413 page when the 2 MB body limit is exceeded (router-scoped only).
router.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') {
    return res.status(413).send(page('Too large', `<h2>File too large</h2><p class="dim">Uploads are capped at 2 MB.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  next(err);
});

// ---- index page ----
const uploadScript = `
<script>
async function sendFile(formId, inputId, target, outId) {
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

router.get('/', (req, res) => {
  const files = storedFiles();
  const fileRows = files.length
    ? files.map((f) => {
        const url = '/uploads/' + encodeURIComponent(f);
        return `<tr><td><code>${esc(f)}</code></td><td><a href="${url}" target="_blank" rel="noopener">${url}</a></td></tr>`;
      }).join('')
    : '<tr><td colspan="2" class="dim">No files uploaded yet.</td></tr>';

  const vulnRows = module.exports.vulns.map((v) => `
    <tr>
      <td><b>${esc(v.name)}</b></td>
      <td><span class="pill">${esc(v.difficulty)}</span></td>
      <td class="dim">${esc(v.how)}</td>
    </tr>
    <tr><td colspan="3">${hintBox(v.hint)}</td></tr>`).join('');

  res.send(page('Unrestricted File Upload', uploadScript + brief('Unrestricted File Upload', `
      <p>An avatar-upload feature that never asks <i>what</i> the file actually is.
      Store a file, get a public link under <code>/uploads/</code>, and see what happens
      when the server serves it back to a browser untouched.</p>`) + `
    <h2>Challenges</h2>
    <table class="tbl"><tr><th>Vulnerability</th><th>Difficulty</th><th>Goal</th></tr>${vulnRows}</table>

    <h2>Upload endpoints</h2>
    <div class="grid2">
      <div class="card">
        <h3>v1 — plain upload <span class="pill">POST /upload?filename=</span></h3>
        <p class="dim">No content checks at all. Files are served inline, so HTML/SVG files render in the browser.</p>
        <p><input type="file" id="file1"> <button class="btn" onclick="sendFile('f1','file1','/upload','out1')">Upload to v1</button></p>
        <div id="out1"></div>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @evil.html "http://localhost:3000/upload?filename=evil.html"</pre>
      </div>
      <div class="card">
        <h3>v2 — blacklisted upload <span class="pill">POST /upload/blacklist?filename=</span></h3>
        <p class="dim">Blocks the exact extensions <code>.php</code>, <code>.exe</code>, <code>.sh</code> (lowercased). Nothing else.</p>
        <p><input type="file" id="file2"> <button class="btn" onclick="sendFile('f2','file2','/upload/blacklist','out2')">Upload to v2</button></p>
        <div id="out2"></div>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @shell.php.jpg "http://localhost:3000/upload/blacklist?filename=shell.php.jpg"</pre>
      </div>
    </div>

    <h2>Stored files</h2>
    <table class="tbl"><tr><th>Filename</th><th>Public link</th></tr>${fileRows}</table>`));
});

module.exports = {
  id: 'upload',
  name: 'Unrestricted File Upload',
  tagline: 'Upload a file, get a link. What could go wrong?',
  description: 'The uploader stores whatever you send and serves it back inline under /uploads/. Poison the stored file and bypass the naive extension blacklist.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'stored-xss',
      name: 'Stored XSS via file upload',
      difficulty: 'Easy',
      hint: 'The server accepts .html and .svg files and serves them inline, unchanged. What happens when a browser renders a file you control?',
      how: 'Upload an .html or .svg file containing JavaScript to POST /upload?filename=..., then open its /uploads/ link.'
    },
    {
      id: 'blacklist-bypass',
      name: 'Extension blacklist bypass',
      difficulty: 'Medium',
      hint: 'v2 blocks only the exact extensions .php, .exe and .sh. Check what path.extname("shell.php.jpg") returns — and notice .phtml is not on the list at all.',
      how: 'Upload shell.php.jpg or evil.phtml to POST /upload/blacklist?filename=... so a dangerous extension survives the check.'
    }
  ],
  router
};
