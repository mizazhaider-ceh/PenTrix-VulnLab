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
  let flagHtml = '';
  if (['.svg', '.html', '.htm'].includes(ext.toLowerCase())) {
    // VULN: case-sensitive blacklist bypassed — ".SVG" is still SVG.
    flagHtml += flagBox(award(req, 'upload', 'upload-case')) + `<p class="dim">Case bypass: <code>${esc(clean)}</code> was stored and is served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  }
  if (/\.(svg|html?)\./i.test(clean)) {
    // VULN: double extension — the final ".jpg" passed, but the file is
    // served as SVG/HTML because of the earlier extension.
    flagHtml += flagBox(award(req, 'upload', 'upload-double-ext')) + `<p class="dim">Double extension bypass: <code>${esc(clean)}</code> passed as <code>${esc(ext)}</code> but is served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  }
  if (!flagHtml) flagHtml = `<p class="dim">Stored. Neither a case variant nor a double extension was used, so nothing was bypassed.</p>`;
  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> — view it at <a href="${viewUrl}">${viewUrl}</a></p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

// Naive content-type detection for the ext-blacklist lab: the served type is
// guessed from a substring of the stored filename.
router.get('/view/:name', (req, res) => {
  const name = path.basename(String(req.params.name || ''));
  const fp = path.join(UPLOADS_DIR, name);
  if (!name || !fs.existsSync(fp)) {
    return res.status(404).send(page('Not found', `<h2>Not found</h2><p class="dim">No such stored file.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  const lower = name.toLowerCase();
  // VULN: substring-based type detection — "shell.svg.jpg" contains ".svg"
  // and is served as SVG, turning the blacklist bypass into stored XSS.
  if (lower.includes('.svg')) res.type('image/svg+xml');
  else if (lower.includes('.html') || lower.includes('.htm')) res.type('text/html');
  else res.type('application/octet-stream');
  res.send(fs.readFileSync(fp));
});

// ---- v4: Content-Type header "validation" ----
router.post('/mime-check', rawUpload, (req, res) => {
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Missing or invalid <code>?filename=</code> query parameter.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  const ctype = String(req.get('content-type') || '');
  // VULN: the only "validation" is the client-supplied Content-Type header;
  // the file bytes are never inspected, so the header can simply be lied about.
  if (!ctype.toLowerCase().startsWith('image/')) {
    return res.status(400).send(page('Blocked', `<h2>Blocked</h2><p>Only images may be uploaded (detected via the <code>Content-Type</code> header: <code>${esc(ctype) || '(none)'}</code>).</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const ext = path.extname(clean).toLowerCase();
  const viewUrl = '/upload/view/' + encodeURIComponent(clean);
  let flagHtml = '';
  if (['.html', '.htm', '.svg'].includes(ext)) {
    // VULN: the header claimed image/*, so an HTML/SVG file was accepted and
    // stored; it is served back as active content.
    flagHtml = flagBox(award(req, 'upload', 'upload-ctype')) + `<p class="dim">Header spoofed: <code>${esc(clean)}</code> was accepted as <code>${esc(ctype)}</code> and is served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored as an image. To beat this check, the filename must still end in <code>.html</code> or <code>.svg</code>.</p>`;
  }
  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> with Content-Type <code>${esc(ctype)}</code>.</p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

// ---- v5: SVG avatars without event-handler sanitization ----
router.post('/svg-avatar', rawUpload, (req, res) => {
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Missing or invalid <code>?filename=</code> query parameter.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (path.extname(clean).toLowerCase() !== '.svg') {
    return res.status(400).send(page('Blocked', `<h2>Blocked</h2><p>Avatars must be <code>.svg</code> files.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const url = '/uploads/' + encodeURIComponent(clean);
  const text = req.body.toString('utf8');
  let flagHtml = '';
  // VULN: SVG uploads are allowed without stripping event-handler
  // attributes, so an onload handler survives and runs when the file is
  // opened directly (served inline as image/svg+xml).
  if (/onload\s*=/i.test(text)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-svg-onload')) + `<p class="dim">Event handler survived: open <a href="${url}" target="_blank" rel="noopener">${url}</a> directly and the <code>onload</code> script runs.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored, but no event handler was found in the SVG. The lab wants an <code>onload</code> handler.</p>`;
  }
  res.send(page('Uploaded', `<h2>Avatar stored</h2>
    <p>Saved as <code>${esc(clean)}</code> — served at <a href="${url}" target="_blank" rel="noopener">${url}</a></p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

// ---- v6: strip-once sanitizer (null-byte truncation is not exploitable on
// this stack: Node's fs rejects NUL bytes in paths, so this classic bypass is
// replaced with the equally real "filter applied only once" bypass) ----
const STRIP_BAD = ['.svg', '.html', '.htm'];

router.post('/filter', rawUpload, (req, res) => {
  let name = String(req.query.filename || '');
  // VULN: the sanitizer strips each dangerous extension only ONCE with a
  // non-global replace, so a nested name like "evil.s.svgvg" becomes "evil.svg".
  for (const bad of STRIP_BAD) name = name.replace(bad, '');
  const clean = cleanFilename(name);
  if (!clean) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Invalid filename after filtering.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const ext = path.extname(clean).toLowerCase();
  const viewUrl = '/upload/view/' + encodeURIComponent(clean);
  let flagHtml = '';
  if (['.svg', '.html', '.htm'].includes(ext)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-strip-once')) + `<p class="dim">Filter bypassed once: stored as <code>${esc(clean)}</code>, served as active content at <a href="${viewUrl}">${viewUrl}</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored as <code>${esc(clean)}</code>. The filter stripped the dangerous extension, so nothing was bypassed.</p>`;
  }
  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> — view it at <a href="${viewUrl}">${viewUrl}</a></p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

// ---- v7: path traversal on write ----
router.post('/traverse', rawUpload, (req, res) => {
  const raw = String(req.query.filename || '');
  if (!raw || raw === '.' || raw === '..') {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Missing <code>?filename=</code> query parameter.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  // VULN: the filename is joined to the uploads dir with no basename or
  // containment check, so "../" segments escape the uploads directory.
  const target = path.normalize(path.join(UPLOADS_DIR, raw));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, req.body);
  const outside = !target.startsWith(UPLOADS_DIR + path.sep);
  let flagHtml = '';
  if (outside && fs.existsSync(target)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-traversal')) + `<p class="dim">Escaped the uploads dir: retrieve it at <a href="/upload/traversed?f=${encodeURIComponent(raw)}">/upload/traversed?f=${encodeURIComponent(raw)}</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored inside the uploads dir. To escape it, the filename must resolve outside of it.</p>`;
  }
  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(raw)}</code></p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

// Retrieval surface for the traversal lab: reads relative to the uploads dir
// with the same missing containment check.
router.get('/traversed', (req, res) => {
  const f = String(req.query.f || '');
  // VULN: same missing containment check on read, so escaped files are retrievable.
  let target;
  try {
    target = path.normalize(path.join(UPLOADS_DIR, f));
    if (!f || !fs.existsSync(target) || !fs.statSync(target).isFile()) throw new Error('nope');
  } catch (e) {
    return res.status(404).send(page('Not found', `<h2>Not found</h2><p class="dim">No such file.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  res.type('text/plain');
  res.send(fs.readFileSync(target));
});

// ---- v8: predictable avatar filenames (overwrite) ----
const AVATAR_DIR = path.join(UPLOADS_DIR, 'avatars');
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
const AVATAR_VICTIM = 'bob';
const AVATAR_ORIGINAL = Buffer.from('BOB-ORIGINAL-AVATAR-v1');
const avatarPath = (u) => path.join(AVATAR_DIR, `avatar-${u}.png`);
if (!fs.existsSync(avatarPath(AVATAR_VICTIM))) fs.writeFileSync(avatarPath(AVATAR_VICTIM), AVATAR_ORIGINAL);

router.post('/avatar', rawUpload, (req, res) => {
  const user = String(req.query.user || '').toLowerCase();
  if (!/^[a-z0-9]{1,20}$/.test(user)) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Provide <code>?user=</code> (letters and digits, max 20).</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(page('Upload failed', `<h2>Empty file</h2><p class="dim">No request body received.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  // VULN: avatar filenames are predictable ("avatar-<user>.png") and anyone
  // may write any user's file, so another user's avatar can be overwritten.
  fs.writeFileSync(avatarPath(user), req.body);
  let flagHtml = '';
  if (user === AVATAR_VICTIM && !fs.readFileSync(avatarPath(user)).equals(AVATAR_ORIGINAL)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-overwrite')) + `<p class="dim">Bob's avatar now serves your bytes: <a href="/upload/avatar/bob">/upload/avatar/bob</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored. The victim's avatar is <a href="/upload/avatar/bob">/upload/avatar/bob</a> (user <code>bob</code>).</p>`;
  }
  res.send(page('Avatar stored', `<h2>Avatar stored</h2>
    <p>Saved avatar for <code>${esc(user)}</code>.</p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

router.get('/avatar/:user', (req, res) => {
  const user = String(req.params.user || '').toLowerCase();
  if (!/^[a-z0-9]{1,20}$/.test(user)) return res.status(404).send('no such avatar');
  const fp = avatarPath(user);
  if (!fs.existsSync(fp)) return res.status(404).send('no such avatar');
  const buf = fs.readFileSync(fp);
  // VULN: content sniffing instead of a fixed image type, so a replaced
  // "avatar" that starts with "<" is served as HTML.
  if (buf.length && buf[0] === 0x3c) res.type('text/html');
  else res.type('image/png');
  res.send(buf);
});

// ---- v9: GIF polyglot (magic bytes + HTML) ----
router.post('/polyglot', rawUpload, (req, res) => {
  const clean = cleanFilename(req.query.filename);
  if (!clean) {
    return res.status(400).send(page('Upload failed', `<h2>Upload failed</h2><p class="dim">Missing or invalid <code>?filename=</code> query parameter.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  const head = Buffer.isBuffer(req.body) ? req.body.slice(0, 6).toString('ascii') : '';
  // VULN: the "image validation" only checks the 6 magic bytes; everything
  // after them can be arbitrary HTML, and the file is later served as HTML.
  if (head !== 'GIF89a' && head !== 'GIF87a') {
    return res.status(400).send(page('Blocked', `<h2>Blocked</h2><p>Only GIF images pass validation (magic-byte check).</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  fs.writeFileSync(path.join(UPLOADS_DIR, clean), req.body);
  const text = req.body.toString('utf8');
  const polyUrl = '/upload/poly/' + encodeURIComponent(clean);
  let flagHtml = '';
  if (/<script[\s>]|on\w+\s*=/i.test(text)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-polyglot')) + `<p class="dim">Magic bytes passed, scriptable HTML survived: rendered at <a href="${polyUrl}" target="_blank" rel="noopener">${polyUrl}</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored, but no scriptable HTML was found. The lab wants a GIF header plus real HTML/JS after it.</p>`;
  }
  res.send(page('Uploaded', `<h2>File stored</h2>
    <p>Saved as <code>${esc(clean)}</code> — rendered at <a href="${polyUrl}" target="_blank" rel="noopener">${polyUrl}</a></p>
    ${flagHtml}
    <p><a class="btn" href="/upload">Back to module</a></p>`));
});

router.get('/poly/:name', (req, res) => {
  const name = path.basename(String(req.params.name || ''));
  const fp = path.join(UPLOADS_DIR, name);
  if (!name || !fs.existsSync(fp)) {
    return res.status(404).send(page('Not found', `<h2>Not found</h2><p class="dim">No such stored file.</p><p><a class="btn" href="/upload">Back</a></p>`));
  }
  // VULN: the "validated image" is served as text/html with no
  // X-Content-Type-Options, so the polyglot's HTML half executes in the browser.
  res.set('Content-Type', 'text/html');
  res.send(fs.readFileSync(fp));
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

    <h2>More upload endpoints</h2>
    <div class="grid2">
      <div class="card">
        <h3>v3 — SVG/HTML blacklist <span class="pill">POST /upload/ext-blacklist?filename=</span></h3>
        <p class="dim">Blocks <code>.svg</code>, <code>.html</code>, <code>.htm</code> by exact, case-sensitive final extension. Served back via <code>/upload/view/:name</code>, which guesses the content type from the filename.</p>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @evil.svg.jpg "http://localhost:3000/upload/ext-blacklist?filename=evil.svg.jpg"</pre>
      </div>
      <div class="card">
        <h3>v4 — Content-Type check <span class="pill">POST /upload/mime-check?filename=</span></h3>
        <p class="dim">"Only images allowed" — but the check reads only the <code>Content-Type</code> request header, never the bytes.</p>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @evil.html -H "Content-Type: image/png" "http://localhost:3000/upload/mime-check?filename=evil.html"</pre>
      </div>
      <div class="card">
        <h3>v5 — SVG avatars <span class="pill">POST /upload/svg-avatar?filename=</span></h3>
        <p class="dim">Only <code>.svg</code> accepted, served inline. Event-handler attributes are never stripped.</p>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @xss.svg "http://localhost:3000/upload/svg-avatar?filename=xss.svg"</pre>
      </div>
      <div class="card">
        <h3>v6 — strip-once filter <span class="pill">POST /upload/filter?filename=</span></h3>
        <p class="dim">Strips <code>.svg</code>/<code>.html</code>/<code>.htm</code> from the filename exactly once, then stores whatever is left.</p>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @evil.svg "http://localhost:3000/upload/filter?filename=evil.s.svgvg"</pre>
      </div>
      <div class="card">
        <h3>v7 — traversal upload <span class="pill">POST /upload/traverse?filename=</span></h3>
        <p class="dim">No basename, no containment check: <code>../</code> in the filename escapes the uploads directory. Read escaped files at <code>/upload/traversed?f=</code>.</p>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @pwn.txt "http://localhost:3000/upload/traverse?filename=../pwn.txt"</pre>
      </div>
      <div class="card">
        <h3>v8 — user avatars <span class="pill">POST /upload/avatar?user=</span></h3>
        <p class="dim">Avatars live at predictable paths (<code>avatar-&lt;user&gt;.png</code>) and anyone can write any user's file. Victim <code>bob</code> already has one: <a href="/upload/avatar/bob">/upload/avatar/bob</a>.</p>
        <p class="dim">curl version:</p>
        <pre>curl --data-binary @evil.png "http://localhost:3000/upload/avatar?user=bob"</pre>
      </div>
      <div class="card">
        <h3>v9 — GIF magic-byte check <span class="pill">POST /upload/polyglot?filename=</span></h3>
        <p class="dim">"Image validation" checks only the 6 GIF magic bytes. The file is later served as <code>text/html</code> at <code>/upload/poly/:name</code>.</p>
        <p class="dim">curl version:</p>
        <pre>printf 'GIF89a&lt;script&gt;alert(1)&lt;/script&gt;' | curl --data-binary @- "http://localhost:3000/upload/polyglot?filename=x.gif"</pre>
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
    },
    {
      id: 'upload-double-ext',
      name: 'Double extension bypass',
      difficulty: 'Medium',
      hint: 'v3 blocks .svg/.html by exact final extension only, and the viewer guesses the content type from the filename. What does path.extname("shell.svg.jpg") return?',
      how: 'Upload shell.svg.jpg to POST /upload/ext-blacklist?filename=..., then open its /upload/view/ link to see it served as SVG.'
    },
    {
      id: 'upload-case',
      name: 'Case-sensitive blacklist bypass',
      difficulty: 'Easy',
      hint: 'The v3 blacklist compares the extension exactly as written. Filesystems and browsers do not care about case.',
      how: 'Upload evil.SVG (uppercase) to POST /upload/ext-blacklist?filename=... so the ".svg" entry misses it.'
    },
    {
      id: 'upload-ctype',
      name: 'Content-Type header spoofing',
      difficulty: 'Easy',
      hint: 'v4 decides "is this an image" from the Content-Type request header alone. Headers are attacker-controlled.',
      how: 'Upload an .html file to POST /upload/mime-check?filename=... with -H "Content-Type: image/png".'
    },
    {
      id: 'upload-traversal',
      name: 'Path traversal on write',
      difficulty: 'Medium',
      hint: 'v7 joins your filename to the uploads dir with no basename or containment check. Where does "../pwn.txt" resolve?',
      how: 'Upload to POST /upload/traverse?filename=../pwn.txt so the file lands outside the uploads dir, then read it back via /upload/traversed?f=../pwn.txt.'
    },
    {
      id: 'upload-svg-onload',
      name: 'SVG onload stored XSS',
      difficulty: 'Easy',
      hint: 'v5 accepts .svg avatars and serves them inline without stripping event handlers. SVG is XML: any element can carry onload.',
      how: 'Upload an .svg containing an onload handler (e.g. <svg onload="alert(1)">) to POST /upload/svg-avatar?filename=..., then open its /uploads/ link directly.'
    },
    {
      id: 'upload-strip-once',
      name: 'Strip-once filter bypass',
      difficulty: 'Medium',
      hint: 'v6 removes each dangerous extension exactly once with a non-global replace. Nest the extension inside itself so one removal rebuilds it.',
      how: 'Upload to POST /upload/filter?filename=evil.s.svgvg — after the single strip the stored name is evil.svg.'
    },
    {
      id: 'upload-overwrite',
      name: 'Avatar overwrite',
      difficulty: 'Medium',
      hint: 'Avatar paths are predictable (avatar-<user>.png) and the endpoint never checks that you own the target user. Bob already has an avatar.',
      how: 'POST your bytes to /upload/avatar?user=bob so the victim avatar URL /upload/avatar/bob serves attacker content.'
    },
    {
      id: 'upload-polyglot',
      name: 'GIF/HTML polyglot',
      difficulty: 'Hard',
      hint: 'v9 validates only the 6 GIF magic bytes, then serves the file as text/html. A file can be a valid GIF header and valid HTML at once.',
      how: 'Upload bytes starting with GIF89a followed by HTML/JS (e.g. GIF89a<script>alert(1)</script>) to POST /upload/polyglot?filename=..., then open its /upload/poly/ link.'
    }
  ],
  router
};
