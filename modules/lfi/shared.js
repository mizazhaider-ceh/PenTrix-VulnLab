'use strict';
// Module-scoped helpers shared by the LFI challenges. No routes, no vuln.
const fs = require('fs');
const path = require('path');
const { esc, appShell, flagBox, fixPanel } = require('../../lib/page');
const { captured, flagFor } = require('../../lib/flags');

const docsDir = path.join(__dirname, 'docs');
const SECRET_MARKER = 'LFI-SECRET-8830';

// ---- planted files for the labs (created once, never overwritten) ----
const CONFIG_PATH = path.join(__dirname, 'lfi_secret.conf');
const CONFIG_MARKER = 'LFI-CONFIG-SECRET-5521';
try {
  if (!fs.existsSync(CONFIG_PATH)) {
    fs.writeFileSync(CONFIG_PATH,
      '# Internal service config - do NOT expose via the document viewer\n' +
      'db_host = 10.0.4.12\n' +
      'db_user = svc_docs\n' +
      'api_key = "' + CONFIG_MARKER + '"\n');
  }
} catch (e) { /* lab still boots; the config-read challenge will report the error */ }

const LANG_DIR = path.join(docsDir, 'lang');
try {
  if (!fs.existsSync(path.join(LANG_DIR, 'en.txt'))) {
    fs.mkdirSync(LANG_DIR, { recursive: true });
    fs.writeFileSync(path.join(LANG_DIR, 'en.txt'), 'Welcome to the document viewer.\n');
    fs.writeFileSync(path.join(LANG_DIR, 'fr.txt'), 'Bienvenue dans la visionneuse de documents.\n');
  }
} catch (e) { /* same as above */ }

// Access log for the log-poisoning chain. Every /lfi/log-demo visit appends the
// raw User-Agent header here with no filtering.
const LOG_PATH = path.join(__dirname, 'lfi_access.log');
const LOG_MARKER = 'PENTRIX-LOG-MARKER';

// /proc/self/environ only reflects the initial process environment (variables
// added later via setenv do not appear there), so the reliable tell that the
// real environ was read is a ubiquitous initial entry like PATH=.
const PROC_TELL = 'PATH=';

// The raw (still percent-encoded) value of a query parameter, taken straight
// from the request line before Express decodes anything. Needed for the
// encoding-bypass labs, where the filter and the decoder see different values.
function rawParam(req, name) {
  const m = new RegExp('[?&]' + name + '=([^&]*)').exec(req.originalUrl || '');
  return m ? m[1] : '';
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch (e) { return s; }
}

// List the benign docs so the surface is discoverable from the pages.
function listDocs() {
  try {
    return fs.readdirSync(docsDir).filter((f) => f.endsWith('.txt')).sort();
  } catch (e) {
    return [];
  }
}

// Quick-open buttons for the benign documents, styled like the rest of the app.
function docLinks(base) {
  const files = listDocs();
  if (files.length === 0) return '<p class="dim"><i>No documents found.</i></p>';
  return '<p>' + files
    .map((f) => `<a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(base)}?file=${encodeURIComponent(f)}">${esc(f)}</a>`)
    .join(' ') + '</p>';
}

// Every file read in this module goes through a byte cap. An uncapped
// readFileSync on /dev/zero, /dev/urandom, or any huge file grows memory
// until the process is OOM-killed, which is a full server-kill denial of
// service from one unauthenticated request. 256 KiB is far above anything
// these labs legitimately read (docs, /etc/passwd, /proc files).
const MAX_READ_BYTES = 256 * 1024;

// Read at most maxBytes from target, returning { ok, data } or
// { ok: false, error }. O_NONBLOCK keeps FIFOs from hanging the open, and
// the cap keeps infinite devices from eating all memory.
function readFileCapped(target, maxBytes = MAX_READ_BYTES) {
  let fd;
  try {
    fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  } catch (e) {
    return { ok: false, error: e.message };
  }
  try {
    const chunks = [];
    let total = 0;
    const buf = Buffer.alloc(64 * 1024);
    for (;;) {
      let n;
      try {
        n = fs.readSync(fd, buf, 0, buf.length, null);
      } catch (e) {
        return { ok: false, error: e.message };
      }
      if (n === 0) break;
      total += n;
      if (total > maxBytes) {
        return { ok: false, error: `refusing to read more than ${maxBytes} bytes` };
      }
      chunks.push(buf.subarray(0, n));
    }
    return { ok: true, data: Buffer.concat(chunks).toString('utf8') };
  } finally {
    try { fs.closeSync(fd); } catch (e) { /* already closed or never opened */ }
  }
}

// Read at most the last maxBytes of target (for log tails), returning
// { ok, data } or { ok: false, error }.
function readTailCapped(target, maxBytes = MAX_READ_BYTES) {
  let fd;
  try {
    const st = fs.statSync(target);
    fd = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
    const start = Math.max(0, st.size - maxBytes);
    const len = Math.min(st.size, maxBytes);
    const buf = Buffer.alloc(len);
    let off = 0;
    while (off < len) {
      const n = fs.readSync(fd, buf, off, len - off, start + off);
      if (n === 0) break;
      off += n;
    }
    return { ok: true, data: buf.subarray(0, off).toString('utf8') };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (e) { /* ignore */ } }
  }
}

function readTarget(file) {
  // VULN: user-controlled path joined to docsDir and read with no checks.
  const target = path.join(docsDir, file);
  const r = readFileCapped(target);
  if (r.ok) return { ok: true, target, data: r.data };
  return { ok: false, target, error: r.error };
}

function showCaptured(req, vulnId) {
  return captured(req, 'lfi', vulnId)
    ? flagBox(flagFor('lfi', vulnId)) + fixPanel('lfi', vulnId)
    : '';
}

// PenDocs: the fictional document portal every LFI page belongs to.
function docsPage(crumb, bodyHtml) {
  return appShell('PenDocs', bodyHtml, {
    nav: ['Library', 'Downloads', 'Settings'],
    crumb,
    mark: '\u{1F4C4}',
  });
}

module.exports = {
  docsDir, SECRET_MARKER, CONFIG_PATH, CONFIG_MARKER, LANG_DIR, LOG_PATH, LOG_MARKER, PROC_TELL,
  MAX_READ_BYTES, readFileCapped, readTailCapped,
  rawParam, safeDecode, listDocs, docLinks, readTarget, showCaptured, docsPage,
};
