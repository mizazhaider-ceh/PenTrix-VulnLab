'use strict';
// Upload module shared plumbing, ported verbatim from the legacy router.js so
// every challenge behaves identically after the module split. Exports exactly
// the names the challenge files import: rawUpload, cleanFilename,
// UPLOADS_DIR, avatarPath, AVATAR_ORIGINAL, AVATAR_VICTIM.
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createSessionState } = require('../../lib/session-state');

// Binary body parsing for every upload POST (raw request bytes, 2 MB cap).
const rawUpload = express.raw({ type: '*/*', limit: '2mb' });

// The project-root uploads/ dir, served inline by app.js at /uploads.
const UPLOADS_DIR = path.join(__dirname, '..', '..', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Safe filename handling (lab hygiene, not part of the vulns): strip
// directories, allow only a safe character set, reject anything else.
function cleanFilename(name) {
  const base = path.basename(String(name || ''));
  if (!/^[a-zA-Z0-9._-]+$/.test(base)) return null;
  if (base === '.' || base === '..') return null;
  return base;
}

// Upload quota (P5-3, reworked for per-session accounting): uploads
// accumulate forever otherwise, and a lab or a test suite can fill the disk
// with probe files. The original sweep kept only the newest 200 files in
// the uploads root as one global pool, so a single flooding session could
// evict every other student's stored files and silently break their
// beacon proofs and traversal read-backs. Quota is now strict per-session
// accounting (D19: per-session state by default):
//
//   - Every challenge handler that stores a file directly in the uploads
//     root calls trackStoredUpload(req, name) right after the write. The
//     call records the name, oldest first, in the owning session's bucket
//     (lib/session-state, keyed by session id, in process memory).
//   - The cap stays at the same order of magnitude as the old global cap:
//     200 files per session. A real student needs a handful of live files
//     at once (one payload per challenge, plus retries), so 200 is
//     generous headroom, not a limit anyone honest should feel, while
//     still bounding what one session can hold on disk.
//   - Enforcement runs synchronously inside trackStoredUpload, against
//     the owning session's list only. Eviction removes that session's
//     oldest names and unlinks a file only when no session claims it any
//     more: if two sessions stored the same filename (the flat uploads
//     namespace is shared by design), the surviving session's claim keeps
//     the file on disk. No code path here ever unlinks a file because a
//     different session uploaded something.
//   - The module middleware in index.js also calls
//     enforceUploadQuota(req) per request; it only ever sees the
//     requesting session's own bucket, so it can only trim that session.
//
// Scope, unchanged from the old sweep: only files stored directly in the
// uploads root are quota-managed. The avatars/ subdirectory is not (its
// filenames are the challenges' own state), and neither are escaped files
// written outside the uploads root by the traversal challenges.
//
// Files whose session is gone: a session bucket that stays idle past the
// session TTL (lib/session-state sweeps hourly; the TTL matches the
// session store) is evicted, and the eviction hook below releases that
// session's claims, deleting files no other session claims. That is an
// age-based sweep of expired sessions only; it never runs per-request
// against other active sessions. Buckets lost to a process restart cannot
// be reconstructed, so their files are deliberately left in place at
// boot: guessing ownership from file age could delete a returning
// student's file or a shipped example file, and orphaned files left by a
// restart stay bounded by the per-session cap their owners were under.
const MAX_KEPT_UPLOADS_PER_SESSION = 200;
// Legacy export name, kept for any existing importer: it now means the
// per-session cap above, not a global pool size.
const MAX_KEPT_UPLOADS = MAX_KEPT_UPLOADS_PER_SESSION;

// How many distinct sessions currently claim each stored name. A name is
// only unlinked when its last claim is released.
const uploadClaimCounts = new Map();

function releaseUploadClaim(name) {
  const left = (uploadClaimCounts.get(name) || 0) - 1;
  if (left > 0) { uploadClaimCounts.set(name, left); return; }
  uploadClaimCounts.delete(name);
  try { fs.unlinkSync(path.join(UPLOADS_DIR, name)); } catch { /* already gone */ }
}

// Per-session ownership buckets: session id -> { files: [names, oldest
// first] }. The eviction hook fires when a session bucket expires, which
// is the "session is gone" cleanup described above.
const uploadOwnership = createSessionState(() => ({ files: [] }), {
  onEvict: (state) => {
    for (const name of (state && state.files) || []) releaseUploadClaim(name);
  },
});

// Trim ONLY the requesting session's stored files back to its cap,
// oldest first. A request with no session bucket (nothing tracked yet)
// is a no-op, and no other session's bucket is ever read here.
function enforceUploadQuota(req) {
  if (!req) return;
  let state;
  try { state = uploadOwnership.peek(req); } catch { return; }
  if (!state) return;
  while (state.files.length > MAX_KEPT_UPLOADS_PER_SESSION) {
    releaseUploadClaim(state.files.shift());
  }
}

// Record that THIS session just stored `file` (a plain basename, directly
// in the uploads root) and immediately enforce this session's own quota.
// Re-storing a name the session already claims only refreshes its recency;
// it does not add a second claim. Returns false when the name is not a
// flat uploads-root name or the request has no session to account against,
// in which case nothing is recorded and nothing is deleted.
function trackStoredUpload(req, file) {
  const name = String(file || '');
  if (!name || path.basename(name) !== name) return false;
  let state;
  try { state = uploadOwnership.get(req); } catch { return false; }
  const at = state.files.indexOf(name);
  if (at >= 0) state.files.splice(at, 1);
  else uploadClaimCounts.set(name, (uploadClaimCounts.get(name) || 0) + 1);
  state.files.push(name);
  enforceUploadQuota(req);
  return true;
}

// v8: predictable avatar filenames under uploads/avatars/. Bob already has
// an avatar; anyone may write any user's file (that is the vulnerability).
const AVATAR_DIR = path.join(UPLOADS_DIR, 'avatars');
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
const AVATAR_VICTIM = 'bob';
const AVATAR_ORIGINAL = Buffer.from('BOB-ORIGINAL-AVATAR-v1');
const avatarPath = (u) => path.join(AVATAR_DIR, `avatar-${u}.png`);
if (!fs.existsSync(avatarPath(AVATAR_VICTIM))) fs.writeFileSync(avatarPath(AVATAR_VICTIM), AVATAR_ORIGINAL);

// ---------------------------------------------------------------------------
// Execution-proof beacons (flag integrity): storing a file proves nothing on
// its own. An upload is only solved when the stored file is later served
// inline with an executable content type AND its script actually runs and
// calls POST /upload/beacon with the per-session token that was issued for
// that challenge. The beacon handler lives in modules/upload/index.js; the
// helpers below are the shared evidence model every challenge relies on.
// ---------------------------------------------------------------------------

// Real script markers: a stored file must contain executable content, not
// merely a dangerous-looking name.
function hasExecutableContent(buf) {
  const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf || '');
  return /<script[\s>]|on\w+\s*=\s*["']|javascript\s*:/i.test(text);
}

// The content type the module's /upload/view/:name surface sends for a name
// (substring guessing, exactly as the viewer does it).
function viewServedType(name) {
  const lower = String(name || '').toLowerCase();
  if (lower.includes('.svg')) return 'image/svg+xml';
  if (lower.includes('.html') || lower.includes('.htm')) return 'text/html';
  return 'application/octet-stream';
}

// The content type the app.js /uploads static mount sends for a name.
function staticServedType(name) {
  const ext = path.extname(String(name || '')).toLowerCase();
  if (ext === '.html' || ext === '.htm') return 'text/html';
  if (ext === '.svg') return 'image/svg+xml';
  return 'application/octet-stream';
}

// The content type the given challenge's serving surface sends for this file.
function servedTypeFor(vulnId, name, buf) {
  if (vulnId === 'stored-xss') return staticServedType(name);
  if (vulnId === 'upload-polyglot') return 'text/html';
  if (vulnId === 'upload-overwrite') return (buf && buf.length && buf[0] === 0x3c) ? 'text/html' : 'image/png';
  return viewServedType(name);
}

// Per-challenge bypass shape, evaluated against the stored artifact at beacon
// time. This is what keeps one upload from awarding a sibling challenge: the
// beacon for challenge X only passes when the stored file satisfies X's own
// bypass condition, not merely "some dangerous file exists".
function bypassShapeFor(vulnId, name, buf) {
  const ext = path.extname(String(name || ''));
  const lcExt = ext.toLowerCase();
  const ACTIVE = ['.svg', '.html', '.htm'];
  switch (vulnId) {
    case 'stored-xss': return ACTIVE.includes(lcExt);
    case 'upload-case': return ACTIVE.includes(lcExt) && !ACTIVE.includes(ext); // raw ext differs in case from the blacklist entries
    case 'upload-double-ext': return /\.(svg|html?)\./i.test(String(name || ''));
    case 'upload-ctype': return ACTIVE.includes(lcExt);
    case 'upload-strip-once': return ACTIVE.includes(lcExt);
    case 'upload-polyglot': {
      const head = Buffer.isBuffer(buf) ? buf.slice(0, 6).toString('ascii') : '';
      return head === 'GIF89a' || head === 'GIF87a';
    }
    case 'upload-overwrite': return true; // shape is the victim path itself; the diff check runs in verifyBeacon
    default: return false;
  }
}

// Per-session beacon token for a challenge. Issued on the module page (and
// echoed in upload responses) so the student can bake it into their payload
// before uploading; stable for the session until consumed by a success.
function issueBeaconToken(req, vulnId) {
  req.session = req.session || {};
  req.session.uploadBeacons = req.session.uploadBeacons || {};
  if (!req.session.uploadBeacons[vulnId]) {
    req.session.uploadBeacons[vulnId] = crypto.randomBytes(16).toString('hex');
  }
  return req.session.uploadBeacons[vulnId];
}

// Records, at upload time, that THIS session stored `file` through challenge
// `vulnId`'s endpoint with that endpoint's bypass condition met. No flag is
// awarded here; the record only arms the beacon check.
function recordPendingUpload(req, vulnId, file) {
  req.session = req.session || {};
  req.session.uploadPending = req.session.uploadPending || {};
  req.session.uploadPending[vulnId] = { file: String(file), at: Date.now() };
}

// The JS snippet a payload must run when its file is served, so a genuine
// browser execution phones home. Rendered on the module page and in upload
// responses; `file` is the stored name the beacon will be checked against.
function beaconSnippet(vulnId, file, token) {
  return `<script>fetch('/upload/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:${JSON.stringify(vulnId)},file:${JSON.stringify(String(file))},token:${JSON.stringify(token)}})})</script>`;
}

// Full beacon verification. Returns { ok: true } or { ok: false, reason }.
// A direct POST is accepted only when every check passes for this session:
// the posted token matches the per-session token issued for this challenge,
// a pending upload was recorded through this challenge's own endpoint (and
// the posted file name matches that record), the stored file is still
// present, this challenge's bypass shape is satisfied, the file is served
// with an executable content type, an executable script is present in the
// file bytes, and the per-session token is embedded in the file bytes.
function verifyBeacon(req, vulnId, token, file) {
  const beacons = (req.session && req.session.uploadBeacons) || {};
  const expected = beacons[vulnId];
  if (!expected || !token || token !== expected) return { ok: false, reason: 'unknown or mismatched beacon token for this challenge' };
  const pending = ((req.session && req.session.uploadPending) || {})[vulnId];
  if (!pending) return { ok: false, reason: 'no qualifying upload for this challenge is on record for your session (an upload only counts for the challenge whose bypass shape it satisfies, even when two challenges share the same endpoint)' };
  if (String(file) !== pending.file) return { ok: false, reason: 'the beacon file does not match the stored filename recorded for this challenge (use the stored name shown in the upload response, the filter may have renamed the file you sent)' };
  let fp;
  if (vulnId === 'upload-overwrite') {
    if (!/^[a-z0-9]{1,20}$/.test(String(file))) return { ok: false, reason: 'bad avatar user' };
    fp = avatarPath(String(file));
  } else {
    const base = path.basename(String(file));
    if (!base || base !== String(file)) return { ok: false, reason: 'bad stored filename' };
    fp = path.join(UPLOADS_DIR, base);
  }
  if (!fs.existsSync(fp)) return { ok: false, reason: 'the stored file is gone' };
  const buf = fs.readFileSync(fp);
  if (!bypassShapeFor(vulnId, String(file), buf)) return { ok: false, reason: 'the stored file does not satisfy this challenge bypass shape' };
  const type = servedTypeFor(vulnId, String(file), buf);
  if (type !== 'text/html' && type !== 'image/svg+xml') return { ok: false, reason: `the file is served as ${type}, not as executable content` };
  if (!hasExecutableContent(buf)) return { ok: false, reason: 'the stored file contains no executable script' };
  if (!buf.includes(Buffer.from(expected))) return { ok: false, reason: 'the beacon token is not inside the stored file, so this beacon did not come from its script' };
  if (vulnId === 'upload-overwrite' && buf.equals(AVATAR_ORIGINAL)) return { ok: false, reason: 'the victim avatar still holds its original bytes' };
  // Consume the pending record: a fresh upload is needed for another proof.
  delete req.session.uploadPending[vulnId];
  return { ok: true };
}
module.exports = { rawUpload, cleanFilename, UPLOADS_DIR, avatarPath, AVATAR_ORIGINAL, AVATAR_VICTIM, enforceUploadQuota, trackStoredUpload, MAX_KEPT_UPLOADS, MAX_KEPT_UPLOADS_PER_SESSION ,
  hasExecutableContent, viewServedType, staticServedType, servedTypeFor, bypassShapeFor,
  issueBeaconToken, recordPendingUpload, beaconSnippet, verifyBeacon,
};
