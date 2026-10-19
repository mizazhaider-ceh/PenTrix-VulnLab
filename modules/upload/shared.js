'use strict';
// Upload module shared plumbing, ported verbatim from the legacy router.js so
// every challenge behaves identically after the module split. Exports exactly
// the names the challenge files import: rawUpload, cleanFilename,
// UPLOADS_DIR, avatarPath, AVATAR_ORIGINAL, AVATAR_VICTIM.
const express = require('express');
const fs = require('fs');
const path = require('path');

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

// v8: predictable avatar filenames under uploads/avatars/. Bob already has
// an avatar; anyone may write any user's file (that is the vulnerability).
const AVATAR_DIR = path.join(UPLOADS_DIR, 'avatars');
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
const AVATAR_VICTIM = 'bob';
const AVATAR_ORIGINAL = Buffer.from('BOB-ORIGINAL-AVATAR-v1');
const avatarPath = (u) => path.join(AVATAR_DIR, `avatar-${u}.png`);
if (!fs.existsSync(avatarPath(AVATAR_VICTIM))) fs.writeFileSync(avatarPath(AVATAR_VICTIM), AVATAR_ORIGINAL);

module.exports = { rawUpload, cleanFilename, UPLOADS_DIR, avatarPath, AVATAR_ORIGINAL, AVATAR_VICTIM };
