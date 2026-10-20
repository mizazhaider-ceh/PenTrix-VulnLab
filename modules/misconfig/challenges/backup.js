'use strict';
// Security Misconfiguration: an exposed database backup. The dump was dropped
// into the web-accessible tree and is served as plain text to anyone who asks
// for the right filename.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { award } = require('../../../lib/flags');

const router = express.Router();

const BACKUP_PATH = path.join(__dirname, '..', 'backup.sql');

const vuln = {
  id: 'backup',
  name: 'Exposed Database Backup',
  difficulty: 'Easy',
  hint: 'Admins sometimes leave database dumps where the web server can serve them. Guess the filename.',
  hints: [
    "Think like an admin in Burp's Proxy history: which backup filenames end up in a web root?",
    "One classic dump filename in the web root gets served to anyone as plain text: a full database backup, readable end to end.",
    "In Burp Repeater, send GET requests for common backup filenames under /misconfig/ until one returns a dump instead of a 404, then search the response body for plaintext credentials or tokens.",
  ],
  tools: 'BZ, B',
  est: 'about 5 minutes',
  how: 'A database dump left under the web root is served to anyone who guesses its name, credentials and all.',
  link: '/misconfig#backup',
  start: 'Proxy your lab address in Burp, browse to /misconfig, then replay the page request in Repeater and try common backup filenames under the same prefix, searching any promising response.',
};

// GET /misconfig/backup.sql -> serves the backup dump verbatim, prefixed with
// a visible capture banner carrying the real flag. The award used to fire
// silently while the dump itself ended in a flag-shaped decoy line, so
// beginners copied the decoy as their answer (P3-9). The decoy line is gone
// from backup.sql, and the banner makes the real award unmissable.
router.get('/backup.sql', (req, res) => {
  // VULN: sensitive database backup stored inside the web-accessible tree and served to anyone who asks
  const flag = award(req, 'misconfig', 'backup');
  const banner = `-- ================================================================\n-- PenTrix VulnLab: FLAG CAPTURED for challenge "Exposed Database Backup".\n-- Your flag: ${flag}\n-- (It is also on your scoreboard. The dump below is what leaked.)\n-- ================================================================\n\n`;
  const dump = fs.readFileSync(BACKUP_PATH, 'utf8');
  res.type('text/plain');
  res.send(banner + dump);
});

module.exports = { vuln, router };
