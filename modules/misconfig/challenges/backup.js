'use strict';
// Security Misconfiguration: an exposed database backup. The dump was dropped
// into the web-accessible tree and is served as plain text to anyone who asks
// for the right filename.
const express = require('express');
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
    "backup.sql in the web root gets served to anyone as plain text. It is a full database dump.",
    "In Burp Repeater, send GET requests for common backup filenames under /misconfig/ until one returns a dump instead of a 404, then search the response body for plaintext credentials or tokens.",
  ],
  tools: 'BZ, B',
  how: 'With Burp Proxy on, browse to /misconfig, then guess the backup filename in Repeater and read the returned dump for plaintext credentials and tokens.',
  link: '/misconfig#backup',
  start: 'Proxy http://localhost:3000 in Burp, browse to /misconfig, then replay the page request in Repeater with the path changed to /misconfig/backup.sql and search the response dump.',
};

// GET /misconfig/backup.sql -> serves the backup dump verbatim.
router.get('/backup.sql', (req, res) => {
  // VULN: sensitive database backup stored inside the web-accessible tree and served to anyone who asks
  award(req, 'misconfig', 'backup');
  res.type('text/plain');
  res.sendFile(BACKUP_PATH);
});

module.exports = { vuln, router };
