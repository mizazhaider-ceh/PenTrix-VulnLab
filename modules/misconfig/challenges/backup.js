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
  hints: ["Is there a database backup in the web root? What files might be there?", "backup.sql or db.bak in the web root gets served to anyone. It's a full database dump.", "Fetch /misconfig/backup.sql (or guess the name) and read it."],
  tools: 'B, C',
  how: 'Download /misconfig/backup.sql and read the dump for plaintext credentials and tokens.',
  link: '/misconfig#backup',
  start: 'curl -s http://localhost:3000/misconfig/backup.sql | head -40',
};

// GET /misconfig/backup.sql -> serves the backup dump verbatim.
router.get('/backup.sql', (req, res) => {
  // VULN: sensitive database backup stored inside the web-accessible tree and served to anyone who asks
  award(req, 'misconfig', 'backup');
  res.type('text/plain');
  res.sendFile(BACKUP_PATH);
});

module.exports = { vuln, router };
