'use strict';
// Robots.txt Disclosure: GET /misconfig/robots.txt advertises a backup zip,
// GET /misconfig/backup.zip serves it to anyone who asks.
// zipSingle() (and its crc32/CRC_TABLE dependencies) lives in the module
// shared code at modules/misconfig/shared.js.
const express = require('express');
const { award } = require('../../../lib/flags');
const { zipSingle } = require('../shared');

const router = express.Router();

// GET /misconfig/robots.txt -> the crawler map that doubles as an attacker map.
// VULN: robots.txt advertises a sensitive backup path to anyone who reads it.
router.get('/robots.txt', (req, res) => {
  res.type('text/plain').send('User-agent: *\nDisallow: /misconfig/backup.zip\n');
});

// GET /misconfig/backup.zip -> nightly backup archive, downloadable by anyone.
// VULN: backup archive left downloadable; robots.txt pointed right at it.
router.get('/backup.zip', (req, res) => {
  const flag = award(req, 'misconfig', 'robots');
  const inner =
    `PenTrix nightly backup - admin credentials\n` +
    `username: admin\n` +
    `password: Sup3rS3cretDb!\n` +
    `backup token: ${flag}\n`;
  res.type('application/zip');
  res.send(zipSingle('backup.txt', Buffer.from(inner, 'utf8')));
});

module.exports = {
  vuln: {
    id: 'robots',
    name: 'Robots.txt Disclosure',
    difficulty: 'Easy',
    hint: 'robots.txt tells crawlers what not to fetch. Attackers read it as a treasure map.',
    hints: ["Proxy the request to the crawler rules file and ask: which disallowed entry looks like an interesting archive?", "It lists backup.zip. That's a roadmap for attackers.", "In Repeater, fetch the crawler rules file, note which disallowed entry looks like an interesting archive, then request that entry through the same path prefix."],
    tools: 'BZ, B',
    how: 'Proxy through /misconfig/robots.txt, note the disallowed archive, then fetch it via Repeater.',
    link: '/misconfig#robots',
    start: 'In Burp: enable Proxy, browse to http://localhost:3000/misconfig/robots.txt, send the request to Repeater, then request the disallowed archive through the same path prefix.',
  },
  router,
};
