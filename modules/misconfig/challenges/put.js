'use strict';
// Unauthenticated HTTP PUT: PUT /misconfig/files/:name writes a raw file with
// no authentication at all, and GET /misconfig/files/:name serves it straight
// back. Reading your upload back proves the arbitrary write and awards the flag.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { esc, hintBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const FILES_DIR = path.join(__dirname, '..', 'public-files');

// Shared module state (modules/misconfig/shared.js): names of files written
// through the unauthenticated PUT endpoint, so the listing challenge's
// serveFile awards the read-back flag. This MUST be the one shared Set
// instance, not a local copy, or the flag can never award.
const { uploadedFiles } = require('../shared');

function renderListing(res) {
  // VULN: hand-rolled directory listing exposes every file in the folder
  let entries = [];
  try {
    entries = fs.readdirSync(FILES_DIR);
  } catch (e) {
    return res.status(500).send(page('Files', '<p>Could not read the directory.</p>'));
  }
  const rows = entries
    .map((name) => {
      const full = path.join(FILES_DIR, name);
      let size = 0;
      try {
        size = fs.statSync(full).size;
      } catch (e) {
        size = 0;
      }
      return `<tr><td><a href="/misconfig/files/${encodeURIComponent(name)}">${esc(name)}</a></td><td class="dim">${size} bytes</td></tr>`;
    })
    .join('');
  res.send(
    page(
      'Public files',
      `<div class="card"><h2>Index of /misconfig/files/</h2>
      <p class="dim">Everything in this folder is served as-is. Probably fine, right?</p>
      <table class="tbl"><tr><th>Name</th><th>Size</th></tr>${rows}</table>
      ${hintBox(esc('The file endpoint accepts PUT with no authentication at all. Upload a file with a raw content type (curl -H "Content-Type: text/plain" --data-binary), then fetch it back with GET to prove the write.'))}</div>`
    )
  );
}

function serveFile(name, req, res) {
  const base = path.basename(String(name || ''));
  const full = path.join(FILES_DIR, base);
  if (!base || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    return res.status(404).send(page('Not found', `<div class="card"><h2>404</h2><p>File <code>${esc(base)}</code> not found.</p></div>`));
  }
  if (base === 'secret.txt') {
    // VULN (shared with the listing challenge): the listing exposed secret.txt
    // and it is served raw to anyone who requests it.
    award(req, 'misconfig', 'listing');
  }
  if (uploadedFiles.has(base)) {
    // VULN: this file arrived via the unauthenticated PUT and is served back raw;
    // reading it back proves the arbitrary write succeeded.
    award(req, 'misconfig', 'put');
  }
  res.type('text/plain');
  res.sendFile(full);
}

router.get('/files', (req, res) => {
  if (req.query.f) return serveFile(req.query.f, req, res);
  renderListing(res);
});
router.get('/files/', (req, res) => {
  if (req.query.f) return serveFile(req.query.f, req, res);
  renderListing(res);
});
router.get('/files/:name', (req, res) => serveFile(req.params.name, req, res));

// PUT /misconfig/files/:name -> raw file write, zero authentication.
// VULN: arbitrary file write with no authentication; the file lands in the served folder.
router.put('/files/:name', express.raw({ type: '*/*', limit: '1mb' }), (req, res) => {
  const name = path.basename(String(req.params.name || ''));
  if (!name || !Buffer.isBuffer(req.body)) {
    return res.status(400).type('text/plain')
      .send('bad upload: send a raw body, e.g. curl -X PUT -H "Content-Type: text/plain" --data-binary @file\n');
  }
  const full = path.join(FILES_DIR, name);
  try {
    fs.writeFileSync(full, req.body);
  } catch (e) {
    return res.status(500).type('text/plain').send('write failed: ' + e.message + '\n');
  }
  uploadedFiles.add(name);
  res
    .status(201)
    .type('text/plain')
    .send(`uploaded ${name} (${req.body.length} bytes) - GET /misconfig/files/${encodeURIComponent(name)} to read it back\n`);
});

module.exports = {
  vuln: {
    id: 'put',
    name: 'Unauthenticated HTTP PUT',
    difficulty: 'Medium',
    hint: 'The file endpoint accepts PUT with no authentication at all. Upload a file with a raw content type (curl -H "Content-Type: text/plain" --data-binary), then fetch it back with GET to prove the write.',
    hints: ["The server allows PUT. Can you write a file into the web root?", "Unauthenticated PUT to /misconfig/files/evil.txt writes a file you can then read.", "PUT your file to /misconfig/files/pwn.txt, then GET it back."],
    tools: 'C',
    how: 'PUT a file to /misconfig/files/<name> with Content-Type: text/plain, then read it back via GET.',
    link: '/misconfig#put',
    start: 'curl -s -X PUT -H "Content-Type: text/plain" --data-binary "hello pentrix" http://localhost:3000/misconfig/files/pwn.txt\ncurl -s http://localhost:3000/misconfig/files/pwn.txt',
  },
  router,
};
