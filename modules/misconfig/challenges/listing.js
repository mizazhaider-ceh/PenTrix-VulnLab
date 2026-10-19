'use strict';
// Directory Listing Leak: GET /misconfig/files/ renders a hand-rolled index of
// every file in public-files, including secret.txt, and /misconfig/files/:name
// serves any listed file raw to anyone who asks.
const express = require('express');
const fs = require('fs');
const path = require('path');
const { esc, page, hintBox, appShell } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
// Shared module state (finisher provides modules/misconfig/shared.js): names of
// files written through the unauthenticated PUT endpoint, so reading one back
// awards that challenge's flag too.
const { uploadedFiles } = require('../shared');

const router = express.Router();

const FILES_DIR = path.join(__dirname, '..', 'public-files');

function renderListing(res) {
  // VULN: hand-rolled directory listing exposes every file in the folder, including secret.txt
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
      return `<tr><td><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/misconfig/files/${encodeURIComponent(name)}">${esc(name)}</a></td><td class="dim">${size} bytes</td></tr>`;
    })
    .join('');
  res.send(
    page(
      'ShareBox: public files',
      appShell('ShareBox', `
        <h2>Index of /files</h2>
        <p class="dim">Shared files, served as-is. If you can see it here, you can download it.</p>
        <table class="tbl"><tr><th>Name</th><th>Size</th></tr>${rows}</table>
        ${hintBox(esc('The file browser lists everything in public-files, including files that were never meant to be seen.'))}
      `, { nav: ['Home', 'Shared files', 'Help'], mark: '▤' })
    )
  );
}

function serveFile(name, req, res) {
  const base = path.basename(String(name || ''));
  const full = path.join(FILES_DIR, base);
  if (!base || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    return res.status(404).send(page('Not found', `<h2>404</h2><p>File <code>${esc(base)}</code> not found.</p>`));
  }
  if (base === 'secret.txt') {
    // VULN: the listing exposed secret.txt and it is served raw to anyone who requests it
    award(req, 'misconfig', 'listing');
  }
  if (uploadedFiles.has(base)) {
    // VULN: this file arrived via the unauthenticated PUT and is served back raw,
    // so reading it back proves the arbitrary write succeeded
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

module.exports = {
  vuln: {
    id: 'listing',
    name: 'Directory Listing Leak',
    difficulty: 'Easy',
    hint: 'The file browser lists everything in public-files, including files that were never meant to be seen.',
    hints: ["The directory listing is hand-rolled. What files does it expose?", "The listing shows secret.txt. Directory listings leak files nobody linked.", "Open the listing and download secret.txt."],
    tools: 'B',
    how: 'Open /misconfig/files/ and read secret.txt.',
    link: '/misconfig#listing',
    start: 'curl -s http://localhost:3000/misconfig/files/',
  },
  router,
};
