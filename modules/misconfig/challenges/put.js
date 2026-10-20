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
      ${hintBox(esc('The file endpoint accepts PUT with no authentication at all. Think about what a successful write would look like, and how you would prove it afterwards.'))}</div>`
    )
  );
}

function serveFile(name, req, res) {
  const base = path.basename(String(name || ''));
  const full = path.join(FILES_DIR, base);
  if (!base || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    return res.status(404).send(page('Not found', `<div class="card"><h2>404</h2><p>File <code>${esc(base)}</code> not found.</p></div>`));
  }
  let banner = '';
  if (base === 'secret.txt') {
    // VULN (shared with the listing challenge): the listing exposed secret.txt
    // and it is served raw to anyone who requests it.
    const flag = award(req, 'misconfig', 'listing');
    banner = `================================================================\nPenTrix VulnLab: FLAG CAPTURED for challenge "Directory Listing Leak".\nYour flag: ${flag}\n(It is also on your scoreboard. The file below is what leaked.)\n================================================================\n\n`;
  }
  if (uploadedFiles.has(base)) {
    // VULN: this file arrived via the unauthenticated PUT and is served back raw;
    // reading it back proves the arbitrary write succeeded.
    const flag = award(req, 'misconfig', 'put');
    banner = `================================================================\nPenTrix VulnLab: FLAG CAPTURED for challenge "Unauthenticated HTTP PUT".\nYour flag: ${flag}\n(It is also on your scoreboard. Your file content is below.)\n================================================================\n\n`;
  }
  res.type('text/plain');
  if (banner) {
    return res.send(banner + fs.readFileSync(full, 'utf8'));
  }
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
      .send('bad upload: send a raw body. In Burp Repeater, change the method to PUT, add a Content-Type: text/plain header, and put your text in the request body.\n');
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
    hint: 'The file endpoint accepts PUT with no authentication at all. A write primitive is only half the story: how would you prove the write really landed?',
    hints: ["The server accepts unauthenticated PUT requests on its file endpoint. Can you write a file into the folder it serves back publicly?", "The server lets anyone PUT a file into its writable uploads area, and anything written there is readable again over HTTP. That turns a raw write primitive into a visible readback.", "Shape: in Repeater, change the request line method to PUT, give the body a plain-text content type, type a short body, and send it. Then request the same file path back to confirm the write landed where the server serves files from."],
    tools: 'BZ, C',
    est: 'about 10 to 20 minutes',
    how: 'An unauthenticated PUT on a served folder lets anyone publish files on the site, no account required.',
    link: '/misconfig#put',
    start: 'In Burp Proxy, send any request to /misconfig/files/ to Repeater. From there, experiment with what that endpoint accepts besides reads, and think about how you would prove a write.',
  },
  router,
};
