'use strict';
// Secret Config Read: a planted config file with secrets sits one directory
// above the docs folder, and this viewer applies no validation at all.
const express = require('express');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { CONFIG_MARKER, docLinks, readTarget, showCaptured, docsPage } = require('../shared');

const router = express.Router();

// ---- v10: planted secret config ----
router.get('/config', (req, res) => {
  const file = req.query.file || 'readme.txt';
  // VULN: no validation at all; a secret config file sits one directory up.
  const r = readTarget(file);
  let body = `
    <p>Read a config doc, or pass your own file name:</p>
    <form class="clay-card" method="get" action="/lfi/config">
      <div class="clay-field">
        <label for="lfi-config-file">File name</label>
        <input class="clay-input" type="text" id="lfi-config-file" name="file" placeholder="readme.txt" value="${esc(file === 'readme.txt' ? '' : file)}">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Read config</button>
    </form>
    <h2>Library</h2>
    ${docLinks('/lfi/config')}
    ${showCaptured(req, 'config-read')}
  `;
  if (file) {
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      // Real success only: the planted config was reached via traversal.
      if (r.data.includes(CONFIG_MARKER) && file.includes('..')) {
        const flag = award(req, 'lfi', 'config-read');
        body += flagBox(flag) + fixPanel('lfi', 'config-read');
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Config File', docsPage('Settings / Config Viewer', `<h1>Config Viewer</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'config-read', name: 'Secret Config Read', difficulty: 'Easy',
    hint: 'A config file with secrets sits one directory above the docs folder, and the config viewer filters nothing. <code>?file=../lfi_secret.conf</code>.',
    hints: ["A config file sits one directory above docs/. No filter blocks it.", "The planted lfi_secret.conf is at ../lfi_secret.conf. Just traverse to it.", "Try ?file=../lfi_secret.conf on /lfi/config."],
    tools: "B",
    how: 'Read the planted lfi_secret.conf via /lfi/config.',
    link: '/lfi/config',
    start: 'curl "http://localhost:3000/lfi/config?file=readme.txt"',
  },
  router,
};
