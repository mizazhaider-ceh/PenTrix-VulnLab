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
    hint: 'A config file sits near the docs folder, and this viewer filters nothing. What lives just outside a folder is still a path.',
    hints: ["A config file sits one directory above docs/. No filter blocks it.", "Proxy the Read config form in Burp, send the request to Repeater, then edit the file parameter to climb one level out of docs/.", "Shape: one parent-directory step out of docs/, then a config file name. Config files announce themselves by their extension; try the names a service would plant next to its document folder."],
    tools: "BZ, B",
    est: 'about 5 to 10 minutes',
    how: 'A config viewer with no validation reads whatever path it is given, including the service\'s own configuration next door.',
    link: '/lfi/config',
    start: 'In Burp, browse to /lfi/config with Proxy on, submit the Read config form, and send the captured request to Repeater.',
  },
  router,
};
