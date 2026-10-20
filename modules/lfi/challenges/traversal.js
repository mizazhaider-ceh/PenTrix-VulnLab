'use strict';
// Basic Path Traversal: the document viewer joins the file name straight onto
// docs/ with no checks at all, so ../ sequences escape the intended folder.
const express = require('express');
const path = require('path');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const {
  SECRET_MARKER, LOG_MARKER, docLinks, readTarget, showCaptured, docsPage,
} = require('../shared');

const router = express.Router();

// ---- v1: plain traversal, no filtering at all ----
router.get('/view', (req, res) => {
  const file = req.query.file || '';
  let body = `
    <p>Open any document from the library, or type a file name of your own.</p>
    <form class="clay-card" method="get" action="/lfi/view">
      <div class="clay-field">
        <label for="lfi-view-file">File name</label>
        <input class="clay-input" type="text" id="lfi-view-file" name="file" placeholder="readme.txt" value="${esc(file)}">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Open document</button>
    </form>
    <h2>Library</h2>
    ${docLinks('/lfi/view')}
    ${showCaptured(req, 'traversal')}
  `;

  if (file) {
    // VULN: the file parameter reaches the reader with no path normalization,
    // so ../ sequences escape the library directory (path traversal).
    const r = readTarget(file);
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      // Real success only: the secret is displayed through a traversal payload.
      if (r.data.includes(SECRET_MARKER) && (file.includes('..') || path.isAbsolute(file))) {
        const flag = award(req, 'lfi', 'traversal');
        body += flagBox(flag) + fixPanel('lfi', 'traversal');
      }
      // Log-poison chain: the marker only reaches lfi_access.log via a crafted
      // User-Agent on /lfi/log-demo (see log-poison.js), so seeing it here
      // through this same viewer proves injection + LFI were chained together.
      if (r.data.includes(LOG_MARKER) && file.includes('..')) {
        const flag = award(req, 'lfi', 'log-poison');
        body += flagBox(flag) + fixPanel('lfi', 'log-poison');
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Document Viewer', docsPage('Library / Document Viewer', `<h1>Document Viewer</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'traversal', name: 'Basic Path Traversal', difficulty: 'Easy',
    hint: 'The viewer joins your input to the docs path with no checks at all. A filename does not have to name something inside docs.',
    hints: ["Proxy a normal document request in Burp and look at the file parameter in Repeater. What if the filename contains ../?", "In Repeater, start with one ../ and add more depth. Watch the Contents line: the path the server says it opened tells you when you have climbed out of docs.", "Shape: a filename of repeated parent-directory segments, deep enough to leave docs behind, ending at the file you want. Plain segments work on this endpoint; save the encoded and nested variants for the filtered endpoints in this module."],
    tools: "BZ, B, C",
    est: 'about 5 to 10 minutes',
    how: 'A document viewer builds file paths from user input with no confinement, so the filesystem beyond its folder is one filename away.',
    link: '/lfi/view?file=readme.txt',
    start: 'In Burp Proxy, intercept a request to the Document Viewer, send it to Repeater, and experiment with the file parameter there.',
  },
  router,
};
