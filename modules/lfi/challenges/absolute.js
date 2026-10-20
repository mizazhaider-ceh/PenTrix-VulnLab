'use strict';
// Absolute Path Read: absolute paths are used verbatim instead of being
// confined to the docs folder, so no "../" traversal is needed at all.
const express = require('express');
const path = require('path');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { docsDir, docsPage, showCaptured, readFileCapped } = require('../shared');

const router = express.Router();

// ---- v3: absolute path, no traversal needed ----
router.get('/abs', (req, res) => {
  const p = req.query.page || 'readme.txt';
  // VULN: absolute paths are used verbatim; reads are not confined to docs/.
  const target = path.isAbsolute(p) ? p : path.join(docsDir, p);
  let body = `
    <p>Read a help page, or pass your own file name.</p>
    <form class="clay-card" method="get" action="/lfi/abs">
      <div class="clay-field">
        <label for="lfi-abs-page">Page</label>
        <input class="clay-input" type="text" id="lfi-abs-page" name="page" placeholder="readme.txt" value="${esc(p === 'readme.txt' ? '' : p)}">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Read page</button>
    </form>
    <p>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/lfi/abs?page=readme.txt">readme.txt</a>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/lfi/abs?page=/etc/hostname">/etc/hostname</a>
    </p>
    ${showCaptured(req, 'absolute')}
  `;
  try {
    const r = readFileCapped(target);
    if (!r.ok) throw new Error(r.error);
    const data = r.data;
    body += `<h2>Contents of <code>${esc(p)}</code></h2><pre>${esc(data)}</pre>`;
    // Real success only: a real system file was read via an absolute path.
    if (path.isAbsolute(p) && data.includes('root:')) {
      const flag = award(req, 'lfi', 'absolute');
      body += flagBox(flag) + fixPanel('lfi', 'absolute');
    }
  } catch (e) {
    body += `<h2>Error reading <code>${esc(p)}</code></h2><pre>${esc(e.message)}</pre>`;
  }
  res.send(page('LFI - Absolute Path', docsPage('Page Reader', `<h1>Page Reader</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'absolute', name: 'Absolute Path Read', difficulty: 'Easy',
    hint: 'The page reader confines nothing at all. Does the page parameter have to be a relative path inside the docs folder?',
    hints: ["Send a normal page read through Burp Proxy to Repeater, then ask: does the page parameter have to be relative?", "In Repeater the path is used verbatim, so ../ games are unnecessary. Name one standard Linux file that lists user accounts, then ask for it by its full system path.", "Shape: forget ../ entirely. In Repeater, name a file by its complete absolute path, exactly the way the system itself names it, and read what comes back."],
    tools: "BZ, B, C",
    est: 'about 5 to 10 minutes',
    how: 'A reader that uses paths verbatim will open absolute paths anywhere on the system, not just inside its own folder.',
    link: '/lfi/abs',
    start: 'Open the Page Reader at /lfi/abs in a Burp-proxied browser, send a read request to Repeater, then start tweaking the page parameter.',
  },
  router,
};
