'use strict';
// Encoding Bypass: the filter decodes the value once and rejects it if it
// still sees "..", but the value is decoded a second time before the read.
const express = require('express');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { SECRET_MARKER, rawParam, safeDecode, docLinks, readTarget, showCaptured, docsPage } = require('../shared');

const router = express.Router();

// ---- v4: double-encoding bypass (filter decodes once, use decodes twice) ----
router.get('/double', (req, res) => {
  const raw = rawParam(req, 'page');
  let body = `
    <p>Traversal sequences are rejected after decoding your input once.
       This one should be safe.</p>
    <form class="clay-card" method="get" action="/lfi/double">
      <div class="clay-field">
        <label for="lfi-double-page">Page</label>
        <input class="clay-input" type="text" id="lfi-double-page" name="page" placeholder="readme.txt" value="${esc(safeDecode(raw))}">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Open page</button>
    </form>
    <h2>Library</h2>
    ${docLinks('/lfi/double')}
    ${showCaptured(req, 'double-encode')}
  `;
  if (raw) {
    const checked = safeDecode(raw);
    if (checked.includes('..')) {
      body += `<p><b>Blocked:</b> traversal sequence detected in your input.</p>`;
    } else {
      // VULN: the value is decoded a second time after the check, so
      // %252e%252e%252f sails through the filter and becomes ../ on use.
      const file = safeDecode(checked);
      const r = readTarget(file);
      if (r.ok) {
        body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
        if (r.data.includes(SECRET_MARKER)) {
          const flag = award(req, 'lfi', 'double-encode');
          body += flagBox(flag) + fixPanel('lfi', 'double-encode');
        }
      } else {
        body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
      }
    }
  }
  res.send(page('LFI - Double Encoding', docsPage('Encoded Viewer', `<h1>Double-Decode Viewer</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'double-encode', name: 'Encoding Bypass', difficulty: 'Medium',
    hint: 'The filter decodes your input once and rejects it if it sees <code>..</code>. But the value is decoded a second time after the check. Encode the dots and slashes twice, e.g. <code>%252e%252e%252f</code>. The same idea works when a filter checks before decoding at all: then single-encoding (<code>%2e%2e%2f</code>) slips through.',
    hints: ["The filter decodes once and checks for ... But the value is decoded again on use.", "Double-encode: %252e becomes %2e after one decode, then . after the second. The check sees no dots.", "Try ?page=%252e%252e%252fdocs%252fsecret.txt."],
    tools: "C",
    how: 'Slip %252e%252e%252fdocs%252fsecret.txt past the one-decode filter on /lfi/double.',
    link: '/lfi/double',
    start: 'curl "http://localhost:3000/lfi/double?page=readme.txt"',
  },
  router,
};
