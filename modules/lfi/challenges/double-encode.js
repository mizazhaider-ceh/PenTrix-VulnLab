'use strict';
// Encoding Bypass: the filter decodes the value once and rejects it if it
// still sees "..", but the value is decoded a second time before the read.
const express = require('express');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { SECRET_MARKER, rawParam, safeDecode, docLinks, readTarget, showCaptured, docsPage } = require('../shared');

const router = express.Router();

// Decoded-traversal semantics: true when resolving `p` climbs above the docs
// dir at some point (i.e. a ".." segment really escapes), not just when the
// raw input happens to contain a "%". A single decode of "%73ecret.txt"
// yields "secret.txt": no segment ever leaves the docs dir, so it must never
// count, even though the raw input carries a percent sign. Only %252e-style
// double encoding can smuggle a real ".." past the one-decode filter, and
// only when the second decode introduces it.
function traversalEscapes(p) {
  const parts = String(p).split(/[\\/]+/);
  let depth = 0;
  for (const part of parts) {
    if (part === '..') {
      depth -= 1;
      if (depth < 0) return true;
    } else if (part && part !== '.') {
      depth += 1;
    }
  }
  return false;
}

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
        // Real success only: the second decode must have introduced a real
        // traversal that escapes the docs dir. A bare percent in the raw
        // input (like %73ecret.txt) or a plain in-docs name never awards.
        if (r.data.includes(SECRET_MARKER) && traversalEscapes(file)) {
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
    hint: 'The filter decodes your input once and rejects it if it sees <code>..</code>. But the value is decoded a second time after the check. Encode the dots and slashes twice, so the check sees harmless text while the final decode rebuilds the traversal. The same idea works when a filter checks before decoding at all: then encoding once is enough to slip through.',
    hints: ["The filter decodes once and checks for ... But the value is decoded again on use. Intercept a normal request in Burp Proxy and send it to Repeater so you can edit the raw page parameter.", "In Repeater, try the traversal with different levels of encoding: plain, encoded once, encoded twice. Watch which one the filter rejects and which one the page actually reads.", "Encode twice with Burp Decoder (encode once, then encode the result again), paste the result into the page parameter in Repeater, and compare the 'Blocked' response with the decoded content the page shows."],
    tools: "BZ, C",
    how: 'Slip a twice-encoded traversal past the one-decode filter on /lfi/double. The page shows the final decoded path and its contents, so Repeater reveals when the filter sees harmless text while the read rebuilds the traversal.',
    link: '/lfi/double',
    start: 'In Burp, browse to /lfi/double, intercept the request in the Proxy, send it to Repeater, and inspect how the filter treats the page parameter.',
  },
  router,
};
