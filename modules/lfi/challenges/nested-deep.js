'use strict';
// Deep Nesting Bypass: every "../" is stripped globally, but only in a single
// pass, so "....//" regenerates a fresh "../" once the inner pair is removed.
const express = require('express');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { SECRET_MARKER, docLinks, readTarget, showCaptured, docsPage } = require('../shared');

const router = express.Router();

// ---- v5: nested bypass of a global one-pass "../" strip ----
router.get('/nested', (req, res) => {
  const raw = req.query.page || '';
  // VULN: every "../" is stripped, but only in a single pass, so ....// regenerates ../.
  const file = raw.split('../').join('');
  let body = `
    <p>All <code>../</code> sequences are stripped from your input before reading.
       Nothing can survive that... right?</p>
    <form class="clay-card" method="get" action="/lfi/nested">
      <div class="clay-field">
        <label for="lfi-nested-page">Page</label>
        <input class="clay-input" type="text" id="lfi-nested-page" name="page" placeholder="readme.txt" value="${esc(raw)}">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Open page</button>
    </form>
    <h2>Library</h2>
    ${docLinks('/lfi/nested')}
    ${showCaptured(req, 'nested-deep')}
  `;
  if (raw) {
    const r = readTarget(file);
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      // Real success only: the secret shows while the post-strip file still
      // carries "..", i.e. nested dots regenerated a traversal the one-pass
      // strip missed. A plain ../secret.txt is stripped to a plain in-docs
      // name and must not award this challenge.
      if (r.data.includes(SECRET_MARKER) && file.includes('..')) {
        const flag = award(req, 'lfi', 'nested-deep');
        body += flagBox(flag) + fixPanel('lfi', 'nested-deep');
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Nested Filter', docsPage('Strict Filter Viewer', `<h1>Nested Filter Viewer</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'nested-deep', name: 'Deep Nesting Bypass', difficulty: 'Easy',
    hint: 'This filter strips every <code>../</code> in one pass, but it never looks at the result again. Nest your dots so stripping creates a fresh traversal, e.g. <code>....///</code> collapses toward <code>../</code>.',
    hints: ["The filter does a one-pass global strip of ../. What about nested dots?", "A single pass over '....//' removes the inner pair and leaves '../'. Nested patterns survive one pass.", "Try ?page=....///docs/secret.txt with nested dots."],
    tools: "B, C",
    how: 'Beat the one-pass global strip on /lfi/nested with nested dots.',
    link: '/lfi/nested',
    start: 'curl "http://localhost:3000/lfi/nested?page=readme.txt"',
  },
  router,
};
