'use strict';
// Billion laughs (entity-expansion DoS): the billion endpoint expands internal
// <!ENTITY> definitions recursively with no depth limit, so nested entities
// blow up exponentially and keep the parser busy past the flag threshold.
const express = require('express');
const { page, esc, brief, hintBox, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
// Module-level helpers live in modules/xxe/shared.js (created by the finisher):
// expandRecursive is the recursive internal-entity expander from router.js.
const { expandRecursive } = require('../shared');

const router = express.Router();

// GET /xxe/billion -> the billion laughs challenge form.
router.get('/billion', (req, res) => {
  res.send(page('Billion Laughs', `
    <h2>Billion laughs (entity-expansion DoS)</h2>
    ${brief('Challenge', `
      <p>This endpoint expands <b>internal</b> entities (<code>&lt;!ENTITY name "value"&gt;</code>)
      <b>recursively with no depth limit</b>. Define entities that reference each other and
      the parser does exponentially more work on every pass.</p>
      <p>Submit XML up to 3000 characters. The flag is awarded when your payload keeps the
      parser busy for more than <b>1.5 seconds</b>, or blows the expansion past <b>5 MB</b>.
      Your browser URL-encodes the form for you;
      with curl, use <code>--data-urlencode</code> so the <code>&amp;</code> characters survive.</p>`)}
    <form class="clay-card" method="POST" action="/xxe/billion">
      <div class="clay-field">
        <label for="xxe-billion-xml">XML payload</label>
        <textarea class="clay-input" id="xxe-billion-xml" name="xml" rows="12" placeholder="&lt;!DOCTYPE lolz [...]&gt;&lt;data&gt;&amp;lol7;&lt;/data&gt;"></textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Parse XML</button>
    </form>
    ${hintBox('Classic shape: <code>&lt;!ENTITY lol "xxxxxxxxxx"&gt;</code>, then <code>&lt;!ENTITY lol2 "&amp;lol;&amp;lol;... (x10)"&gt;</code>, up to <code>lol7</code>, and reference <code>&amp;lol7;</code> in the body. Each level multiplies the work by ten.')}
  `));
});

// POST /xxe/billion -> expand internal entities, award when the parser is
// kept busy past the time threshold or the expansion passes 5 MB.
router.post('/billion', (req, res) => {
  const xml = String(req.body.xml || '');
  if (xml.length > 3000) {
    return res.status(400).send(page('Billion Laughs', `
      <div class="clay-card">
        <h2>Payload too large</h2>
        <p>Payload too large (max 3000 characters).</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe/billion">Back</a></p>
      </div>`));
  }
  const t0 = Date.now();
  const expanded = expandRecursive(xml);
  const elapsed = Date.now() - t0;
  let flags = '';
  // VULN: award only when a real entity-expansion payload kept the parser busy past the
  // threshold, or blew expansion past 5 MB (a 12 MB expansion from 525 bytes kept the
  // parser busy regardless of machine speed; the size gate de-flakes fast hardware).
  if ((elapsed > 1500 || expanded.length > 5000000) && /<!ENTITY/i.test(xml) && /&\w+;/.test(xml)) {
    flags += flagBox(award(req, 'xxe', 'xxe-billion-laughs'));
    flags += fixPanel('xxe', 'xxe-billion-laughs');
  }
  res.send(page('Billion Laughs', `
    <h2>Parse result</h2>
    ${flags}
    <div class="clay-card">
      <p>Parser busy for <b>${elapsed} ms</b> (time threshold: 1500 ms, size threshold: 5 MB). Input: ${xml.length} chars,
      expanded output: ${expanded.length} chars.</p>
      <h3>Output preview</h3>
      <pre>${esc(expanded.slice(0, 500))}${expanded.length > 500 ? '...' : ''}</pre>
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe/billion">&larr; Try again</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'xxe-billion-laughs',
    name: 'Billion Laughs (Entity-Expansion DoS)',
    difficulty: 'Medium',
    hint: 'The billion endpoint expands internal entities recursively with no depth limit. Define entities that reference each other and watch the parse time.',
    hints: ["Entities can reference other entities. What if they reference each other exponentially?", "Nested entity definitions multiply at parse time: a small document can expand into gigabytes of text. Think about how few nested definitions it takes to overwhelm a parser.", "Define a small cascade of entities where each level repeats the previous one many times, then reference the top level once in your document. Key insight: the parser has no depth or size cap here, so the expansion compounds until it crosses the flag threshold. Watch the parse time, not the output."],
    tools: "C",
    how: 'Submit nested <!ENTITY> definitions (lol, lol2 ... lol7) so expansion explodes exponentially and parse time exceeds 1.5s.',
    link: '/xxe#xxe-billion-laughs',
    start: 'curl -s http://localhost:3000/xxe/billion\ncurl -s -X POST --data-urlencode xml@payload.xml http://localhost:3000/xxe/billion',
  },
  router,
};
