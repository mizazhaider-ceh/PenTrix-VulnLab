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
      in Burp Repeater, URL-encode the body before sending so the
      <code>&amp;</code> characters survive (select the body text, right-click, URL-encode).</p>`)}
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
    hints: ["Start in Burp Proxy: capture a normal POST /xxe/billion request from the form so you have a baseline you can replay before changing anything.", "Send that request to Repeater. Entities can reference other entities; in Repeater, build a small cascade where each level repeats the previous one many times, then reference the top level once in your document body.", "Send the request and read the response: the result page reports how long the parser was busy and how large the expansion got. Tune the payload until the parse crosses the time or size threshold and the flag box appears."],
    tools: "BZ",
    how: 'In Burp Repeater, send nested <!ENTITY> definitions (lol, lol2 ... lol7) in the xml field so expansion explodes exponentially and parse time exceeds 1.5s.',
    link: '/xxe#xxe-billion-laughs',
    start: 'Proxy your browser through Burp and open GET /xxe/billion. Submit the form once with plain XML, find the POST /xxe/billion request in Proxy HTTP history, send it to Repeater, then replace the xml field with your nested entity payload and send.',
  },
  router,
};
