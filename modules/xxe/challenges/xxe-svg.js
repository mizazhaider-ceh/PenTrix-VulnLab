'use strict';
// XXE in uploaded SVG: the SVG text extractor runs the entity-expanding parser
// before pulling <text> elements, and an SVG is just XML with a DOCTYPE.
const express = require('express');
const { page, esc, brief, hintBox, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { expandEntities, SECRET_ABS } = require('../shared');

const router = express.Router();

// GET /xxe/svg -> the SVG text extractor upload form.
router.get('/svg', (req, res) => {
  const sample = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">\n<text x="10" y="30">hello</text>\n</svg>`;
  res.send(page('XXE in SVG', `
    <h2>SVG text extractor</h2>
    ${brief('Challenge', `
      <p>Upload an SVG and the app extracts its <code>&lt;text&gt;</code> elements server-side.
      The extractor runs the module's entity-expanding parser first, and an SVG is just XML,
      so it can carry a <code>DOCTYPE</code>.</p>`)}
    <form method="POST" action="/xxe/svg">
      <div class="clay-field">
        <label for="svg">SVG markup</label>
        <textarea class="clay-input" id="svg" name="svg" rows="10">${esc(sample)}</textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Extract text</button>
    </form>
    ${hintBox('Give the SVG a DOCTYPE that declares <code>&lt;!ENTITY xxe SYSTEM "file://' + esc(SECRET_ABS) + '"&gt;</code> and put <code>&amp;xxe;</code> inside a <code>&lt;text&gt;</code> element.')}
  `));
});

// POST /xxe/svg -> expand entities in the SVG, then extract <text> content.
router.post('/svg', async (req, res) => {
  const svg = String(req.body.svg || '').slice(0, 20000);
  // VULN: the SVG "parser" expands external entities before extracting text.
  const expanded = await expandEntities(svg);
  const texts = [...expanded.matchAll(/<text[^>]*>([\s\S]*?)<\/text>/gi)].map((m) => m[1].trim()).filter(Boolean);
  const shown = texts.length ? texts.join(' | ') : '(no <text> elements found)';
  let flags = '';
  if (expanded.includes('XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'xxe-svg'));
    flags += fixPanel('xxe', 'xxe-svg');
  }
  res.send(page('XXE in SVG', `
    <h2>Extraction result</h2>
    ${flags}
    <h3>Extracted text</h3>
    <pre>${esc(shown.slice(0, 2000))}</pre>
    <p><a href="/xxe/svg">&larr; Extract another</a> · <a href="/xxe">Back to module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'xxe-svg',
    name: 'XXE in Uploaded SVG',
    difficulty: 'Medium',
    hint: 'The SVG text extractor runs the same entity-expanding parser. An SVG is just XML, and XML can carry a DOCTYPE.',
    hints: ["SVG files are XML. Do uploaded SVGs get parsed with entities resolved?", "An SVG with a DOCTYPE declaring an external entity will have it resolved when the server parses the SVG.", "Your uploaded SVG needs a DOCTYPE that declares a file-reading entity, with the entity reference placed inside visible SVG text. Key insight: an SVG is still XML, so the DOCTYPE rides along through the parser. Watch the text extractor's output to confirm where your entity content lands."],
    tools: "B, C",
    how: 'Upload an SVG whose DOCTYPE declares a file:// entity for secret.txt and references it inside a <text> element.',
    link: '/xxe#xxe-svg',
    start: 'curl -s http://localhost:3000/xxe/svg\ncurl -s --data-urlencode \'svg=<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>\' http://localhost:3000/xxe/svg',
  },
  router,
};
