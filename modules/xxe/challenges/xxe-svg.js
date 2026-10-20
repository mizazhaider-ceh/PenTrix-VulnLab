'use strict';
// XXE in uploaded SVG: the SVG text extractor runs the entity-expanding parser
// before pulling <text> elements, and an SVG is just XML with a DOCTYPE.
const express = require('express');
const { page, esc, brief, hintBox, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { expandEntities, SECRET_ABS, markerProven } = require('../shared');

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
    ${hintBox('Give the SVG a DOCTYPE that declares an external entity aimed at the module secret file (the file-read challenge shows how paths work here), and reference the entity inside a <code>&lt;text&gt;</code> element.')}
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
  if (markerProven(svg, expanded, 'XXE-SECRET-4471')) {
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
    est: 'about 10 minutes',
    hint: 'The SVG text extractor runs the same entity-expanding parser. An SVG is just XML, and XML can carry a DOCTYPE.',
    hints: ["Start in Burp Proxy: capture a normal POST /xxe/svg request from the form so you have a baseline you can replay before changing anything.", "Send that request to Repeater. An SVG is still XML, so a DOCTYPE declaring an external file-reading entity rides along through the extractor's parser. Put the entity reference inside a visible <text> element.", "Send the request and read the extractor output: your entity content lands in the <text> extraction results, so watch that section of the response for the spliced file content."],
    tools: "BZ, B",
    how: 'An SVG is XML too. If the extractor expands entities before reading the text, the file content ends up where the label used to be.',
    link: '/xxe#xxe-svg',
    start: 'Proxy your browser through Burp and open GET /xxe/svg. Submit the form once with a plain SVG, find the POST /xxe/svg request in Proxy HTTP history, send it to Repeater, then replace the svg field with your DOCTYPE entity payload and send.',
  },
  router,
};
