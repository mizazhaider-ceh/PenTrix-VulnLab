'use strict';
// Dot Blacklist Bypass: the template engine strips every dot from input, but JavaScript
// property access has a second syntax. Bracket notation reaches the same property
// without typing a single dot.
const express = require('express');
const { award, flagFor } = require('../../../lib/flags');
const { brief, esc, fixPanel, flagBox, hintBox, page } = require('../../../lib/page');
const { sstiRender } = require('../shared');

const router = express.Router();

// GET /ssti/dotblock -> record viewer. Same behavior as router.js: the dot filter runs
// on the raw input, the naive engine evaluates {{ }} via sstiRender, and the flag is
// awarded when the rendered output contains the flag value.
router.get('/dotblock', (req, res) => {
  const hasInput = req.query.input !== undefined;
  const raw = hasInput ? String(req.query.input) : '';
  let result = '';
  let awardHtml = '';
  if (hasInput) {
    // VULN: dot blacklist is defeated by bracket-notation property access.
    const input = raw.replace(/\./g, '');
    const tpl = `Record: ${input}`;
    // VULN: the evaluated result is injected into the page raw so learners see the output plainly
    const rendered = sstiRender(tpl, { db: { key: flagFor('ssti', 'ssti-dotblock') } });
    result = `<div class="ssti-result">${rendered}</div>`;
    if (rendered.includes(flagFor('ssti', 'ssti-dotblock'))) {
      awardHtml = flagBox(award(req, 'ssti', 'ssti-dotblock')) + fixPanel('ssti', 'ssti-dotblock');
    }
  }
  res.send(page('No Dots', `
    ${brief('No Dots', `<p>The engine still evaluates <code>{{ }}</code>, but every dot is deleted from your
      input. The flag is a property of an object - dot access is the first thing you would try.</p>`)}
    <form method="get" action="/ssti/dotblock">
      <div class="clay-field">
        <label for="input">Record text</label>
        <input class="clay-input" id="input" name="input" type="text" value="${esc(raw)}" size="48" autocomplete="off" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Render</button>
    </form>
    ${result}
    ${awardHtml}
    ${hintBox('Dots are gone, but JavaScript has a second syntax for property access that uses no dots at all.')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-dotblock',
    name: 'Dot Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'Dots are deleted from your input. JavaScript has a second property-access syntax that uses no dots.',
    hints: [
      'Dots are blocked. But property access has two syntaxes.',
      "Bracket notation: obj['prop'] works where obj.prop is blocked. The filter only strips dots, so it never sees the second syntax.",
      "Find the object that holds the flag and the exact key name, then reach the value with the no-dot syntax: brackets around a quoted string.",
    ],
    tools: 'B, C',
    how: 'Use bracket notation, e.g. input={{db["key"]}}, to read the property without a dot.',
    link: '/ssti#ssti-dotblock',
    start: 'curl -s "http://localhost:3000/ssti/dotblock?input=hello"',
  },
  router,
};
