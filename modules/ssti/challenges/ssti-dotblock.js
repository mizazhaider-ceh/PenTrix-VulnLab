'use strict';
// Dot Blacklist Bypass: the template engine strips every dot from input, but JavaScript
// property access has a second syntax. Bracket notation reaches the same property
// without typing a single dot.
const express = require('express');
const { award, flagFor } = require('../../../lib/flags');
const { brief, esc, fixPanel, flagBox, hintBox, page } = require('../../../lib/page');
const { sstiRender } = require('../shared');

const router = express.Router();

// GET /ssti/dotblock -> record viewer. The dot filter runs
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
    est: 'about 10 to 25 minutes',
    hint: 'Dots are deleted from your input. JavaScript has a second property-access syntax that uses no dots.',
    hints: [
      'Capture the form submission in Burp Proxy and send it to Repeater. Try dot-style property access first and watch the filter delete the dots.',
      "JavaScript property access has a second syntax that uses no dots. In Repeater, reach the flag-holding object's key with brackets around a quoted string.",
      'Once the rendered output shows the flag value instead of an empty result, resend once to confirm it reproduces, then claim it.',
    ],
    tools: 'BZ, B',
    how: 'Fuzz the input parameter in Burp Repeater: first confirm dot access is stripped, then switch to the no-dot bracket syntax to explore the db object and read what it holds.',
    link: '/ssti#ssti-dotblock',
    start: 'Proxy the form through Burp, send the request to Repeater, and fuzz the input parameter, starting with a harmless baseline and then property-access variations.',
  },
  router,
};
