'use strict';
// ssti-curly: "Curly Stripper" echo gadget. The homemade template engine still
// evaluates {{ }}, but a filter deletes the first "{{" and the first "}}"
// (once each, no re-scan). The flag is awarded when the raw input still
// contains {{ }} and the rendered output shows 49 (the doubled-brace bypass).
const express = require('express');
const { brief, esc, flagBox, fixPanel, hintBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { sstiRender } = require('../shared');

const router = express.Router();

// GET /ssti/curly -> echo gadget with a single-strip curly-brace filter.
router.get('/curly', (req, res) => {
  const hasInput = req.query.input !== undefined;
  const raw = hasInput ? String(req.query.input) : '';
  let result = '';
  let awardHtml = '';
  if (hasInput) {
    // VULN: single-strip filter is defeated by doubling the stripped sequence.
    const input = raw.replace('{{', '').replace('}}', '');
    const tpl = `Echo: ${input}`;
    // VULN: the evaluated result is injected into the page raw so learners see the output plainly
    const rendered = sstiRender(tpl, {});
    result = `<div class="ssti-result card"><div class="card-top"><b>Rendered echo</b></div>${rendered}</div>`;
    if (/\{\{/.test(raw) && rendered.includes('49')) {
      awardHtml = flagBox(award(req, 'ssti', 'ssti-curly')) + fixPanel('ssti', 'ssti-curly');
    }
  }

  res.send(page('Curly Stripper', `
    ${brief('Curly Stripper',
      `<p>The engine still evaluates <code>{{ }}</code>, but a filter removes the first ` +
      `<code>{{</code> and the first <code>}}</code> from your input: once each, like the naive ` +
      `semicolon filter in the command-injection module.</p>`)}
    <div class="card">
      <div class="card-top"><b>Echo your input</b></div>
      <form method="get" action="/ssti/curly">
        <div class="clay-field">
          <label for="curly-input">input</label>
          <input class="clay-input" id="curly-input" name="input" type="text" value="${esc(raw)}" size="48" autocomplete="off" />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Render</button>
      </form>
    </div>
    ${result}
    ${awardHtml}
    ${hintBox('The filter strips one pair of braces. What happens if you send two pairs?')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-curly',
    name: 'Curly-Brace Strip Bypass',
    difficulty: 'Medium',
    hint: 'The filter removes the first {{ and the first }} only, once each. Feed it more braces than it can strip.',
    hints: ["Capture the form submission in Burp Proxy and send it to Repeater. Try a plain template expression first and watch the filter strip the braces.", "The filter removes each brace pair only once and never re-scans the result. In Repeater, add more brace pairs around the expression and watch the rendered output change.", "Once one valid {{ }} pair survives the single strip pass, the math evaluates. Confirm the raw input still contained {{ }} before the filter ran."],
    tools: 'BZ, B',
    how: 'Fuzz the input parameter in Burp Repeater, adding extra braces around the expression until one {{ }} pair survives the single strip pass and evaluates to 49.',
    link: '/ssti#ssti-curly',
    start: 'Proxy the form through Burp, send the request to Repeater, and fuzz the input parameter with brace-count variations, starting from the plain expression baseline.',
  },
  router,
};
