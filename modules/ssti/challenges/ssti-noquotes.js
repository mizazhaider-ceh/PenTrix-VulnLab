'use strict';
// ssti-noquotes: "No Quotes" vault gadget. The homemade template engine still
// evaluates {{ }}, but quotes are deleted from the input and the flag
// variable name vaultKey is blocked as a word. The flag is awarded when the
// rendered output contains the vaultKey value (reachable only via
// String.fromCharCode plus eval).
const express = require('express');
const { brief, esc, flagBox, fixPanel, hintBox, page } = require('../../../lib/page');
const { award, flagFor } = require('../../../lib/flags');
const { sstiRender } = require('../shared');

const router = express.Router();

// GET /ssti/noquotes -> vault gadget with a quote and word blacklist.
router.get('/noquotes', (req, res) => {
  const hasInput = req.query.input !== undefined;
  const raw = hasInput ? String(req.query.input) : '';
  let result = '';
  let awardHtml = '';
  if (hasInput) {
    // VULN: quote blacklist is defeated by spelling strings with String.fromCharCode and eval.
    const input = raw.replace(/['"]/g, '').replace(/vaultKey/g, '');
    const tpl = `Vault: ${input}`;
    // VULN: the evaluated result is injected into the page raw so learners see the output plainly
    const rendered = sstiRender(tpl, { vaultKey: flagFor('ssti', 'ssti-noquotes') });
    result = `<div class="ssti-result card"><div class="card-top"><b>Rendered vault</b></div>${rendered}</div>`;
    if (rendered.includes(flagFor('ssti', 'ssti-noquotes'))) {
      awardHtml = flagBox(award(req, 'ssti', 'ssti-noquotes')) + fixPanel('ssti', 'ssti-noquotes');
    }
  }

  res.send(page('No Quotes', `
    ${brief('No Quotes',
      `<p>The engine still evaluates <code>{{ }}</code>, but single and double quotes are deleted ` +
      `from your input, and the flag variable name itself is blocked as a word. No string literals, no ` +
      `direct reference.</p>`)}
    <div class="card">
      <div class="card-top"><b>Open the vault</b></div>
      <form method="get" action="/ssti/noquotes">
        <div class="clay-field">
          <label for="noquotes-input">input</label>
          <input class="clay-input" id="noquotes-input" name="input" type="text" value="${esc(raw)}" size="48" autocomplete="off" />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Render</button>
      </form>
    </div>
    ${result}
    ${awardHtml}
    ${hintBox('Build the variable name without typing it and without quotes: spell it with character codes, then evaluate the result.')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-noquotes',
    name: 'Quote Blacklist Bypass',
    difficulty: 'Hard',
    est: 'about 20 to 45 minutes',
    hint: 'Quotes are deleted and the variable name is blocked as a word. Spell the name with character codes and evaluate the result.',
    hints: ["Capture the render request in Burp Proxy and send it to Repeater: quotes are deleted from your input. How do you spell a string when you have no string literals?", "Repeater makes this a fast trial-and-error loop. Strings can be built from character codes: String.fromCharCode(65,68,77,73,78) builds a word with no quotes. Now you only need to evaluate the result.", "There is a built-in that runs a string as code. Build the blocked variable name from char codes, feed the result to that built-in inside your {{ }} expression, and replay in Repeater until the flag prints."],
    tools: 'BZ, B',
    how: 'Build the blocked variable name from character codes with no quotes, evaluate the resulting string inside the {{ }} expression, and replay the request in Repeater until the rendered page shows the flag.',
    link: '/ssti#ssti-noquotes',
    start: 'Browse to /ssti/noquotes through Burp Proxy, submit the vault form once, then send the request to Repeater. Edit the input parameter, send, and read the rendered vault in the response.',
  },
  router,
};
