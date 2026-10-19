// ssti-wordfilter: "Filtered Note" renders user input through the same homemade
// template engine as /ssti/greet, but first deletes the words flag, secret and
// config from the input. The flag lives in the in-scope variable vaultSecret.
// (No 'use strict' here: the vulnerable renderer relies on `with`, which strict
// mode forbids. This keeps behavior identical to modules/ssti/router.js.)
const express = require('express');
const { brief, esc, flagBox, fixPanel, hintBox, page } = require('../../../lib/page');
const { award, flagFor } = require('../../../lib/flags');

const router = express.Router();

// VULN: naive template engine eval()s anything inside {{ }} with the function's
// scope visible. with(scope) puts server-side secret variables in the eval scope chain.
function sstiRender(tpl, scope) {
  // VULN: naive template engine eval()s anything inside {{ }} with attacker input in the template
  return tpl.replace(/\{\{(.*?)\}\}/g, (_, e) => {
    try {
      with (scope) { return eval(e); }
    } catch (err) { return ''; }
  });
}

// GET /ssti/wordfilter -> note gadget with a word blacklist.
router.get('/wordfilter', (req, res) => {
  const hasInput = req.query.input !== undefined;
  const raw = hasInput ? String(req.query.input) : '';
  let result = '';
  let awardHtml = '';
  if (hasInput) {
    // VULN: word blacklist is defeated by splitting the blocked word across a string concatenation.
    const input = raw.replace(/flag|secret|config/gi, '');
    const tpl = `Note: ${input}`;
    // VULN: the evaluated result is injected into the page raw so learners see the output plainly
    const rendered = sstiRender(tpl, { vaultSecret: flagFor('ssti', 'ssti-wordfilter') });
    result = `<div class="ssti-result card"><div class="card-top"><b>Rendered note</b></div>${rendered}</div>`;
    if (rendered.includes(flagFor('ssti', 'ssti-wordfilter'))) {
      awardHtml = flagBox(award(req, 'ssti', 'ssti-wordfilter')) + fixPanel('ssti', 'ssti-wordfilter');
    }
  }

  res.send(page('Filtered Note', `
    ${brief('Filtered Note',
      `<p>The engine still evaluates <code>{{ }}</code>, but a filter now deletes the words ` +
      `<code>flag</code>, <code>secret</code> and <code>config</code> from your input. A server-side ` +
      `variable holds the flag: its name contains one of those words.</p>`)}
    <div class="card">
      <div class="card-top"><b>Write a note</b></div>
      <form method="get" action="/ssti/wordfilter">
        <div class="clay-field">
          <label for="note-input">input:</label>
          <input class="clay-input" id="note-input" name="input" type="text" value="${esc(raw)}" size="48" autocomplete="off" />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Render</button>
      </form>
    </div>
    ${result}
    ${awardHtml}
    ${hintBox('The filter is plain string matching. Build the blocked word at run time instead of typing it: <code>{{eval("vaultSec"+"ret")}}</code>.')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-wordfilter',
    name: 'Word Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'The words flag, secret and config are deleted from your input. Build the blocked word at run time instead of typing it.',
    hints: ["The filter blocks words like 'secret'. But strings can be built without typing the word.", "Concatenate: 'vaultSec'+'ret'. Or use template tricks to assemble the blocked word at runtime.", "Submit {{eval('vaultSec'+'ret')}} to reach the flag variable."],
    tools: 'B, C',
    how: 'Use nested eval with string concatenation, e.g. input={{eval("vaultSec"+"ret")}}, to read the filtered variable name.',
    link: '/ssti#ssti-wordfilter',
    start: 'curl -s "http://localhost:3000/ssti/wordfilter?input={{7*7}}"\ncurl -s "http://localhost:3000/ssti/wordfilter?input={{eval(\"vaultSec\"+\"ret\")}}"',
  },
  router,
};
