// ssti-nounderscore: "No Underscores" renders user input through the same homemade
// template engine as /ssti/greet, but first deletes every underscore from the
// input. The flag lives in the in-scope variable db_pass.
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

// GET /ssti/nounderscore -> note gadget that deletes all underscores.
router.get('/nounderscore', (req, res) => {
  const hasInput = req.query.input !== undefined;
  const raw = hasInput ? String(req.query.input) : '';
  let result = '';
  let awardHtml = '';
  if (hasInput) {
    // VULN: underscore blacklist is defeated by building the character from its char code.
    const input = raw.replace(/_/g, '');
    const tpl = `Note: ${input}`;
    // VULN: the evaluated result is injected into the page raw so learners see the output plainly
    const rendered = sstiRender(tpl, { db_pass: flagFor('ssti', 'ssti-nounderscore') });
    result = `<div class="ssti-result card"><div class="card-top"><b>Rendered note</b></div>${rendered}</div>`;
    if (rendered.includes(flagFor('ssti', 'ssti-nounderscore'))) {
      awardHtml = flagBox(award(req, 'ssti', 'ssti-nounderscore')) + fixPanel('ssti', 'ssti-nounderscore');
    }
  }

  res.send(page('No Underscores', `
    ${brief('No Underscores',
      `<p>The engine still evaluates <code>{{ }}</code>, but every underscore is deleted from ` +
      `your input. The flag lives in a variable whose name contains an underscore.</p>`)}
    <div class="card">
      <div class="card-top"><b>Write a note</b></div>
      <form method="get" action="/ssti/nounderscore">
        <div class="clay-field">
          <label for="note-input">input:</label>
          <input class="clay-input" id="note-input" name="input" type="text" value="${esc(raw)}" size="48" autocomplete="off" />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Render</button>
      </form>
    </div>
    ${result}
    ${awardHtml}
    ${hintBox('You cannot type the underscore, but JavaScript can build any character: <code>String.fromCharCode(95)</code> is <code>_</code>. Combine it with <code>eval</code>.')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-nounderscore',
    name: 'Underscore Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'Underscores are deleted from your input. JavaScript can build any character from its code: String.fromCharCode(95) is _.',
    hints: ["Underscores are blocked. But every character has a char code.", "String.fromCharCode(95) is '_'. Build the underscore without typing it.", "Assemble the variable name from its typeable pieces plus a char-code-built underscore, then evaluate the assembled string. The filter only ever sees your raw input, not what eval builds from it."],
    tools: 'B, C',
    how: 'Evaluate the variable name assembled at run time, e.g. input={{eval("db"+String.fromCharCode(95)+"pass")}}.',
    link: '/ssti#ssti-nounderscore',
    start: 'curl -s "http://localhost:3000/ssti/nounderscore?input={{7*7}}"\ncurl -s "http://localhost:3000/ssti/nounderscore?input={{eval(\"db\"+String.fromCharCode(95)+\"pass\")}}"',
  },
  router,
};
