// ssti-wordfilter: "Filtered Note" renders user input through the same homemade
// template engine as /ssti/greet, but first deletes the words flag, secret and
// config from the input. The flag lives in the in-scope variable vaultSecret.
// (No 'use strict' here: the vulnerable renderer relies on `with`, which strict
// mode forbids. The module is assembled in modules/ssti/index.js.)
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
    ${hintBox('The filter is plain string matching. In Burp Repeater, build the blocked variable name at run time instead of typing it: evaluate a concatenation of harmless fragments so the filter never sees the whole word in your raw input.')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-wordfilter',
    name: 'Word Blacklist Bypass',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'The words flag, secret and config are deleted from your input. Build the blocked word at run time instead of typing it.',
    hints: ["Capture the form request in Burp Proxy and send it to Repeater. First prove the engine still evaluates templates: put a small arithmetic expression between {{ }} in the input parameter.", "The brief says the flag variable's name contains a blocked word. In Repeater, type the full variable name and watch the filter delete it in the response, then think about how to assemble that name at run time instead of typing it.", "Send the request to Intruder and fuzz ways to build the blocked word without typing it whole: split it into innocent fragments inside an evaluated string and join them at runtime, then try case tricks and encoding variants until the rendered note shows the flag."],
    tools: 'BZ, B',
    how: 'In Burp Repeater, wrap an expression in {{ }} that builds the filtered variable name at run time (concatenate harmless string fragments and evaluate the result), so the filter never sees the whole blocked word in the raw input.',
    link: '/ssti#ssti-wordfilter',
    start: 'With Burp Proxy on, open /ssti/wordfilter in the browser, submit a note, and send the request to Repeater. Prove the engine evaluates templates with a small arithmetic expression, then probe how the filter treats the words it blocks.',
  },
  router,
};
