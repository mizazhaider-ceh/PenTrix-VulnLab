'use strict';
// Bracket Blacklist Bypass: the template engine strips [ and ] from input, and the
// flag object key contains a dash so dot notation cannot reach it either. Dumping the
// whole object with JSON.stringify reveals the flag without any indexing.
const express = require('express');
const { award, flagFor } = require('../../../lib/flags');
const { brief, esc, fixPanel, flagBox, hintBox, page } = require('../../../lib/page');
const { sstiRender } = require('../shared');

const router = express.Router();

// GET /ssti/nobrackets -> config preview. Same behavior as router.js: the bracket
// filter runs on the raw input, the naive engine evaluates {{ }} via sstiRender,
// and the flag is awarded when the rendered output contains the flag value.
router.get('/nobrackets', (req, res) => {
  const hasInput = req.query.input !== undefined;
  const raw = hasInput ? String(req.query.input) : '';
  let result = '';
  let awardHtml = '';
  if (hasInput) {
    // VULN: bracket blacklist is defeated by serializing the object instead of indexing it.
    const input = raw.replace(/[\[\]]/g, '');
    const tpl = `Config: ${input}`;
    // VULN: the evaluated result is injected into the page raw so learners see the output plainly
    const rendered = sstiRender(tpl, { cfg: { 'db-pass': flagFor('ssti', 'ssti-nobrackets') } });
    result = `<div class="ssti-result">${rendered}</div>`;
    if (rendered.includes(flagFor('ssti', 'ssti-nobrackets'))) {
      awardHtml = flagBox(award(req, 'ssti', 'ssti-nobrackets')) + fixPanel('ssti', 'ssti-nobrackets');
    }
  }
  res.send(page('No Brackets', `
    ${brief('No Brackets', `<p>The engine still evaluates <code>{{ }}</code>, but <code>[</code> and <code>]</code>
      are deleted from your input. The flag is stored as an object property whose key contains a dash,
      so dot notation cannot reach it either.</p>`)}
    <form method="get" action="/ssti/nobrackets">
      <div class="clay-field">
        <label for="input">Config text</label>
        <input class="clay-input" id="input" name="input" type="text" value="${esc(raw)}" size="48" autocomplete="off" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Render</button>
    </form>
    ${result}
    ${awardHtml}
    ${hintBox('You cannot index the object, but you can dump the whole thing: what function turns any object into text?')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-nobrackets',
    name: 'Bracket Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'Brackets are deleted and the object key has a dash, so neither indexing nor dot access works directly. Dump the whole object instead.',
    hints: [
      'Capture the render request in Burp Proxy and send it to Repeater. Brackets [] are deleted from your input: what can you do to an object that needs no indexing at all?',
      'The flag lives in an object whose dashed key also defeats dot access. But you never need to index it: replay in Repeater with the whole object printed as text, and the dump will show the dashed key and all.',
      'There is a built-in that converts an entire object into readable text. Wrap the flag-bearing object in it inside your {{ }} expression and the flag value will appear in the dump.',
    ],
    tools: 'BZ, B',
    how: 'Serialize the whole object to text inside the {{ }} expression instead of indexing it, then replay the request in Repeater until the rendered page shows the flag value.',
    link: '/ssti#ssti-nobrackets',
    start: 'Browse to /ssti/nobrackets through Burp Proxy, submit the config form once, then send the request to Repeater. Edit the input parameter, send, and read the rendered config in the response.',
  },
  router,
};
