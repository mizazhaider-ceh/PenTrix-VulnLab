'use strict';
// XInclude file inclusion: <xi:include href="..."> is resolved server-side with
// the same file:// and http:// support as external entities.
const express = require('express');
const { page, esc, brief, hintBox, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { expandXInclude, SECRET_ABS } = require('../shared');

const router = express.Router();

// GET /xxe/xinclude -> the XInclude importer form.
router.get('/xinclude', (req, res) => {
  const sample = `<root xmlns:xi="http://www.w3.org/2001/XInclude">\n  <xi:include href="file://${SECRET_ABS}" parse="text"/>\n</root>`;
  res.send(page('XInclude', `
    <h2>XInclude importer</h2>
    ${brief('Challenge', `
      <p>This endpoint honors <code>&lt;xi:include&gt;</code> tags: the <code>href</code> is
      fetched server-side and spliced into the document. Both <code>file://</code> and
      <code>http://</code> hrefs work.</p>`)}
    <form method="POST" action="/xxe/xinclude">
      <div class="clay-field">
        <label for="xml">XML with XInclude</label>
        <textarea class="clay-input" id="xml" name="xml" rows="8">${esc(sample)}</textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Import XML</button>
    </form>
    ${hintBox('Point an <code>&lt;xi:include href="file://..."&gt;</code> at the module secret file and read the spliced content in the output.')}
  `));
});

// POST /xxe/xinclude -> resolve <xi:include> hrefs and show the spliced document.
router.post('/xinclude', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  // VULN: xi:include hrefs are resolved server-side with no allowlist.
  const out = await expandXInclude(xml);
  let flags = '';
  if (out.includes('XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'xxe-xinclude'));
    flags += fixPanel('xxe', 'xxe-xinclude');
  }
  res.send(page('XInclude', `
    <h2>Import result</h2>
    ${flags}
    <h3>Expanded document</h3>
    <pre>${esc(out.slice(0, 2000))}</pre>
    <p><a href="/xxe/xinclude">&larr; Try again</a> · <a href="/xxe">Back to module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'xxe-xinclude',
    name: 'XInclude File Inclusion',
    difficulty: 'Medium',
    hint: 'The xinclude endpoint honors xi:include tags. The href is resolved server-side with the same file:// and http:// support as entities.',
    hints: ["There's another XML inclusion mechanism besides entities. What is it?", "XInclude (<xi:include>) pulls in external resources. It's XXE by another name.", "Use the XInclude include element with its proper namespace, pointing its href at the secret file and setting parse to text. Key insight: XInclude is processed server-side, so the included file gets spliced into the parsed document and returned. Declare the xi namespace on your root element and check the output for the spliced content."],
    tools: "B, C",
    how: 'Submit XML with <xi:include href="file:///.../secret.txt" parse="text"/> and read the spliced content in the output.',
    link: '/xxe#xxe-xinclude',
    start: 'curl -s http://localhost:3000/xxe/xinclude\ncurl -s --data-urlencode \'xml=<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/hostname" parse="text"/></root>\' http://localhost:3000/xxe/xinclude',
  },
  router,
};
