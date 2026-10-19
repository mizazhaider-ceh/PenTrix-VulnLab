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
    hints: ["Start in Burp Proxy: capture a normal POST /xxe/xinclude request from the form so you have a baseline you can replay before changing anything.", "Send that request to Repeater. Besides entities, XML has another inclusion mechanism that pulls external resources into the document; the importer form honors it for both file:// and http:// hrefs.", "Declare the proper namespace for that inclusion element on your root, point its href at the secret file with parse set to text, and send. Read the expanded document output for the spliced content."],
    tools: "BZ, B",
    how: 'Burp the XInclude importer form, send the POST to Repeater, and put XML with the include element (declared under its proper namespace) pointing its href at the secret file and parse="text" into the xml parameter. Read the expanded document output for the spliced content.',
    link: '/xxe#xxe-xinclude',
    start: 'Proxy your browser through Burp and open GET /xxe/xinclude. Submit the form once with plain XML, find the POST /xxe/xinclude request in Proxy HTTP history, send it to Repeater, then replace the xml field with your XInclude payload and send.',
  },
  router,
};
