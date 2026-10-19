'use strict';
// Ping Gadget v5 (separators blocked): ; & and | are all stripped, but a
// newline still separates shell commands and the blacklist forgot it.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-newline',
  name: 'Ping Gadget v5 (separators blocked)',
  difficulty: 'Medium',
  hint: 'The characters ; & and | are all stripped. But a shell treats more than those as command separators. In a URL, %0a becomes one of them. The same gap appears when a value is dropped into the command line with no quotes and the blacklist forgets newline.',
  hints: [
    "The filter strips ; & |. But the shell treats newlines as command separators too.",
    "%0a in a URL decodes to a newline. Each line runs as its own command.",
    "Try ?host=127.0.0.1%0acat /etc/passwd.",
  ],
  tools: 'B, C',
  how: 'Inject a newline (%0a) to start a second command, e.g. ?host=127.0.0.1%0acat /etc/passwd',
  link: '/cmdi/ping5',
  start: 'curl "http://localhost:3000/cmdi/ping5?host=127.0.0.1"',
};

// GET /cmdi/ping5 -> v5 gadget: ; & and | are stripped, newline is not.
router.get('/ping5', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'The filter now strips <code>;</code>, <code>&amp;</code> and <code>|</code>. Every classic command separator is gone... or is it?';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping5', briefHtml }));
  }
  // VULN: ; & | are stripped, but a newline still separates commands in the shell.
  const filtered = host.replace(/[;&|]/g, '');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    if (host.includes('\n') && out.includes('root:')) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping5', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
