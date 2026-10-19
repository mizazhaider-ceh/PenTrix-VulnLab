'use strict';
// Ping Gadget v9 (spaces blocked, again): spaces are stripped, but a literal
// tab is whitespace to the shell too.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-tab',
  name: 'Ping Gadget v9 (spaces blocked, again)',
  difficulty: 'Easy',
  hint: 'Spaces are stripped from your input. A literal tab character (%09 in a URL) is also whitespace to the shell.',
  hints: [
    "Spaces are stripped. But space isn't the only whitespace.",
    "%09 is a tab. The shell treats it as a word separator just like space.",
    "Try ?host=127.0.0.1;cat%09/etc/passwd.",
  ],
  tools: 'B, C',
  how: 'Use a tab as the word separator, e.g. ?host=127.0.0.1;cat%09/etc/passwd',
  link: '/cmdi/ping9',
  start: 'curl "http://localhost:3000/cmdi/ping9?host=127.0.0.1"',
};

// GET /cmdi/ping9 -> v9 gadget: spaces are stripped (again).
router.get('/ping9', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'Spaces are stripped from your input again. But space is not the only whitespace the shell understands.';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping9', briefHtml }));
  }
  // VULN: spaces are stripped, but a literal tab still acts as a shell word separator.
  const filtered = host.replace(/ /g, '');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    if (host.includes('\t') && PASSWD_EVIDENCE.test(out)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping9', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
