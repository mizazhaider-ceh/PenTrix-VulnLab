'use strict';
// Ping Gadget v3 (spaces stripped): the filter deletes every space, but the
// shell's $IFS variable expands to whitespace and still separates words.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-ifs',
  name: 'Ping Gadget v3 (spaces stripped)',
  difficulty: 'Medium',
  hint: 'Every space is deleted from your input, but the shell still needs word separators. Bash has a built-in variable that expands to whitespace.',
  hints: [
    "Spaces are deleted from your input. But the shell needs word separators. What else expands to whitespace?",
    "Bash's $IFS variable expands to whitespace. Use it where you'd put a space.",
    "Try ?host=127.0.0.1;cat$IFS/etc/passwd.",
  ],
  tools: 'B, C',
  how: 'Replace spaces with $IFS, e.g. ?host=127.0.0.1;cat$IFS/etc/passwd',
  link: '/cmdi/ping3',
  start: 'curl "http://localhost:3000/cmdi/ping3?host=127.0.0.1"',
};

// GET /cmdi/ping3 -> v3 gadget: every space is stripped before the shell runs it.
router.get('/ping3', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'The developers now strip <b>every space</b> from your input before building the shell command. Find another way to separate your words.';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping3', briefHtml }));
  }
  // VULN: spaces are stripped, but $IFS still expands to a word separator in the shell.
  const filtered = host.replace(/ /g, '');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    if (/\$(\{)?IFS\}?/.test(host) && PASSWD_EVIDENCE.test(out)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping3', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
