'use strict';
// Ping Gadget v8 (; blocked): only the semicolon is stripped, but a pipe
// chains commands just as well without one.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-pipe',
  name: 'Ping Gadget v8 (; blocked)',
  difficulty: 'Easy',
  hint: 'Semicolons are stripped, but the shell has other ways to chain commands. One of them feeds the first command output into the second.',
  hints: [
    "Semicolons are stripped. But | chains commands without a semicolon.",
    "The pipe feeds ping's output into the next command. The filter only looks for ;.",
    "Try ?host=127.0.0.1|id.",
  ],
  tools: 'B, C',
  how: 'Chain with a pipe, e.g. ?host=127.0.0.1|id (encode & as %26 when you need it, but | needs no encoding)',
  link: '/cmdi/ping8',
  start: 'curl "http://localhost:3000/cmdi/ping8?host=127.0.0.1"',
};

// GET /cmdi/ping8 -> v8 gadget: only ";" is stripped.
router.get('/ping8', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'Semicolons are stripped from your input. The shell offers other command separators that this filter forgot.';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping8', briefHtml }));
  }
  // VULN: only ; is stripped; | still chains commands.
  const filtered = host.replace(/;/g, '');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    if (host.includes('|') && out.includes('uid=')) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping8', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
