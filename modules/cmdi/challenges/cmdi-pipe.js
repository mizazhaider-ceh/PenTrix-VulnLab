'use strict';
// Ping Gadget v8 (; blocked): only the semicolon is stripped, but a pipe
// chains commands just as well without one.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, evidenceInOutput, ID_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-pipe',
  name: 'Ping Gadget v8 (; blocked)',
  difficulty: 'Easy',
  est: '5-10 minutes',
  hint: 'Semicolons are stripped, but the shell has other ways to chain commands. One of them feeds the first command output into the second.',
  hints: [
    "In Repeater, test the filter first: send a host with a semicolon and watch the page strip it. The filter only watches for semicolons.",
    "The shell has other command separators the filter never touches. In Repeater, swap the stripped separator for one that feeds the first command's output into the next, placed right after a valid host.",
    "Confirm the win in Repeater: the flag fires only when your second command's real output shows up in the response body, so end with a command whose output you will recognize.",
  ],
  tools: 'BZ, B, C',
  how: 'In Burp Repeater, chain a second command after a valid host with a separator the filter never strips, then confirm its real output in the response body.',
  link: '/cmdi/ping8',
  start: 'Open the Ping Gadget v8 page with Burp Proxy intercepting, submit a normal host like 127.0.0.1, send the request to Repeater, and probe the host parameter there.',
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
    if (host.includes('|') && evidenceInOutput(out, [host, filtered], ID_EVIDENCE)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping8', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
