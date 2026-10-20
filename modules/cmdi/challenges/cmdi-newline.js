'use strict';
// Ping Gadget v5 (separators blocked): ; & and | are all stripped, but a
// newline still separates shell commands and the blacklist forgot it.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, evidenceInOutput, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-newline',
  name: 'Ping Gadget v5 (separators blocked)',
  difficulty: 'Medium',
  est: '10-20 minutes',
  hint: 'The characters ; & and | are all stripped. But a shell treats more than those as command separators. In a URL, %0a becomes one of them. The same gap appears when a value is dropped into the command line with no quotes and the blacklist forgets newline.',
  hints: [
    "Open the page in Burp's browser and submit a normal host, then send the request to Repeater. Try a classic separator in the host value first and watch the filter strip it.",
    "The shell treats more than ; & | as command separators. In a URL, %0a decodes to one of them. Try placing that between a valid host and a second command.",
    "In Repeater, place a URL-encoded newline between a valid host and a command that reads a recognizable file, so each line runs as its own statement. Send it and read the response body: the flag is awarded only when passwd file lines show up in the response; output from other commands (id, for example) proves execution, but it is not the evidence this gadget checks for.",
  ],
  tools: 'BZ, B',
  how: 'In Repeater, inject a URL-encoded newline between a valid host and a second command so the shell runs each line as its own statement, then confirm the response body carries that command real output before claiming the flag.',
  link: '/cmdi/ping5',
  start: 'Open the ping5 gadget in your browser (with Burp Proxy on), submit a plain host like 127.0.0.1, then push the request to Repeater.',
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
    if (host.includes('\n') && evidenceInOutput(out, [host, filtered], PASSWD_EVIDENCE)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping5', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
