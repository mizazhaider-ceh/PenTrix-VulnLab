'use strict';
// Ping Gadget v3 (spaces stripped): the filter deletes every space, but the
// shell's $IFS variable expands to whitespace and still separates words.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, evidenceInOutput, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-ifs',
  name: 'Ping Gadget v3 (spaces stripped)',
  difficulty: 'Medium',
  hint: 'Every space is deleted from your input, but the shell still needs word separators. Bash has a built-in variable that expands to whitespace.',
  hints: [
    "Open the page in Burp's browser and submit a normal host, then send the request to Repeater. First try a space-containing injection and watch the response: every space vanishes.",
    "In Repeater, think about where the host value lands in the shell command. The shell still needs word separators, and Bash has a built-in variable that expands to whitespace.",
    "Chain a second command after the ping with a statement separator, writing every separator with the whitespace variable the filter forgot to strip. Send it in Repeater and read the response body: the flag is awarded only when the second command's real output shows up, so pick a command that prints something unmistakable.",
  ],
  tools: 'BZ, B',
  how: 'In Repeater, rewrite the injection so every word separator is the shell whitespace variable the filter never strips, then confirm the response body carries the injected command real output before claiming the flag.',
  link: '/cmdi/ping3',
  start: 'Open the ping3 gadget in your browser (with Burp Proxy on), submit a plain host like 127.0.0.1, then push the request to Repeater.',
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
    if (/\$(\{)?IFS\}?/.test(host) && evidenceInOutput(out, [host, filtered], PASSWD_EVIDENCE)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping3', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
