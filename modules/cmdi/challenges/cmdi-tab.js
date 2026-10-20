'use strict';
// Ping Gadget v9 (spaces blocked, again): spaces are stripped, but a literal
// tab is whitespace to the shell too.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, evidenceInOutput, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-tab',
  name: 'Ping Gadget v9 (spaces blocked, again)',
  difficulty: 'Easy',
  est: '5-10 minutes',
  hint: 'Spaces are stripped from your input. A literal tab character (%09 in a URL) is also whitespace to the shell.',
  hints: [
    "Spaces are stripped. In Repeater, send a host with a space and watch the filter strip it: space is not the only whitespace the shell understands.",
    "The URL-encoded tab (%09) is whitespace to the shell, and the filter never looks for it. Repeater sends %09 through untouched, so build your chain with a separator the filter allows and a word separator it never sees.",
    "Chain a command after the ping and pick one that prints a recognizable file, so the response body confirms the second command actually ran.",
  ],
  tools: 'BZ, B, C',
  how: 'In Burp Repeater, chain a second command after a valid host using a whitespace character the filter never looks for as the word separator, then read the command output in the response body.',
  link: '/cmdi/ping9',
  start: 'Open the Ping Gadget v9 page with Burp Proxy intercepting, submit a normal host like 127.0.0.1, send the request to Repeater, and probe the host parameter there.',
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
    if (host.includes('\t') && evidenceInOutput(out, [host, filtered], PASSWD_EVIDENCE)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping9', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
