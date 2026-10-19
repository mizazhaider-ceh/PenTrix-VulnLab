'use strict';
// Ping Gadget v7 (cat and / blocked): the filter strips the word "cat" and a
// standalone "/", but shell glob wildcards rebuild both at run time.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-wildcard',
  name: 'Ping Gadget v7 (cat and / blocked)',
  difficulty: 'Hard',
  hint: 'The words "cat" and "/" are stripped as standalone tokens. The shell expands ? into any single character, including inside paths and command names.',
  hints: [
    "The filter strips the word 'cat' and standalone '/'. But the shell expands wildcards before running.",
    "Wildcards expand after the filter has already run, and ? stands for any single character. So you can spell a banned word without typing any of its letters: count the letters and build a pattern that matches them.",
    "Rebuild the blocked command name and path with ? placeholders, one per character, and chain it after the ping with a statement separator. Look for the file's content in the response.",
  ],
  tools: 'B, C',
  how: 'Glob your way around both words, e.g. ?host=127.0.0.1;/???/bin/?at /???/p?sswd',
  link: '/cmdi/ping7',
  start: 'curl "http://localhost:3000/cmdi/ping7?host=127.0.0.1"',
};

// GET /cmdi/ping7 -> v7 gadget: the word "cat" and a standalone "/" are stripped.
router.get('/ping7', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'The filter strips the word <code>cat</code> and any standalone <code>/</code> token. You need to read <code>/etc/passwd</code> without typing either.';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping7', briefHtml }));
  }
  // VULN: word-boundary blacklist for cat and / is defeated by ? glob wildcards.
  const filtered = host.replace(/\bcat\b/gi, '').replace(/(^|\s)\/(?=\s|$)/g, '$1');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    if (host.includes('?') && PASSWD_EVIDENCE.test(out)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping7', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
