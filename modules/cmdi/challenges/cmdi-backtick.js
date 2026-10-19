'use strict';
// Ping Gadget v6 ($() blocked): the filter removes "$(" to kill modern
// command substitution, but legacy backtick substitution still runs.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, ID_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-backtick',
  name: 'Ping Gadget v6 ($() blocked)',
  difficulty: 'Easy',
  hint: 'The filter removes $(, killing the modern command-substitution syntax. The shell has an older syntax that does the same job.',
  hints: [
    "The filter removes $(, killing modern command substitution. But shells are old. What came before $()?",
    "Backticks are the legacy command-substitution syntax: whatever sits between a pair of them runs, and its output lands in place. The filter never mentions them.",
    "Join the ping to a second statement with a separator, and inside your input use the legacy substitution syntax to run a command whose output gets dropped in place. The injected command's output must show up in the response for the flag to fire.",
  ],
  tools: 'B, C',
  how: 'Use backticks for command substitution, e.g. ?host=127.0.0.1;echo `id`',
  link: '/cmdi/ping6',
  start: 'curl "http://localhost:3000/cmdi/ping6?host=127.0.0.1"',
};

// GET /cmdi/ping6 -> v6 gadget: "$(" is stripped, backticks are not.
router.get('/ping6', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'The filter removes <code>$(</code>, blocking the modern <code>$(...)</code> command-substitution syntax. Older shells had another way.';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping6', briefHtml }));
  }
  // VULN: $( is stripped, but legacy backtick command substitution still runs.
  const filtered = host.replace(/\$\(/g, '');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    if (host.includes('`') && ID_EVIDENCE.test(out)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping6', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
