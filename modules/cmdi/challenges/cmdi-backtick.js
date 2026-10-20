'use strict';
// Ping Gadget v6 ($() blocked): the filter removes "$(" to kill modern
// command substitution, but legacy backtick substitution still runs.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, evidenceInOutput, ID_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-backtick',
  name: 'Ping Gadget v6 ($() blocked)',
  difficulty: 'Easy',
  est: '5-10 minutes',
  hint: 'The filter removes $(, killing the modern command-substitution syntax. The shell has an older syntax that does the same job. Probe the host parameter in Repeater to see which forms survive the filter.',
  hints: [
    "In Repeater, send a request carrying a $( substitution attempt and read the page to see what the filter removed. Then ask: which older substitution syntax does this filter never mention?",
    "Command substitution has a legacy form older than $(): whatever sits between a pair of those marks runs, and its output lands in place. In Repeater, probe which of those characters survive the round trip (the URL-decode view shows you exactly what the server received).",
    "Join the ping to a second statement with a separator, and wrap your injected command in the legacy substitution pair the filter ignores. Confirm in Repeater by reading the injected command's real output in the response body: the flag only fires when that output shows up.",
  ],
  tools: 'BZ, B, C',
  how: 'In Repeater, submit the ping request with the host parameter using the legacy command-substitution syntax the filter does not strip, then read the injected command output in the response.',
  link: '/cmdi/ping6',
  start: 'Open the Ping Gadget v6 page with Burp Proxy intercepting, submit a normal ping, send the request to Repeater, and probe the host parameter there.',
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
    if (host.includes('`') && evidenceInOutput(out, [host, filtered], ID_EVIDENCE)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping6', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
