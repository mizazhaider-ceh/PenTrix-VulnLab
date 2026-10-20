'use strict';
// Ping Gadget v4 ($IFS blocked too): spaces and the literal text "$IFS" are
// both stripped, but the braced form ${IFS} expands the same variable and
// does not match the naive string filter.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, evidenceInOutput, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-braces',
  name: 'Ping Gadget v4 ($IFS blocked too)',
  difficulty: 'Medium',
  est: '15-25 minutes',
  hint: 'Spaces are stripped and the literal text $IFS is stripped as well. The braced form of a variable looks different to a naive string filter. Probe the host parameter in Repeater to see exactly which bytes the filter removes.',
  hints: [
    "In Repeater, send the host parameter carrying the exact text $IFS and read the page to see what the filter removed. It strips that literal string only. What other spelling of the same variable would not match?",
    "Variables have a braced form that a naive string filter cannot see. Use Repeater's Decoder tab to check your encoding: the server must receive the spelling the filter misses, with no literal spaces anywhere in the value.",
    "Chain a second command after the ping with a statement separator, writing the whole command with no literal spaces by using the braced variable spelling the filter misses. Confirm the win in Repeater by spotting passwd file lines in the response body; other commands' output proves execution but is not the evidence this gadget checks for.",
  ],
  tools: 'BZ, B, C',
  how: 'In Repeater, submit the ping request with the host parameter using the braced variable spelling that the naive string filter misses, with no literal spaces, and read the file content in the response.',
  link: '/cmdi/ping4',
  start: 'Open the Ping Gadget v4 page with Burp Proxy intercepting, submit a normal ping, send the request to Repeater, and probe the host parameter there.',
};

// GET /cmdi/ping4 -> v4 gadget: spaces and the literal string "$IFS" are stripped.
router.get('/ping4', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'Spaces are stripped, and now the literal text <code>$IFS</code> is stripped too. The filter is just string matching, not shell parsing.';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping4', briefHtml }));
  }
  // VULN: the filter removes the exact string $IFS, but ${IFS} expands the same variable.
  const filtered = host.replace(/ /g, '').replace(/\$IFS/g, '');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    if (/\$\{IFS\}/.test(host) && evidenceInOutput(out, [host, filtered], PASSWD_EVIDENCE)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping4', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
