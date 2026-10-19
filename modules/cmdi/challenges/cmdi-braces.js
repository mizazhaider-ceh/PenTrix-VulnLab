'use strict';
// Ping Gadget v4 ($IFS blocked too): spaces and the literal text "$IFS" are
// both stripped, but the braced form ${IFS} expands the same variable and
// does not match the naive string filter.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { gadgetPage, runPing, PASSWD_EVIDENCE } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'cmdi-braces',
  name: 'Ping Gadget v4 ($IFS blocked too)',
  difficulty: 'Medium',
  hint: 'Spaces are stripped and the literal text $IFS is stripped as well. The braced form of a variable looks different to a naive string filter.',
  hints: [
    "The filter strips the exact string $IFS. But variables have another spelling.",
    "${IFS} is the braced form. A naive string filter looking for '$IFS' misses it.",
    "Try ?host=127.0.0.1;cat${IFS}/etc/passwd.",
  ],
  tools: 'B, C',
  how: 'Use ${IFS} instead of $IFS, e.g. ?host=127.0.0.1;cat${IFS}/etc/passwd',
  link: '/cmdi/ping4',
  start: 'curl "http://localhost:3000/cmdi/ping4?host=127.0.0.1"',
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
    if (/\$\{IFS\}/.test(host) && PASSWD_EVIDENCE.test(out)) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping4', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
