'use strict';
// Ping Gadget v2 (weak blacklist): strips a single ";" from the host value,
// which blocks the obvious payload but none of the shell's other separators.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { executedSomething, gadgetPage, runPing } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'bypass',
  name: 'Ping Gadget v2 (weak blacklist)',
  difficulty: 'Medium',
  hint: 'Only the ";" character is removed, and only once. Shells give you several other ways to chain commands.',
  hints: [
    "The filter strips semicolons. But the shell has other command separators. Which ones?",
    "A newline (%0a) always starts a second, independent command, no matter how the first one exits. && and || also work, but only when the first command's exit status cooperates. The filter only removes the first ; it finds.",
    "Follow a valid host with a URL-encoded separator the filter cannot see in raw form, then end with a command whose output you will recognize. Remember: a newline always runs the second command, while && and || depend on the first command's exit status. Confirm success by spotting that output in the response.",
  ],
  tools: 'B, C',
  how: 'Bypass the semicolon filter with a newline, && , or ||, e.g. ?host=127.0.0.1%0aid',
  link: '/cmdi/ping2',
  start: 'curl "http://localhost:3000/cmdi/ping2?host=127.0.0.1"',
};

// GET /cmdi/ping2 -> v2 gadget: a naive blacklist that strips ';' only, once.
router.get('/ping2', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  const briefHtml = 'The developers heard about command injection and "fixed" it by removing <code>;</code> from your input. Find a way around the filter.';
  if (host === undefined) {
    return res.send(gadgetPage({ v: vuln, route: 'ping2', briefHtml }));
  }
  // VULN: weak blacklist that only removes a single ';' instead of proper escaping.
  const filtered = host.replace(';', '');
  runPing(filtered, (outputHtml, out) => {
    let flagHtml = '';
    // Award only when the command output shows an injected command ran.
    if (executedSomething(out, [host, filtered])) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({ v: vuln, route: 'ping2', host, briefHtml, filtered, resultHtml: outputHtml, flagHtml }));
  });
});

module.exports = { vuln, router };
