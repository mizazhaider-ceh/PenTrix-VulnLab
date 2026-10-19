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
  hint: 'Only the ";" character is removed, and only once. Probe the host parameter in Repeater: shells give you several other ways to chain commands.',
  hints: [
    "In Repeater, watch what the filter removes from your host parameter: it strips the first semicolon only. The shell offers several other command separators that this filter never touches. Which ones?",
    "Try the separator in its URL-encoded form so the raw filter never sees it: Repeater lets you edit the parameter and resend in one place. A newline always starts a second, independent command no matter how the first exits, while && and || depend on the first command's exit status. Intruder is built for this kind of separator fuzzing: run a payload set of separators through the host parameter.",
    "Follow a valid host with an encoded separator the filter cannot see in raw form, then end with a command whose output you will recognize. Confirm the win in Repeater by spotting that output in the response.",
  ],
  tools: 'BZ, B, C',
  how: 'In Burp Repeater, submit the ping request with the host parameter carrying a URL-encoded command separator the filter cannot see, then read the injected command output in the response.',
  link: '/cmdi/ping2',
  start: 'Open the Ping Gadget v2 page with Burp Proxy intercepting, submit a normal ping, send the request to Repeater, and probe the host parameter there.',
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
