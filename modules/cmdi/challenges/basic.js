'use strict';
// Ping Gadget (no filtering): the host field is dropped straight into a shell
// command. Any shell metacharacter lets a second command run.
const express = require('express');
const { award } = require('../../../lib/flags');
const { fixPanel, flagBox } = require('../../../lib/page');
const { executedSomething, gadgetPage, runPing } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'basic',
  name: 'Ping Gadget (no filtering)',
  difficulty: 'Medium',
  hint: 'The host value is pasted straight into a shell command. What happens when you add a second command after it?',
  hints: [
    "The ping tool takes a host and runs ping. Where does your input go in the command?",
    "Your input is concatenated into a shell command with no escaping. A semicolon ends the ping and starts a new command.",
    "Try ?host=127.0.0.1;id or ?host=127.0.0.1;cat /etc/passwd. The flag needs the second command's output (uid= or root:) in the response.",
  ],
  tools: 'B, C',
  how: 'Inject an extra shell command through the host field, e.g. ?host=127.0.0.1;id',
  link: '/cmdi/ping',
  start: 'curl "http://localhost:3000/cmdi/ping?host=127.0.0.1"',
};

// GET /cmdi/ping -> v1 gadget, zero filtering.
router.get('/ping', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : undefined;
  if (host === undefined) {
    return res.send(gadgetPage({
      v: vuln,
      route: 'ping',
      briefHtml: 'This network tool runs <code>ping</code> on a host you choose. Try to make it run <em>another</em> command too, like <code>id</code>.',
    }));
  }
  runPing(host, (outputHtml, out) => {
    let flagHtml = '';
    // Award only when the command output shows an injected command ran.
    if (executedSomething(out, [host])) {
      const flag = award(req, 'cmdi', vuln.id);
      flagHtml = flagBox(flag) + fixPanel('cmdi', vuln.id);
    }
    res.send(gadgetPage({
      v: vuln,
      route: 'ping',
      host,
      briefHtml: 'This network tool runs <code>ping</code> on a host you choose. Try to make it run <em>another</em> command too, like <code>id</code>.',
      resultHtml: outputHtml,
      flagHtml,
    }));
  });
});

module.exports = { vuln, router };
