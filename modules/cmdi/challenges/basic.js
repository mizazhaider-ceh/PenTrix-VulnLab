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
    "Open the page in Burp's browser and submit a normal host. In Proxy history, find the request and send it to Repeater.",
    "In Repeater, look at the host parameter value and think about where it lands in the shell command the server builds.",
    "Edit the host value in Repeater and append a command separator after a valid host, followed by a second command of your choosing. Send it and read the response body: the flag is awarded only when the second command's real output shows up in the response, so pick a command that prints something unmistakable.",
  ],
  tools: 'BZ, B',
  how: 'In Repeater, modify the host parameter so the shell command runs your second command after the ping, then confirm the response body carries its real output before claiming the flag.',
  link: '/cmdi/ping',
  start: 'Open the ping gadget in your browser (with Burp Proxy on), submit a plain host like 127.0.0.1, then push the request to Repeater.',
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
