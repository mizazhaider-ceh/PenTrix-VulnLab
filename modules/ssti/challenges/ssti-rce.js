'use strict';
// ssti-rce: "Template to Shell" gadget. The homemade template engine evaluates
// {{ }} with a full Node.js runtime behind it: no sandbox, require() in
// scope. The flag is awarded when the rendered output contains "uid=", which
// only happens when a real system command ran (SSTI to remote code execution).
const express = require('express');
const { brief, esc, flagBox, fixPanel, hintBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { sstiRender } = require('../shared');

const router = express.Router();

// GET /ssti/exec -> template gadget backed by the full Node.js runtime.
router.get('/exec', (req, res) => {
  const hasInput = req.query.expr !== undefined;
  const raw = hasInput ? String(req.query.expr) : '';
  let result = '';
  let awardHtml = '';
  if (hasInput) {
    const input = raw;
    const tpl = `Result: ${input}`;
    // VULN: template expressions run in Node with require() in scope: SSTI becomes remote code execution.
    const rendered = sstiRender(tpl, {});
    result = `<div class="ssti-result card"><div class="card-top"><b>Command result</b></div>${rendered}</div>`;
    if (rendered.includes('uid=')) {
      awardHtml = flagBox(award(req, 'ssti', 'ssti-rce')) + fixPanel('ssti', 'ssti-rce');
    }
  }

  res.send(page('Template to Shell', `
    ${brief('Template to Shell',
      `<p>The engine evaluates <code>{{ }}</code> with a full Node.js runtime behind it: there ` +
      `is no sandbox. Expressions can reach <code>require</code> and from there the operating system. ` +
      `Prove it by running a system command and showing its output.</p>`)}
    <div class="card">
      <div class="card-top"><b>Run an expression</b></div>
      <form method="get" action="/ssti/exec">
        <div class="clay-field">
          <label for="exec-input">expr</label>
          <input class="clay-input" id="exec-input" name="expr" type="text" value="${esc(raw)}" size="48" autocomplete="off" />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Render</button>
      </form>
    </div>
    ${result}
    ${awardHtml}
    ${hintBox('You are one <code>require("child_process")</code> away from the shell. What does <code>execSync("id")</code> return?')}
    <p><a href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'ssti-rce',
    name: 'SSTI to Remote Code Execution',
    difficulty: 'Hard',
    hint: 'There is no sandbox: expressions run in Node.js with require() in scope. In Repeater, reach child_process and run a system command from the expr parameter.',
    hints: ["Capture the /ssti/exec form request in Burp Proxy and send it to Repeater. Probe the expr parameter with a small arithmetic expression to confirm the engine evaluates {{ }}.", "In Repeater, remember the engine runs the full Node.js runtime: expressions can reach require(). Which built-in module runs system commands?", "In Repeater, require the child-process module from the template scope, run a harmless system command synchronously, and convert its raw output to text so it renders in the response."],
    tools: 'BZ, B, C',
    how: 'In Repeater, send expr={{require("child_process").execSync("id").toString()}} and read the uid= output from the rendered result.',
    link: '/ssti#ssti-rce',
    start: 'With Burp Proxy on, open /ssti/exec in the browser, submit an expression, and send the request to Repeater. Try expr={{7*7}} first; the page should echo 49.',
  },
  router,
};
