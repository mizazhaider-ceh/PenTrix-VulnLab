'use strict';
// Basic Template Injection: the greeting card renders your name through a
// naive homemade template engine that eval()s anything inside {{ }} with the
// handler's closure scope (name, secretFlag) visible. Prove evaluation with
// name={{7*7}} and look for 49 in the greeting.
// NOTE: challenges 'basic' and 'rce' share the /ssti/greet route. This
// file therefore keeps the complete route behavior, including both award
// points, identical to the sibling 'rce' challenge file. Mounting either
// this router or the 'rce' router serves a fully working /ssti/greet.
// The module itself is assembled in modules/ssti/index.js.
const express = require('express');
const { brief, esc, fixPanel, flagBox, hintBox, page, payloadBlock } = require('../../../lib/page');
const { award, flagFor } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'basic',
  name: 'Basic Template Injection',
  // Rebalanced from Medium (P3-10): proving evaluation with {{7*7}} is the
  // module's gentlest step, and the module previously had zero Easy challenges.
  difficulty: 'Easy',
  est: 'about 5 minutes',
  hint: 'The greeting is built with a naive template engine: anything you put inside {{ }} gets evaluated. Start by proving it with simple arithmetic, like a multiplication the page could only echo back if it really ran your expression.',
  hints: ["The greeting echoes your name back. Capture the form request in Burp Proxy and send it to Repeater, then try typing your name as a template expression instead.", "In Repeater, anything between {{ }} in the name value is evaluated server side. Tweak the expression and watch the rendered greeting change in the response.", "Prove the engine evaluates templates: in Repeater, place a small arithmetic expression between {{ }} in the name parameter. If the page echoes the computed answer instead of your literal text, you have SSTI and the flag is yours."],
  tools: 'BZ, B',
  how: 'In Repeater, prove the greeting engine evaluates expressions instead of echoing them literally, with a small arithmetic test whose result only appears if the engine really ran it.',
  link: '/ssti#basic',
  start: 'With Burp Proxy on, open /ssti/greet in the browser, submit a name, and send the request to Repeater. Experiment with the name parameter as a template expression and read the rendered greeting in the response.',
};

// GET /ssti/greet -> greeting card rendered by the naive template engine.
// Behavior identical to the sibling 'rce' challenge file: anything inside {{ }} is eval()d with the
// function's scope visible, the raw result is injected into the page, and the
// flags are awarded at the same points (basic on 49, rce on the leaked flag).
router.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  const secretFlag = flagFor('ssti', 'rce'); // server-side variable, in scope below

  let result = '';
  let awardHtml = '';

  if (req.query.name) {
    const tpl = `Hello ${name}!`;
    // VULN: naive template engine eval()s anything inside {{ }} with the function's scope (name, secretFlag) visible
    const rendered = tpl.replace(/\{\{(.*?)\}\}/g, (_, e) => { try { return eval(e); } catch { return ''; } });

    // VULN: the evaluated result is injected into the page raw so students can see the output plainly
    result = `<div class="ssti-result card"><div class="card-top"><b>Rendered greeting</b></div>${rendered}</div>`;

    if (/\{\{.*\}\}/.test(name) && rendered.includes('49') && !rendered.includes(secretFlag)) {
      awardHtml += flagBox(award(req, 'ssti', 'basic'));
      awardHtml += fixPanel('ssti', 'basic');
    }
    if (rendered.includes(secretFlag)) {
      awardHtml += flagBox(award(req, 'ssti', 'rce'));
      awardHtml += fixPanel('ssti', 'rce');
    }
  }

  res.send(page('SSTI Greeting', `
    ${brief('Greeting card',
      `<p>Enter your name and the server greets you. The greeting is rendered by a naive template engine ` +
      `that evaluates <code>{{ expressions }}</code>. Start with a small arithmetic expression to prove evaluation, then hunt for what is in scope.</p>`)}
    <div class="card">
      <div class="card-top"><b>Get greeted</b></div>
      <form method="get" action="/ssti/greet">
        <label for="name"><b>Name:</b></label><br />
        <input class="clay-input" id="name" name="name" type="text" value="${esc(req.query.name || '')}" size="40" />
        <button type="submit" class="clay-btn clay-btn-primary">Greet me</button>
      </form>
    </div>
    ${result}
    ${awardHtml}
    ${payloadBlock('Starting point', vuln.start)}
    ${hintBox(esc(vuln.hint))}
    <p>Quick links: <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssti/greet">Open the greeting card</a> <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = { vuln, router };
