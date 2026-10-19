'use strict';
// Scope Leak (data exposure): the same naive template engine as the 'basic'
// challenge, but the handler's closure scope also holds secretFlag, a
// server-side variable containing the flag. Once {{ }} evaluation is proven,
// probe the scope with name={{secretFlag}} to read it. (Named 'rce' for
// continuity with the module router; the flaw itself is a scope leak, not RCE.)
// NOTE: challenges 'basic' and 'rce' share the /ssti/greet route in
// modules/ssti/router.js. This file therefore keeps the complete route
// behavior, including both award points, identical to router.js. Mounting
// either this router or the 'basic' router serves a fully working /ssti/greet.
const express = require('express');
const { brief, esc, fixPanel, flagBox, hintBox, page, payloadBlock } = require('../../../lib/page');
const { award, flagFor } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'rce',
  name: 'Scope Leak (Data Exposure, Not RCE)',
  difficulty: 'Medium',
  hint: 'In Burp Repeater, once you know {{ }} is evaluated, ask yourself: what server-side variables are in scope when the expression runs? Probe for a variable that holds the flag: its name is the most obvious one you would pick for this job.',
  hints: ["Send the /ssti/greet request to Burp Repeater and first confirm {{ }} evaluates by trying a harmless arithmetic expression; the module page tells you the answer to expect.", "In Repeater, change the name parameter and think about which server-side variables the template engine can see while it runs. Probe for the one holding the flag: its name is the most obvious one you would pick for this job.", "Read that in-scope variable directly in Repeater: you only need its conventional name, and the template echoes its value into the greeting. (This is a scope leak, not RCE.)"],
  tools: 'BZ, B, C',
  how: 'In Burp Repeater, send /ssti/greet with the name parameter set to a {{ }} expression that reads the flag variable from the template scope; the rendered greeting echoes its value.',
  link: '/ssti#rce',
  start: 'Open /ssti/greet in the browser with Burp Proxy intercepting, send the request to Repeater, then change the name parameter to probe which server-side variables the template can see.',
};

// GET /ssti/greet -> greeting card rendered by the naive template engine.
// Behavior identical to router.js: anything inside {{ }} is eval()d with the
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
      `that evaluates <code>{{ expressions }}</code>. Try <code>{{7*7}}</code> first, then hunt for what is in scope.</p>`)}
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
    <p>Quick links: <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssti/greet?name={{7*7}}">test {{7*7}}</a> <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssti">Back to SSTI module</a></p>
  `));
});

module.exports = { vuln, router };
