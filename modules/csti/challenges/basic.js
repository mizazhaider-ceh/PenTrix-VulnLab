'use strict';
// Basic CSTI: the greeting is stored on the server, but the browser's template
// engine evaluates {{ expression }} as live JavaScript when it renders.
const express = require('express');
const crypto = require('crypto');
const { tokenScriptParts } = require('../../../lib/jstoken');
const { page, esc, claimBox } = require('../../../lib/page');

const router = express.Router();

// The naive client-side template engine, served to the lab page.
// It is intentionally the vulnerability: expressions become live JavaScript.
const RENDER_JS = `
var CSTI_CTX = { constructor: Object }; // VULN: exposing constructor hands out Function
function cstiRender(tpl) {
  function ev(m, expr) {
    try {
      // VULN: {{ expression }} is compiled and executed with Function.
      return Function('ctx', 'with(ctx){ return (' + expr + '); }')(CSTI_CTX);
    } catch (err) { return '[ERR]'; }
  }
  var s = String(tpl).replace(/\\{\\{([\\s\\S]*?)\\}\\}/g, ev);
  // VULN: a second delimiter syntax, [[ expression ]], is evaluated too.
  s = s.replace(/\\[\\[([\\s\\S]*?)\\]\\]/g, ev);
  return s;
}`;

// Per-session, per-vuln token issued when the lab page loads and rendered into
// the page as CSTI_NONCE. The beacon must echo it back, so only a template
// that really evaluated in the page (or a client that loaded the page) can
// claim the flag. Single-use: consumed on award. A bare curl of the beacon
// with no page load earns no flag.
function cstiNonce(req, v) {
  if (!req.session.cstiNonce) req.session.cstiNonce = {};
  // hasOwnProperty: one lab is literally named 'constructor', which exists on
  // Object.prototype - a plain truthiness check would return the Object
  // function instead of issuing a token.
  if (!Object.prototype.hasOwnProperty.call(req.session.cstiNonce, v)) {
    req.session.cstiNonce[v] = crypto.randomBytes(16).toString('hex');
  }
  return req.session.cstiNonce[v];
}
// Script fragment: the page token only exists once this script runs. The
// page renders two random share arrays and computes CSTI_NONCE from them at
// load; the raw token string never appears in the HTML.
function cstiNonceScript(req, v) {
  const p = tokenScriptParts(cstiNonce(req, v));
  return p.decl + '\n      var CSTI_NONCE = ' + p.combine + ';';
}

const DEFAULT_BASIC = "Hello {{'gues'+'t'}}!";

router.get('/basic', (req, res) => {
  const tpl = req.session.csti_basic || DEFAULT_BASIC;
  res.send(page('Basic CSTI', `
    <h2>Greeting card (basic)</h2>
    <p>Your greeting is stored on the server and rendered by the browser's template engine.</p>
    <form class="clay-card" method="POST" action="/csti/basic">
      <div class="card-top"><b>Your greeting</b></div>
      <div class="clay-field">
        <label for="tpl">Greeting template</label>
        <textarea class="clay-input" id="tpl" name="tpl" rows="3" cols="60">${esc(tpl)}</textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Save greeting</button>
    </form>
    <div class="clay-card">
      <div class="card-top"><b>Preview</b></div>
      <div id="out" style="border:1px dashed #888; padding:1em; min-height:2em;"></div>
    </div>
    <script>
      ${RENDER_JS}
      // Page-bound token: the beacon must echo it back.
      ${cstiNonceScript(req, 'basic')}
      var TPL = ${JSON.stringify(tpl)};
      var html = cstiRender(TPL);
      // VULN: rendered template output is injected as HTML.
      document.getElementById('out').innerHTML = html;
      if (html.indexOf('49') !== -1) {
        fetch('/csti/beacon?v=basic&d=' + encodeURIComponent('49') + '&n=' + encodeURIComponent(CSTI_NONCE));
      }
    </script>
    <p class="note">Goal: make the preview show <b>49</b>. The engine evaluates
    <code>{{ expression }}</code> as JavaScript.</p>
    ${claimBox({ vulnId: 'basic', payload: esc('{{ expression }}'), statusUrl: '/csti/claim-status?v=basic', beaconInfo: 'This page beacons for you: when the preview output contains 49, the page fetches /csti/beacon with v=basic, d=49 and n=<the CSTI_NONCE token rendered into this page>. The token is single-use per page load, so reload for a fresh one after each attempt.' })}
  `));
});

router.post('/basic', (req, res) => {
  req.session.csti_basic = String(req.body.tpl || '').slice(0, 2000) || DEFAULT_BASIC;
  res.redirect('/csti/basic');
});

module.exports = {
  vuln: {
    id: 'basic',
    name: 'Basic Template Evaluation',
    difficulty: 'Easy',
    est: '5-10 minutes',
    hint: 'The preview renders {{ expression }} as live JavaScript. What expression evaluates to 49?',
    hints: ["Open the lab page in Burp's embedded browser and find the greeting form. The preview evaluates {{ }} client-side as live JavaScript, so save an arithmetic expression that produces a distinctive number.", "The page source carries a page-bound token (CSTI_NONCE). Repeater can replay the beacon, but only with a fresh token from a real page load.", "When the preview renders 49, the page fires its beacon for you with that token. Watch the beacon request in Proxy and see the flag come back."],
    tools: "BZ, B",
    how: 'Save a greeting whose template expression evaluates to a distinctive number in Burp\'s embedded browser, then load the page and watch the preview.',
    link: '/csti#basic',
    start: 'In Burp, proxy your browser (or use the embedded browser) and open /csti/basic. Find the greeting form and the CSTI_NONCE token in the page source.',
  },
  router,
};
