'use strict';
// Basic CSTI: the greeting is stored on the server, but the browser's template
// engine evaluates {{ expression }} as live JavaScript when it renders.
const express = require('express');
const crypto = require('crypto');
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
      var CSTI_NONCE = ${JSON.stringify(cstiNonce(req, 'basic'))};
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
    ${claimBox({ vulnId: 'basic', payload: esc('{{7*7}}'), statusUrl: '/csti/claim-status?v=basic', beaconInfo: 'This page beacons for you: when the preview output contains 49, the page fetches /csti/beacon with v=basic, d=49 and n=<the CSTI_NONCE token rendered into this page>. The token is single-use per page load, so reload for a fresh one after each attempt.' })}
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
    hint: 'The preview renders {{ expression }} as live JavaScript. What expression evaluates to 49?',
    hints: ["The page evaluates {{ }} client-side. Try {{7*7}}.", "The Function constructor runs it. 49 proves execution.", "Submit {{7*7}} and the beacon fires with the token."],
    tools: "B",
    how: 'Save a greeting containing {{7*7}} and watch the preview render 49.',
    link: '/csti#basic',
    start: 'curl -s -b jar -c jar http://localhost:3000/csti/basic | grep -n CSTI_NONCE',
  },
  router,
};
