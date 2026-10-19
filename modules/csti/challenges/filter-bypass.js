'use strict';
// Filter bypass CSTI: the server rejects {{ }} at the door, but the client
// engine also evaluates a second delimiter, [[ ]], that the filter never heard of.
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

const DEFAULT_FB = "[[ 'hel' + 'lo' ]]";

router.get('/filter-bypass', (req, res) => {
  const tpl = req.session.csti_fb || DEFAULT_FB;
  res.send(page('Filtered CSTI', `
    <h2>Greeting card (filtered)</h2>
    <p class="note">Server-side filter: templates containing <code>{{</code> or
    <code>}}</code> are rejected. Surely that stops template injection...</p>
    <form class="clay-card" method="POST" action="/csti/filter-bypass">
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
      var CSTI_NONCE = ${JSON.stringify(cstiNonce(req, 'filter-bypass'))};
      var TPL = ${JSON.stringify(tpl)};
      var html = cstiRender(TPL);
      document.getElementById('out').innerHTML = html;
      if (html.indexOf('49') !== -1) {
        fetch('/csti/beacon?v=filter-bypass&d=' + encodeURIComponent('49') + '&n=' + encodeURIComponent(CSTI_NONCE));
      }
    </script>
    <p class="note">Goal: make the preview show <b>49</b> without using
    <code>{{</code> or <code>}}</code>. The client engine knows more than one syntax.</p>
    ${claimBox({ vulnId: 'filter-bypass', payload: esc('[[7*7]]'), statusUrl: '/csti/claim-status?v=filter-bypass', beaconInfo: 'This page beacons for you: when the preview output contains 49, the page fetches /csti/beacon with v=filter-bypass, d=49 and n=<the CSTI_NONCE token rendered into this page>. The token is single-use per page load, so reload for a fresh one after each attempt.' })}
  `));
});

router.post('/filter-bypass', (req, res) => {
  const tpl = String(req.body.tpl || '').slice(0, 2000);
  // VULN: naive blacklist. It blocks {{ }} at the door, but the client-side
  // engine also evaluates the [[ ]] delimiter, which the filter never heard of.
  if (tpl.includes('{{') || tpl.includes('}}')) {
    return res.status(400).send(page('Blocked', `
      <h2>Blocked by the filter</h2>
      <p>Templates containing <code>{{</code> or <code>}}</code> are not allowed.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csti/filter-bypass">Back</a></p>
    `));
  }
  req.session.csti_fb = tpl || DEFAULT_FB;
  res.redirect('/csti/filter-bypass');
});

module.exports = {
  vuln: {
    id: 'filter-bypass',
    name: 'Filter Bypass via Alternative Delimiter',
    difficulty: 'Medium',
    hint: 'The server rejects {{ and }}. But the client engine understands a second delimiter syntax, which the filter never heard of.',
    hints: ["The filter blocks {{ }}. But the engine has another delimiter.", "[[ ]] works too. The blacklist only knows {{ }}.", "Probe the alternative delimiter with an arithmetic expression that yields a distinctive number: the blacklist never heard of it."],
    tools: "B",
    how: 'Use the [[ expression ]] syntax to evaluate 7*7 without touching {{ }}.',
    link: '/csti#filter-bypass',
    start: 'curl -s -b jar -c jar http://localhost:3000/csti/filter-bypass | grep -n CSTI_NONCE',
  },
  router,
};
