'use strict';
// CSTI inside an HTML attribute: the badge text is entity-encoded by the
// server into the value attribute, but the browser decodes it back with
// getAttribute() before the client-side template engine evaluates it.
// Server-side encoding cannot stop client-side evaluation. Behavior identical
// to modules/csti/router.js: same engine, same session storage, same routes,
// same flag condition.
const express = require('express');
const crypto = require('crypto');
const { page, esc, appShell } = require('../../../lib/page');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'attr',
  name: 'CSTI Inside an HTML Attribute',
  difficulty: 'Medium',
  hint: 'The server entity-encodes your text into the value attribute, but the browser decodes it with getAttribute before the engine evaluates it. Encoding does not stop client-side evaluation.',
  hints: [
    "The template is inside an HTML attribute. When is it evaluated?",
    "After HTML decoding. The attribute value becomes template code.",
    "Inject into the attribute so the decoded value is a template expression whose result proves evaluation: an arithmetic result is enough.",
  ],
  tools: 'B, DT',
  how: 'Save {{7*7}} as the badge text; the attribute decodes and the engine renders 49.',
  link: '/csti#attr',
  start: 'curl -s -c jar http://localhost:3000/csti/attr\n# Browser lab: open http://localhost:3000/csti/attr, save badge text, and watch the attribute decode and evaluate.',
};

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

const DEFAULT_ATTR = '{{1+1}}';

// Attribute encoding used for the badge value, identical to router.js: it
// does not escape single quotes, and getAttribute() decodes it back anyway.
function escAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// GET /csti/attr -> profile badge lab (Lab 4 in modules/csti/router.js).
router.get('/attr', (req, res) => {
  const tpl = req.session.csti_attr || DEFAULT_ATTR;
  res.send(page('Attribute CSTI', `
    ${appShell('BadgeForge', `
      <h2>Profile badge (attribute context)</h2>
      <p>Your badge text is placed inside an HTML attribute, entity-encoded by the server.
      Surely encoding <code>&quot;</code> stops injection...</p>
      <form method="POST" action="/csti/attr">
        <div class="clay-field">
          <label for="tpl">Badge text</label>
          <textarea class="clay-input" id="tpl" name="tpl" rows="3" maxlength="2000">${esc(tpl)}</textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Save badge text</button>
      </form>
      <h3>Badge</h3>
      <div class="card">
        <div class="clay-field">
          <label for="badge">Your badge</label>
          <input class="clay-input" id="badge" type="text" size="60" value="${escAttr(tpl)}" readonly />
        </div>
        <p id="msg"></p>
      </div>
      <script>
        ${RENDER_JS}
        // Page-bound token: the beacon must echo it back.
        var CSTI_NONCE = ${JSON.stringify(cstiNonce(req, 'attr'))};
        // VULN: getAttribute() decodes the entities back, and then the raw
        // template is evaluated client-side. Server-side encoding cannot stop
        // client-side evaluation.
        var raw = document.getElementById('badge').getAttribute('value');
        var html = cstiRender(raw);
        document.getElementById('badge').value = html;
        document.getElementById('msg').textContent = 'Evaluated inside the value attribute: ' + html;
        if (html.indexOf('49') !== -1) {
          fetch('/csti/beacon?v=attr&d=' + encodeURIComponent('49') + '&n=' + encodeURIComponent(CSTI_NONCE));
        }
      </script>
      <p class="note">Goal: make the badge show <b>49</b>. View source: your payload sits
      entity-encoded in the attribute, yet it still evaluates. Double quotes in payloads are
      fine; the browser decodes them back before the engine runs.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csti">Back to the CSTI module</a></p>
    `, { crumb: 'Profiles · Badges', mark: '&#9670;' })}
  `));
});

// POST /csti/attr -> save the badge text (max 2000 chars) and re-render.
router.post('/attr', (req, res) => {
  req.session.csti_attr = String(req.body.tpl || '').slice(0, 2000) || DEFAULT_ATTR;
  res.redirect('/csti/attr');
});

module.exports = { vuln, router };
