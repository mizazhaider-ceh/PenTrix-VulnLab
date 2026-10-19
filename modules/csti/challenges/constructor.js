'use strict';
// CSTI constructor breakout: the client-side template engine exposes
// `constructor` (which is Object) to every {{ expression }}, and
// Object.constructor is Function. From there the browser can compile and run
// any string as code, so the flag is beacons manually with the page-bound
// token. Behavior identical to modules/csti/router.js: same engine, same
// session storage, same routes, same flag condition.
const express = require('express');
const crypto = require('crypto');
const { page, esc, appShell } = require('../../../lib/page');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'constructor',
  name: 'Constructor Breakout to Code Execution',
  difficulty: 'Medium',
  hint: 'Expressions can see constructor (which is Object), and Object.constructor is Function. Compile a string that beacons the flag.',
  hints: [
    "You need code execution. What's the path from a string to a function?",
    "constructor.constructor is the Function constructor. Build it from a string.",
    "Reach the Function constructor through the exposed constructor reference, then compile a string that fetches the beacon endpoint and echoes the page-bound token. The code inside the compiled string is the one part you must write yourself.",
  ],
  tools: 'B, DT',
  how: 'Submit {{constructor.constructor("fetch(...)")()}} with a fetch to /csti/beacon?v=constructor that echoes the page token CSTI_NONCE.',
  link: '/csti#constructor',
  start: 'curl -s -c jar http://localhost:3000/csti/constructor\n# Browser lab: open http://localhost:3000/csti/constructor, read the page-bound token, then work the template.',
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

const DEFAULT_CTOR = '2 + 2 = {{2+2}}';

// GET /csti/constructor -> math card lab (Lab 3 in modules/csti/router.js).
router.get('/constructor', (req, res) => {
  const tpl = req.session.csti_ctor || DEFAULT_CTOR;
  res.send(page('Constructor breakout', `
    ${appShell('Mathly', `
      <h2>Math card (constructor breakout)</h2>
      <p>Design your own math card. Your template is saved on the server and the
      browser's template engine renders the preview below.</p>
      <form method="POST" action="/csti/constructor">
        <div class="clay-field">
          <label for="tpl">Card template</label>
          <textarea class="clay-input" id="tpl" name="tpl" rows="3" maxlength="2000">${esc(tpl)}</textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Save template</button>
      </form>
      <h3>Preview</h3>
      <div id="out" class="card"></div>
      <script>
        ${RENDER_JS}
        // Page-bound token: your manual beacon must echo it back.
        var CSTI_NONCE = ${JSON.stringify(cstiNonce(req, 'constructor'))};
        var TPL = ${JSON.stringify(tpl)};
        document.getElementById('out').innerHTML = cstiRender(TPL);
      </script>
      <p class="note">Goal: execute JavaScript through the template. The engine exposes
      <code>constructor</code> (which is <code>Object</code>) to every expression, and
      <code>Object.constructor</code> is <code>Function</code>. From there you can compile
      and run any string as code, then beacon the flag yourself - your beacon must echo the
      page-bound token, e.g.
      <code>{{constructor.constructor("fetch('/csti/beacon?v=constructor&amp;d='+document.cookie+'&amp;n='+CSTI_NONCE)")()}}</code>.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csti">Back to the CSTI module</a></p>
    `, { crumb: 'Dashboard · Math cards', mark: '&#8721;' })}
  `));
});

// POST /csti/constructor -> save the template (max 2000 chars) and re-render.
router.post('/constructor', (req, res) => {
  req.session.csti_ctor = String(req.body.tpl || '').slice(0, 2000) || DEFAULT_CTOR;
  res.redirect('/csti/constructor');
});

module.exports = { vuln, router };
