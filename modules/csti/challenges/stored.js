'use strict';
// Stored CSTI: member display names are saved verbatim in the database and
// every view runs them through the site's client-side template engine, so a
// template saved as a name evaluates in every visitor's browser.
const express = require('express');
const crypto = require('crypto');
const { tokenScriptParts } = require('../../../lib/jstoken');
const { getDb } = require('../../../lib/db');
const { page, esc, claimBox, errorPage, flagBox } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const vm = require('vm');

const router = express.Router();

// The site's client-side template engine, served to the lab page. It is the
// vulnerability: expressions become live JavaScript. (Local copy of the
// module-level constant from the module router; the finisher keeps the
// canonical copy in shared.js alongside the beacon route.)
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

// Per-session token for this lab, rendered into the page as CSTI_NONCE. The
// beacon must echo it back, so only a template that really evaluated in the
// page can claim the flag. (Local copy of the module-level helper; the
// consuming side lives in the shared /csti/beacon route kept by the finisher.
// Both sides use the same req.session.cstiNonce key.)
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

// GET /csti/stored -> member directory. Every stored display name is
// evaluated as a template in the visitor's browser when the list renders.
router.get('/stored', (req, res) => {
  const db = getDb();
  const names = db.prepare('SELECT name FROM csti_profiles ORDER BY id').all().map((r) => r.name);
  res.send(page('Member directory', `
    <h2>Tinkerer's Guild</h2>
    <p class="dim">A makerspace member directory. Set your display name and it shows up for every visitor.</p>
    <div class="card">
      <div class="card-top"><b>Your profile</b></div>
      <form method="POST" action="/csti/stored/profile">
        <div class="clay-field">
          <label for="name">Display name</label>
          <input class="clay-input" type="text" id="name" name="name" placeholder="e.g. Sam the solderer" maxlength="200" size="40" required />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Save profile</button>
      </form>
    </div>
    <h3>Members</h3>
    <div id="profiles"></div>
    <script>
      ${RENDER_JS}
      // Page-bound token: the beacon must echo it back.
      ${cstiNonceScript(req, 'stored')}
      var NAMES = ${JSON.stringify(names)};
      var box = document.getElementById('profiles');
      var hit = false;
      NAMES.forEach(function (n) {
        // VULN: every stored display name is evaluated as a template on view.
        var html = cstiRender(n);
        var div = document.createElement('div');
        div.className = 'card comment';
        div.innerHTML = '<b>Member:</b> ' + html;
        box.appendChild(div);
        if (html.indexOf('49') !== -1) hit = true;
      });
      if (hit) {
        fetch('/csti/beacon?v=stored&d=' + encodeURIComponent('49') + '&n=' + encodeURIComponent(CSTI_NONCE));
      }
    </script>
    <div class="card">
      <div class="card-top"><b>Goal</b></div>
      <p>Store a display name that renders as <b>49</b> for everyone who views this page. The directory runs every name through the site template engine.</p>
    </div>
    ${claimBox({
      vulnId: 'stored',
      payload: 'Set your display name to ' + esc('{{7*7}}') + ' and reload this page.',
      statusUrl: '/csti/claim-status?v=stored',
      beaconInfo: 'The page token is computed at runtime by the page script as <code>CSTI_NONCE</code>; it never appears in the page source. This flag is victim-bound: after planting your name, load <a href="/csti/stored/victim-visit">/csti/stored/victim-visit</a> so a simulated victim views the directory and the stored template evaluates there. A beacon fired with your own session token is rejected.',
    })}
    <p class="dim"><a href="/csti#stored">Challenge card</a> · <a href="/csti">CSTI module</a></p>
  `));
});

// GET /csti/stored/victim-visit -> simulated victim. A fresh victim session
// loads the member directory and every stored name is evaluated as a
// template there, with the page token set to a per-visit victim secret. The
// flag goes to YOUR session only when the beacon fired inside that victim
// execution carries the victim secret, proving a stored template really
// evaluated in someone else's page load.
router.get('/stored/victim-visit', (req, res) => {
  const secret = crypto.randomBytes(16).toString('hex');
  const db = getDb();
  const names = db.prepare('SELECT name FROM csti_profiles ORDER BY id').all().map((r) => r.name);
  // Hardened sandbox (lib/fix-worker.js pattern): fresh vm context with zero
  // host-realm values. Every helper the guest sees (fetch, document,
  // console) is built INSIDE the guest context from guest-realm intrinsics
  // via bootstrap. encodeURIComponent is the guest realm own global, never
  // the host function. Only primitives (strings) cross the boundary on the
  // way out, so template payloads can never reach the host Function
  // constructor via fetch.constructor or encodeURIComponent.constructor.
  const context = vm.createContext(Object.create(null));
  const bootstrap = new vm.Script(
    'var __beacons = [];\n' +
    'var console = { log: function () {}, warn: function () {}, error: function () {}, info: function () {}, debug: function () {} };\n' +
    'function fetch(u) { __beacons.push(String(u)); }\n' +
    'var document = {\n' +
    '  getElementById: function () { return { appendChild: function () {} }; },\n' +
    '  createElement: function () { return { className: \'\', innerHTML: \'\' }; }\n' +
    '};\n',
    { filename: 'csti-victim-bootstrap.js' }
  );
  bootstrap.runInContext(context, { timeout: 2000 });
  const driver = RENDER_JS + '\n'
    + 'var CSTI_NONCE = ' + JSON.stringify(secret) + ';\n'
    + 'var NAMES = ' + JSON.stringify(names) + ';\n'
    + 'var box = document.getElementById(\'profiles\');\n'
    + 'var hit = false;\n'
    + 'NAMES.forEach(function (n) { var html = cstiRender(n); var div = document.createElement(\'div\'); div.className = \'card comment\'; div.innerHTML = \'<b>Member:</b> \' + html; box.appendChild(div); if (html.indexOf(\'49\') !== -1) hit = true; });\n'
    + 'if (hit) { fetch(\'/csti/beacon?v=stored&d=\' + encodeURIComponent(\'49\') + \'&n=\' + encodeURIComponent(CSTI_NONCE)); }';
  try {
    new vm.Script(driver, { filename: 'csti-victim-visit.js' }).runInContext(context, { timeout: 2000 });
  } catch (e) { /* a real victim browser swallows template errors too */ }
  let beaconJoined = '';
  try {
    beaconJoined = new vm.Script('__beacons.join("\\n")', { filename: 'csti-victim-extract.js' }).runInContext(context, { timeout: 2000 });
  } catch (e) { beaconJoined = ''; }
  const beacons = (typeof beaconJoined === 'string' && beaconJoined) ? String(beaconJoined).split('\n') : [];
  const won = beacons.some((u) => {
    try {
      const url = new URL(u, 'http://lab.invalid/');
      return url.pathname === '/csti/beacon'
        && (url.searchParams.get('v') || '') === 'stored'
        && (url.searchParams.get('n') || '') === secret
        && (url.searchParams.get('d') || '') === '49';
    } catch (e) { return false; }
  });
  let flags = '';
  if (won) flags += flagBox(award(req, 'csti', 'stored'));
  res.send(page('Victim visit', `
    <h2>Simulated victim visit</h2>
    <p>A fresh victim just loaded the member directory in their own session. ${beacons.length} beacon call(s) fired inside that page load.</p>
    ${flags || '<p class="dim">No beacon carrying this visit secret arrived, so no flag was awarded. Set your display name to a template that renders as 49 (such as {{7*7}}), then come back here.</p>'}
    <p><a href="/csti/stored">Back to the member directory</a></p>
  `));
});

// POST /csti/stored/profile -> save a display name verbatim, then it is
// evaluated as a template on every future view of the directory.
router.post('/stored/profile', (req, res) => {
  const name = String(req.body.name || '').slice(0, 200).trim();
  if (!name) {
    return res.status(400).send(page('Member directory', errorPage(400, 'A display name is required',
      '<p>A display name is required.</p><p><a href="/csti/stored">Back</a></p>')));
  }
  getDb().prepare('INSERT INTO csti_profiles (name) VALUES (?)').run(name);
  res.redirect('/csti/stored');
});

module.exports = {
  vuln: {
    id: 'stored',
    name: 'Stored Template in Profile Name',
    difficulty: 'Easy',
    hint: 'Display names are stored and every view evaluates them as templates. Your payload persists and fires for every visitor.',
    hints: [
      'Two requests, not one: first plant the payload with a form POST, then it fires when the member list is viewed. Repeater is the natural tool.',
      'Route your browser through Burp Proxy, submit the profile form, then reload the directory. Watch the Proxy history: the page fires a GET to /csti/beacon by itself once your stored template evaluates.',
      'Then load /csti/stored/victim-visit in the browser: a simulated victim views the directory with a fresh victim token, and your stored template evaluating to 49 inside that visit is what claims the flag. Forging the beacon with a token from your own page view earns nothing.',
    ],
    tools: 'BZ, B',
    how: 'Plant a template expression (such as {{7*7}}) as your display name through the profile form, then reload the member list: the stored template evaluates on every view and the page beacons proof.',
    link: '/csti#stored',
    start: 'In Burp: browse /csti/stored through Proxy, submit the profile form with a template as your display name, then reload the directory and watch /csti/beacon fire in the Proxy history.',
  },
  router,
};
