'use strict';
// Stored CSTI: member display names are saved verbatim in the database and
// every view runs them through the site's client-side template engine, so a
// template saved as a name evaluates in every visitor's browser.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../../lib/db');
const { page, esc, claimBox, errorPage } = require('../../../lib/page');

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
      var CSTI_NONCE = ${JSON.stringify(cstiNonce(req, 'stored'))};
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
      beaconInfo: 'This lab renders its one-time token as the <code>CSTI_NONCE</code> variable in the page script (not <code>window.__px</code>). The page beacons automatically once a stored name renders as 49.',
    })}
    <p class="dim"><a href="/csti#stored">Challenge card</a> · <a href="/csti">CSTI module</a></p>
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
      'Manual path: in Repeater, copy the session cookie and the CSTI_NONCE token from the directory response, then forge the beacon GET with your evaluated result and the token. The token is single-use per page load, so fetch a fresh one each try.',
    ],
    tools: 'BZ, B',
    how: 'Plant a template expression (such as {{7*7}}) as your display name through the profile form, then reload the member list: the stored template evaluates on every view and the page beacons proof.',
    link: '/csti#stored',
    start: 'In Burp: browse /csti/stored through Proxy, submit the profile form with a template as your display name, then reload the directory and watch /csti/beacon fire in the Proxy history.',
  },
  router,
};
