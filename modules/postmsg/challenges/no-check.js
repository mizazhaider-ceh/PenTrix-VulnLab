'use strict';
// Lab 1: chat widget listens for postMessage, never checks event.origin, and
// renders the message as HTML. The victim page's own handler fires the flag
// beacon (a shared module-level route) with a page-bound one-time token.
const express = require('express');
const { page } = require('../../../lib/page');
const { pmNonce } = require('../shared');

const router = express.Router();

// "How to claim this flag" card with the live claim-status widget. The steps
// describe the postMessage lab flow (the victim page fires the beacon itself);
// the widget markup matches the global poller in public/app.js.
function claimCard(vulnId, steps) {
  const id = String(vulnId).replace(/[^a-z0-9-]/gi, '');
  const items = steps.map((s) => `<li>${s}</li>`).join('');
  return `<div class="card claim-box">
    <div class="card-top"><b>How to claim this flag</b></div>
    <ol>${items}</ol>
    <p id="claim-status-${id}" class="status status-missing" role="status" data-status-url="/postmsg/claim-status?v=${id}"><span class="dot" aria-hidden="true"></span><span class="claim-text">Checking claim status...</span></p>
  </div>`;
}

// GET /postmsg/no-check -> victim chat widget (no origin check, HTML sink).
router.get('/no-check', (req, res) => {
  res.send(page('Chat widget (no origin check)', `
    <h2>Chat widget</h2>
    <p>Messages posted to this page appear below.</p>
    <div class="card">
      <div class="card-top"><b>Inbox</b></div>
      <div id="inbox" style="border:1px dashed #888; padding:1em; min-height:3em;">(no message yet)</div>
    </div>
    <script>
      // Page-bound token: only a handler running in this loaded page can know it.
      var PM_NONCE = ${JSON.stringify(pmNonce(req, 'no-check'))};
      window.addEventListener('message', function (e) {
        // VULN: no origin check at all - any website can drive this handler,
        // and the message is rendered as HTML.
        document.getElementById('inbox').innerHTML = '<p>Message: ' + e.data + '</p>';
        fetch('/postmsg/beacon?v=no-check&d=' + encodeURIComponent('no-check:' + String(e.data).slice(0, 200)) + '&n=' + encodeURIComponent(PM_NONCE));
      });
    </script>
    <p class="note">Attacker page: <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/postmsg/no-check/attacker">open it</a> and fire the payload.</p>
  `));
});

// GET /postmsg/no-check/attacker -> attacker page driving the victim iframe.
router.get('/no-check/attacker', (req, res) => {
  res.send(page('Attacker: no origin check', `
    <h2>Attacker page (lab 1)</h2>
    <p>This page embeds the victim widget in an iframe, then posts a message to it
    from a <i>different</i> page. The victim never checks <code>event.origin</code>.</p>
    <div class="card">
      <div class="card-top"><b>Victim widget (embedded)</b></div>
      <iframe id="v" src="/postmsg/no-check" width="100%" height="220" style="border:0; border-radius:1rem;" title="victim widget"></iframe>
    </div>
    <p><button id="fire" class="clay-btn clay-btn-primary" type="button">Fire payload</button></p>
    <p id="log" class="dim" role="status"></p>
    <script>
      document.getElementById('fire').onclick = function () {
        var payload = '<img src=x onerror="document.getElementById(\\'log\\').textContent=\\'XSS via postMessage\\'">';
        document.getElementById('v').contentWindow.postMessage(payload, '*');
        document.getElementById('log').textContent = 'Payload posted. Check the widget above and your flag.';
      };
    </script>
    ${claimCard('no-check', [
      'Click <b>Fire payload</b> above. It posts a message into the victim iframe.',
      'The victim handler runs with no origin check, renders the message as HTML, and fires the beacon itself with its page-bound token.',
      'The widget below polls for confirmation; once it flips, the flag is on your scoreboard.',
    ])}
  `));
});

module.exports = {
  vuln: {
    id: 'no-check',
    name: 'No Origin Check on Message Handler',
    difficulty: 'Medium',
    hint: 'The widget renders every message it receives as HTML and never looks at event.origin. Any page can talk to it.',
    hints: [
      'Route your browser through Burp Proxy and open the attacker page. In Proxy HTTP history, find the victim iframe request and read its inline message listener.',
      'The victim renders every message as HTML and never checks event.origin. So any page, including this attacker page, can drive it.',
      'Click Fire payload on the attacker page, then look in Burp Proxy history for the /postmsg/beacon request the victim handler fires. That beacon carries the page token and claims your flag.',
    ],
    tools: 'BZ, B, DT',
    how: 'Open the attacker page in your proxied browser and post an HTML payload into the victim iframe; the victim handler fires the claim beacon itself, which you can watch in Burp Proxy history.',
    link: '/postmsg#no-check',
    start: 'Start Burp Proxy, browse to /postmsg/no-check/attacker in your proxied browser, and watch the victim iframe load in Proxy history.',
  },
  router,
};
