'use strict';
// Lab 4: naive substring check on the origin. The partner widget trusts any
// origin containing 'pentrix.lab', so an attacker domain such as
// pentrix.lab.evil.com passes the check. ?simulateOrigin= lets the lab test
// an attacker origin without minting new DNS names. The victim page's own
// message handler fires the flag beacon with its page-bound token.
// The award itself lives in the module-level /postmsg/beacon route.
const express = require('express');
const { page, esc, appShell, payloadBlock } = require('../../../lib/page');
const { pmNonce } = require('../shared');

const router = express.Router();

// GET /substring -> the victim page: a partner widget that renders messages
// from origins containing 'pentrix.lab'.
router.get('/substring', (req, res) => {
  const sim = req.query.simulateOrigin || '';
  res.send(page('Partner widget · PartnerHub', `
    ${appShell('PartnerHub', `
      <h2>Partner widget</h2>
      ${sim ? `<div class="brief"><p><b>LAB SIMULATION:</b> this page is testing the origin
        <code>${esc(sim)}</code> instead of the real <code>event.origin</code>. A local lab cannot
        mint new DNS origins, so the attacker origin is simulated; the
        <code>includes()</code> check itself is the real code under test.</p></div>` : ''}
      <div class="card" id="out"><p class="dim">(no message yet)</p></div>
      <script>
        var SIMULATED_ORIGIN = ${JSON.stringify(sim)};
        // Page-bound token: only a handler running in this loaded page can know it.
        var PM_NONCE = ${JSON.stringify(pmNonce(req, 'substring'))};
        window.addEventListener('message', function (e) {
          var originToTest = SIMULATED_ORIGIN || e.origin;
          if (originToTest.includes('pentrix.lab')) {
            document.getElementById('out').innerHTML = String(e.data);
            fetch('/postmsg/beacon?v=substring&d=' + encodeURIComponent('substring:' + String(e.data).slice(0, 200)) + '&n=' + encodeURIComponent(PM_NONCE));
          } else {
            document.getElementById('out').textContent = 'Blocked origin: ' + e.origin;
          }
        });
      </script>
      <p class="dim">In-lab attacker page: <a href="/postmsg/substring/attacker">open it</a>.</p>
    `, { nav: ['Partners', 'Docs', 'Support'], crumb: 'Partner widget' })}
  `));
});

// GET /substring/attacker -> the in-lab attacker page: loads the victim with
// the attacker origin simulated, then posts the payload.
router.get('/substring/attacker', (req, res) => {
  const evil = 'https://pentrix.lab.evil.com';
  res.send(page('Attacker page · PartnerHub', `
    <div class="clay-card">
      <div class="card-top"><b>Attacker page</b><span class="clay-pill">lab 4</span></div>
      <p>The victim trusts any origin <i>containing</i> <code>pentrix.lab</code>.
      In production the attacker hosts this page at <code>${esc(evil)}</code>:</p>
      ${payloadBlock('Why the check passes', `'${evil}'.includes('pentrix.lab')  // true - check passes\n'https://pentrix.lab'.includes('pentrix.lab')      // true - legitimate partner\n'https://evil.com'.includes('pentrix.lab')         // false - blocked`)}
      <p>The iframe below loads the victim with the attacker origin simulated
      (see the banner on the victim page), then this page posts the payload:</p>
      <div class="card"><iframe id="v" src="/postmsg/substring?simulateOrigin=${encodeURIComponent(evil)}" width="100%" height="300" style="border:0" title="Victim partner widget"></iframe></div>
      <p><button class="clay-btn clay-btn-primary" id="fire" type="button">Fire payload</button></p>
      <p id="log" class="dim" role="status"></p>
      <script>
        document.getElementById('fire').onclick = function () {
          document.getElementById('v').contentWindow.postMessage('<b>pwned via substring check</b>', '*');
          document.getElementById('log').textContent = 'Payload posted. Check the widget above and your flag.';
        };
      </script>
    </div>
    <div class="card">
      <div class="card-top"><b>Claim status</b></div>
      <p id="claim-status-substring" class="status status-missing" role="status" data-status-url="/postmsg/claim-status?v=substring"><span class="dot" aria-hidden="true"></span><span class="claim-text">Checking claim status...</span></p>
    </div>
  `));
});

module.exports = {
  vuln: {
    id: 'substring',
    name: 'Substring Origin Check Bypass',
    difficulty: 'Medium',
    hint: 'The check is origin.includes("pentrix.lab"), not an exact match. Which attacker domain contains that string?',
    hints: [
      "Route your browser through Burp Proxy and open the attacker page. In Proxy history, check the victim iframe URL and see which attacker origin the lab is simulating.",
      "Read the origin check in the victim page source (DevTools on the widget). A substring test means any domain containing the trusted string passes; think like a domain squatter.",
      "Click Fire payload on the attacker page, then find the /postmsg/beacon request in Burp Proxy history to confirm the message was accepted under the simulated attacker origin and the token was claimed.",
    ],
    tools: 'BZ, B, DT',
    how: 'Open the lab attacker page in your proxied browser (it loads the victim under a substring-bypassing attacker origin), post your payload, and confirm the claim beacon in Burp Proxy history.',
    link: '/postmsg#substring',
    start: 'Start Burp Proxy, browse to /postmsg/substring/attacker in your proxied browser, and inspect the simulated-origin banner on the victim iframe.',
  },
  router,
};
