'use strict';
// DOM-based XSS: location.hash flows into innerHTML in the browser.
const express = require('express');
const { page, esc, claimBox, fixCta } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');

const router = express.Router();

router.get('/dom', (req, res) => {
  const demoUrl = '/xss/dom#' + encodeURIComponent('Welcome back, Sam');
  res.send(page('Welcome · Northwind Community', `
    <h2>Northwind Community</h2>
    ${xssNonceTag(req, 'dom')}
    ${siteFrame('Northwind Community', ['Home', 'Events', 'Members'], `
      <p>Personal greetings are built in the browser from the part of the URL after <code>#</code>, so the server never sees them.</p>
      <div id="out" class="note"></div>
      <script>
        // VULN: location.hash flows straight into innerHTML with no sanitization.
        var raw = location.hash.slice(1);
        try { raw = decodeURIComponent(raw); } catch (e) { /* keep the raw fragment */ }
        document.getElementById('out').innerHTML = raw;
      </script>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(demoUrl)}">Preview a greeting</a></p>`)}
    ${claimBox({ vulnId: 'dom', payload: esc(`<img src=x onerror="${beacon('dom')}">`), statusUrl: '/xss/claim-status?v=dom', beaconInfo: 'For DOM XSS, put the payload in the URL fragment (after #). The fragment is URL-decoded before it is used.' })}
    ${fixCta('xss', 'dom')}
    ${backLinks('dom')}
  `));
});

module.exports = {
  vuln: {
    id: 'dom',
    name: 'DOM-based XSS',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'The server never sees the fragment. JavaScript on the page copies location.hash into innerHTML. Craft the URL.',
    hints: [
      'The server never sees the URL fragment (everything after #). So where does the vulnerability live? Read the inline script in the page source of your proxied browser.',
      'In Burp Proxy HTTP history, watch what the browser does when the page loads. The sink is client-side only; the server just serves the static page.',
      'A <script> tag dropped in through innerHTML never runs. In Burp Proxy history, find the beacon the payload must fire on page load, then build a fragment with an element whose handler fires automatically and paste the full URL into the proxied browser address bar.',
    ],
    tools: 'BZ, B, DT',
    how: 'Build a /xss/dom#... URL whose fragment carries an event-handler payload that fires the /xss/collect beacon on page load, then open it in your proxied browser and watch the beacon land in Burp Proxy history.',
    link: '/xss/dom',
    start: 'Start Burp Proxy, browse to /xss/dom in your proxied browser, and view the page source to find the inline script that reads location.hash.',
  },
  router,
};
