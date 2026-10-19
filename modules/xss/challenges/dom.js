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
    hint: 'The server never sees the fragment. JavaScript on the page copies location.hash into innerHTML. Craft the URL.',
    hints: [
      'The server never sees the URL fragment (everything after #). So where does the vulnerability live?',
      'JavaScript on the page copies location.hash into innerHTML. The sink is client-side only; the server just serves the static page.',
      'Build a URL of the form /xss/dom#<tag with an event handler> where the handler calls /xss/collect (parameters c, v=dom and n=window.__px), then open it. A <script> tag inserted through innerHTML does not run, so use an element with an event handler.',
    ],
    tools: 'B, DT',
    how: 'Build a /xss/dom#... link whose fragment contains the exfiltration payload, then open it.',
    link: '/xss/dom',
    start: 'curl -s http://localhost:3000/xss/dom | grep -n "<script>"',
  },
  router,
};
