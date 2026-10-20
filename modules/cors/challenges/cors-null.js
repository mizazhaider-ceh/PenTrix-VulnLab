'use strict';
// CORS lab: Null Origin Trusted. GET /api/settings trusts Origin "null" with
// credentials, so any null-origin context (sandboxed iframe, file:// page,
// redirect chain) can read alice's account settings.
const express = require('express');
const { page, esc, brief, hintLadder, toolsPill, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'cors-null',
  name: 'Null Origin Trusted',
  difficulty: 'Medium',
  hint: 'Only one origin value is trusted here, and it is the one sandboxed iframes and file:// pages send.',
  hints: ["In Repeater, add an Origin header to GET /cors/api/settings and send a few values. Watch the response headers: only one literal value earns Access-Control-Allow-Origin plus Access-Control-Allow-Credentials.", "The trusted value is one that sandboxed iframes (no allow-same-origin) and file:// pages send, and that no ordinary website origin should ever be able to claim.", "Fastest correct tool: Repeater for everything. Send your candidate value against /cors/api/settings, confirm the response trusts it with credentials, then prove the same combination through /cors/prove. It is a plain GET, no proxy browser needed."],
  tools: 'BZ, B',
  est: 'about 10 minutes',
  how: 'One origin value earns this API\'s trust, and it is a value no real website should be able to claim. Find the value the API cannot resist.',
  link: '/cors#cors-null',
  start: 'Repeater: send GET /cors/api/settings with an Origin header and read the response headers. Try candidate values until one is trusted.',
};

// VULN: Origin "null" (sandboxed iframes, file:// pages, redirects) is trusted
// with credentials, so any null-origin context can read this data.
router.get('/api/settings', (req, res) => {
  const origin = req.headers.origin;
  if (origin === 'null') {
    res.set('Access-Control-Allow-Origin', 'null');
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ theme: 'dark', twoFactor: true, recoveryEmail: 'alice@pentrix.lab' });
});

// Challenge page: reads like a developer portal for the settings API of a
// small customer app. The flaw is demonstrated through /cors/prove, never
// named on the page itself.
router.get('/null-origin', (req, res) => {
  res.send(page('Null Origin Trusted', `
    <h1>Settings API</h1>
    ${brief('Developer portal', `
      Northwind Accounts keeps account preferences behind a small JSON API. The
      account page fetches <code>/cors/api/settings</code> to show the signed-in
      user's theme, two-factor status, and recovery email. Your goal: show that
      another website can read this response cross-origin in the victim's
      browser.
    `)}
    <div class="vuln-card">
      <h3>Live endpoint</h3>
      <p><a href="/cors/api/settings"><code>/cors/api/settings</code></a></p>
      ${payloadBlock('Burp Repeater', 'GET /cors/api/settings HTTP/1.1\nHost: <your-lab-address>\nOrigin: null\n\n')}
    </div>
    <p>Only <code>Origin: null</code> is trusted here (with credentials). Prove
    it with exactly that origin.</p>
    <p>
      <a class="clay-btn clay-btn-primary" href="/cors/prove?vuln=cors-null&amp;origin=null">Prove it with the suggested Origin</a>
      <a class="clay-btn clay-btn-secondary" href="/cors/prove?vuln=cors-null">Choose your own Origin</a>
    </p>
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}
    <p><i>Attack:</i> ${esc(vuln.how)}</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/cors">Back to the module</a></p>
  `));
});

module.exports = { vuln, router };
