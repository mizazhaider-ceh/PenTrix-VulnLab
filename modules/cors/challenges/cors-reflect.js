'use strict';
// CORS lab: Reflected Origin with Credentials. GET /api/profile mirrors any
// Origin back with Access-Control-Allow-Credentials: true, so any website the
// victim visits can read alice's profile with the victim's cookies.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, hintLadder, toolsPill, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'cors-reflect',
  name: 'Reflected Origin with Credentials',
  difficulty: 'Medium',
  hint: 'The endpoint echoes any Origin back and adds Access-Control-Allow-Credentials: true. There is no allowlist at all.',
  hints: ["The API reflects any Origin with credentials. In Burp Repeater, request /cors/api/profile with an Origin header and watch the response headers.", "The response comes back with Access-Control-Allow-Origin set to your origin plus Access-Control-Allow-Credentials: true. What does that let an attacker's page do in a victim's browser?", "Stay in Repeater: the response headers are the whole proof. An origin echoed back together with credentials allowed is exactly what would let any attacker page read this data in a victim browser. You do not need to build an attacker page or route anything through the proxy browser for this one."],
  tools: 'BZ, B',
  est: 'about 10 minutes',
  how: 'This API answers cross-origin reads far too politely. Send it a foreign Origin in Repeater and read what it promises that origin in return.',
  link: '/cors#cors-reflect',
  start: 'Burp: browse to /cors/api/profile through the Proxy, send the request to Repeater, add an Origin header, and send it.',
};

// VULN: any Origin is reflected with credentials allowed. No allowlist at all.
router.get('/api/profile', (req, res) => {
  const origin = req.headers.origin;
  if (origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  const alice = getDb()
    .prepare('SELECT username, email, secret FROM users WHERE username = ?')
    .get('alice');
  res.json({ user: alice });
});

// Challenge page: reads like a developer portal for the profile API of a
// small customer app. The flaw is demonstrated through /cors/prove, never
// named on the page itself.
router.get('/reflect', (req, res) => {
  res.send(page('Reflected Origin with Credentials', `
    <h1>Profile API</h1>
    ${brief('Developer portal', `
      Northwind Accounts serves customer data through a small JSON API. The
      customer portal frontend fetches <code>/cors/api/profile</code> to render
      the signed-in user's details. Your goal: show that another website can
      read this response cross-origin in the victim's browser.
    `)}
    <div class="vuln-card">
      <h3>Live endpoint</h3>
      <p><a href="/cors/api/profile"><code>/cors/api/profile</code></a></p>
      ${payloadBlock('Burp Repeater', 'GET /cors/api/profile HTTP/1.1\nHost: <your-lab-address>\nOrigin: https://evil.com\n\n')}
    </div>
    <p>The endpoint reflects <b>any</b> Origin and adds
    <code>Access-Control-Allow-Credentials: true</code>. Prove the combination
    with the suggested origin.</p>
    <p>
      <a class="clay-btn clay-btn-primary" href="/cors/prove?vuln=cors-reflect&amp;origin=https%3A%2F%2Fevil.com">Prove it with the suggested Origin</a>
      <a class="clay-btn clay-btn-secondary" href="/cors/prove?vuln=cors-reflect">Choose your own Origin</a>
    </p>
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}
    <p><i>Attack:</i> ${esc(vuln.how)}</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/cors">Back to the module</a></p>
  `));
});

module.exports = { vuln, router };
