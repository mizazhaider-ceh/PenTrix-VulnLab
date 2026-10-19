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
  hints: ["The API reflects any Origin with credentials. What does that let an attacker's page do?", "Any website can make authenticated requests and read the responses. The browser allows it because of the reflected ACAO.", "From the attacker page (127.0.0.1 origin), fetch the victim API with credentials. The secret comes back."],
  tools: 'B',
  how: 'Prove it: /cors/prove?vuln=cors-reflect&origin=https://evil.com',
  link: '/cors#cors-reflect',
  start: 'curl -si -H "Origin: https://evil.com" http://localhost:3000/cors/api/profile',
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
      ${payloadBlock('Try it raw', 'curl -si -H "Origin: https://evil.com" http://localhost:3000/cors/api/profile')}
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
