'use strict';
// Scope tampering: the IdP issues tokens with whatever scope was requested,
// and GET /oauth/idp/admin-data only checks the token scope, not the user's
// role, so a plain user holding an admin-scoped token can read admin data.
const express = require('express');
const { page, esc, hintLadder, toolsPill, difficultyPill, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
// Shared IdP state and helpers live in modules/oauth/shared.js (created by
// the module finisher): the tokens map, bearerToken(req), and userById(id).
const { tokens, bearerToken, userById } = require('../shared');

const router = express.Router();

const TRUSTED_PREFIX = 'http://app.pentrix.lab';

const vuln = {
  id: 'scope-upgrade',
  name: 'Scope Tampering',
  difficulty: 'Easy',
  hint: 'The authorize request takes a scope parameter and the IdP never checks whether your role allows it. Ask for a scope that exceeds your own privileges.',
  hints: ["In Burp's browser, log in as bob and authorize pentrix-spa once normally. In Proxy history, look at the authorize request: the scope is whatever was asked for, and nothing about the request proves your role.", "Send the token exchange request to Repeater and read the token response: the IdP issues the token with the requested scope, no entitlement check anywhere.", "Back in the browser, edit the scope parameter of the authorize request to a privilege level you were never assigned, approve it, exchange the code in Repeater, then present the resulting token to the admin-only endpoint from Repeater."],
  tools: 'BZ, B, C',
  how: 'In Burp, authorize as bob while requesting a scope you were never granted, exchange the code in Repeater, then call the admin-only endpoint with the admin-scoped token.',
  link: '/oauth#scope-upgrade',
  start: 'With Burp Proxy on, log in to the IdP as bob in the browser, authorize pentrix-spa once normally, and send the authorize request from Proxy history to Repeater.',
};

// GET /oauth/idp/admin-data -> admin-only resource. Checks that the token has
// the admin scope, but never checks the user's role, so an admin-scoped token
// held by a plain user is accepted and the flag is awarded.
router.get('/idp/admin-data', (req, res) => {
  const t = tokens.get(req.query.access_token || bearerToken(req));
  if (!t) return res.status(401).json({ error: 'missing or unknown access token' });
  if (!String(t.scope || '').split(' ').includes('admin')) {
    return res.status(403).json({ error: 'admin scope required' });
  }
  const u = userById(t.ownerId);
  const body = {
    admin_secret: 'LAB FICTION: production deploy keys are stored in /opt/pentrix (do not try this at home)',
    granted_to: u.username, scope: t.scope,
  };
  // VULN: the IdP grants whatever scope is requested without checking whether
  // the user is entitled to it.
  if (u.role !== 'admin') body.flag = award(req, 'oauth', 'scope-upgrade');
  res.json(body);
});

// GET /oauth/scope-upgrade -> Lab 5 challenge page.
router.get('/scope-upgrade', (req, res) => {
  const href = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' +
    encodeURIComponent(TRUSTED_PREFIX + '/callback') +
    '&response_type=code&scope=admin';
  res.send(page('Lab 5: Scope tampering', `
    <div class="card app-shell">
      <div class="card-top"><span class="orb" aria-hidden="true">🔐</span>
        <b>PenTrix IdP</b><span class="app-nav"><span class="dim">Authorize</span><span class="dim"> · </span><span class="dim">Token</span><span class="dim"> · </span><span class="dim">Admin data</span></span></div>
      <p class="dim">Labs / Lab 5</p>
      <h2>Scope tampering</h2>
      <div>${difficultyPill(vuln.difficulty)} ${toolsPill(vuln)}</div>
      <p>Every authorization request carries a <code>scope</code> parameter, and the
      access token is issued with whatever scope was asked for.</p>
      <ol>
        <li>Log in to the IdP as
          <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/login/bob">bob</a>
          (a plain user).</li>
        <li><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(href)}">Authorize with scope=admin</a>
          and approve the request, then copy the code from the redirect target.</li>
        <li>Exchange the code at <code>POST /oauth/idp/token</code> with
          <code>client_id=pentrix-spa</code> (a public client, no secret needed).</li>
        <li>Call <code>GET /oauth/idp/admin-data?access_token=...</code>.</li>
      </ol>
      ${payloadBlock('Authorize with scope=admin', 'http://<your-lab-address>' + href)}
      ${payloadBlock('Burp Repeater (token exchange)', `POST /oauth/idp/token HTTP/1.1
Host: <your-lab-address>
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<PASTE_YOUR_SESSION_COOKIE>

client_id=pentrix-spa&code=<CODE>`)}
      ${payloadBlock('Burp Repeater (admin data)', `GET /oauth/idp/admin-data?access_token=<TOKEN> HTTP/1.1
Host: <your-lab-address>
Cookie: connect.sid=<PASTE_YOUR_SESSION_COOKIE>

`)}
      <p class="dim">The flag is awarded when admin-data is read with an admin-scoped token held by a non-admin user.</p>
    </div>
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = { vuln, router };
