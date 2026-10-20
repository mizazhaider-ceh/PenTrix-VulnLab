'use strict';
// Login CSRF (Missing state Parameter): GET /oauth/no-state is the lab page,
// and GET /oauth/no-state/attacker mints a code for the attacker's own IdP
// account. The client callback (module-level shared route
// /oauth/client/callback) exchanges whatever code it is given without ever
// validating a state parameter, so a victim who opens the malicious link ends
// up logged in to the client as the attacker. The flag is awarded by that
// shared callback, not here.
// VULN: the client callback never validates a state parameter, so any code
// it is handed is exchanged and bound to the victim's session (login CSRF).
const express = require('express');
const { page, esc, brief, hintLadder, payloadBlock } = require('../../../lib/page');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'no-state',
  name: 'Login CSRF (Missing state Parameter)',
  difficulty: 'Medium',
  hint: 'The client callback exchanges any code it is given and never validates state. Mint a code for YOUR account, then get the victim to visit the callback with it.',
  hints: ["There's no state parameter. What attack does that enable?", "Login CSRF: the attacker starts the flow, the victim finishes it logged in as the attacker.", "Shape: a callback URL carrying a code minted for the attacker's account, visited by a session whose IdP user is the victim. Nothing in the callback lets the client ask who started the flow."],
  tools: 'BZ, B',
  est: 'about 10 to 20 minutes',
  how: 'Without a state parameter, the client callback cannot tell a login the user started from one an attacker started for them.',
  link: '/oauth#no-state',
  start: 'Route your browser through Burp Proxy. Log in to the IdP as bob (/oauth/login/bob), open the attacker link generator (/oauth/no-state/attacker), and copy the malicious callback link from the response.',
};

router.get('/no-state', (req, res) => {
  res.send(page('Lab 3: Login CSRF (missing state)',
    brief('Lab 3: Login CSRF (missing state)',
      `The client callback exchanges any <code>code</code> it is given and never checks
      a <code>state</code> parameter. So an attacker can mint a code for <i>their own</i>
      account and trick the victim into visiting the callback with it: the victim ends up
      logged in to the client as the attacker.`) +
    `<div class="clay-card">
      <h3>The scenario</h3>
      <p>One account starts a login flow, a different account's browser finishes
      it. The pieces you need are the IdP logins
      (<a href="/oauth/login/bob">bob</a> as the attacker,
      <a href="/oauth/login/alice">alice</a> as the victim) and the
      <a class="clay-btn clay-btn-primary clay-btn-sm" href="/oauth/no-state/attacker">link generator</a>,
      which mints a callback link for whoever is signed in as the attacker.</p>
      <p class="dim">The flag is awarded when the callback logs the session in as someone other than its own IdP user.</p>
    </div>` +
    hintLadder(vuln) +
    `<p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>`
  ));
});

// Attacker link generator for the login-CSRF lab.
router.get('/no-state/attacker', (req, res) => {
  const me = shared.idpUser(req);
  if (!me) {
    return res.send(page('Login-CSRF link generator',
      `<h2>Login-CSRF link generator</h2>
      <div class="clay-card">
        <p class="note">Log in to the IdP as the attacker first, then come back here:</p>
        <p><a class="clay-btn clay-btn-primary" href="/oauth/login/bob">Log in as bob</a></p>
      </div>
      <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>`
    ));
  }
  // Same call as router.js: the code is minted for the attacker's own account,
  // with no state involved anywhere, and written to the shared in-memory store.
  // It is stamped with this challenge's flow explicitly: the code belongs to
  // the login-CSRF flow, never to the code-replay flow.
  const code = shared.issueCode({
    clientId: 'pentrix-spa', ownerId: me.id,
    redirectUri: shared.TRUSTED_PREFIX + '/callback', scope: 'read',
    flow: 'no-state',
  });
  const evil = '/oauth/client/callback?code=' + code;
  res.send(page('Login-CSRF link generator',
    `<h2>Login-CSRF link generator</h2>
    <div class="clay-card">
      <p>A code for the attacker account <b>${esc(me.username)}</b> was minted
      (no <code>state</code> involved anywhere).</p>
      <p><b>Malicious link to send the victim:</b></p>
      ${payloadBlock('Malicious login link', evil)}
      <p>When the victim (logged in to the IdP as alice) visits it, the client logs
      them in as <b>${esc(me.username)}</b>.</p>
    </div>
    <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>`
  ));
});

module.exports = { vuln, router };
