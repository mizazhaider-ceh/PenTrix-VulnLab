'use strict';
// Lab 1: Redirect URI prefix bypass. The IdP validates redirect_uri with a
// naive prefix check against http://app.pentrix.lab, so an attacker URI that
// starts with the prefix but points at a foreign host still gets the code.
// This file owns the challenge page only. The vulnerable check and the flag
// award live in the shared POST /oauth/idp/approve handler (shared.js), kept
// byte for byte identical to the original router: the flag is awarded when
// the IdP issues a code to a redirect URI whose host is not app.pentrix.lab.
const express = require('express');
const { page, esc, briefPanel, payloadBlock } = require('../../../lib/page');

const router = express.Router();

// The fictional client host used by the lab. It never resolves; students read
// issued codes from the approval pages instead of following the redirect.
const TRUSTED = 'http://app.pentrix.lab';
// Attacker URI: passes the prefix check, delivers the code to a foreign host.
// Identical to the original router's TRUSTED_PREFIX + '.evil.com/cb'.
const EVIL = TRUSTED + '.evil.com/cb';

// GET /oauth/redirect-bypass -> the Lab 1 challenge page.
router.get('/redirect-bypass', (req, res) => {
  const href = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' + encodeURIComponent(EVIL) +
    '&response_type=code&scope=read';
  res.send(page('Lab 1: Redirect URI prefix bypass', `
    ${briefPanel('The setup', `
      <p>Every OAuth client registers one <b>redirect_uri</b> with the identity provider.
      After you approve an app, the IdP sends your authorization code back to that URI.
      This IdP validates the URI with a simple prefix check against
      <code>${esc(TRUSTED)}</code>.</p>
      <p>Your job: find a URI that passes the check but delivers the authorization
      code somewhere else entirely.</p>`, 'Lab 1: Redirect URI prefix bypass')}
    <div class="clay-card">
      <h3>Attacker redirect URI</h3>
      ${payloadBlock('redirect_uri', EVIL)}
      <p class="note">It starts with the trusted prefix, so the check lets it through,
      but the host belongs to the attacker.</p>
      <p><a class="clay-btn clay-btn-primary" href="${esc(href)}">Start authorization with this redirect_uri</a></p>
    </div>
    <div class="clay-card">
      <h3>How to run it</h3>
      <ol>
        <li>Log in to the IdP first as
          <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/login/alice">alice</a>
          (the victim).</li>
        <li>Click the button above, then approve the request on the consent screen.</li>
        <li>Watch where the code goes. The flag is awarded when the IdP issues a code
        to a redirect URI whose host is not the registered one.</li>
      </ol>
    </div>
    <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'redirect-bypass',
    name: 'Redirect URI Prefix Bypass',
    difficulty: 'Medium',
    hint: 'The IdP checks redirect_uri with a naive prefix match against http://app.pentrix.lab. What string starts with that but points at an attacker host?',
    hints: ["The redirect_uri check is a naive prefix match. What URIs pass but aren't the real app?", "https://app.pentrix.lab.evil.com starts with the prefix but is attacker-controlled.", "Register the evil URI, authorize, and catch the code."],
    tools: "B, C",
    how: 'Request an authorization code with redirect_uri=http://app.pentrix.lab.evil.com/cb and watch the code go to the attacker host.',
    link: '/oauth#redirect-bypass',
    start: 'curl -s -b jar -c jar http://localhost:3000/oauth/login/alice\ncurl -s -b jar "http://localhost:3000/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=http://app.pentrix.lab.evil.com/cb&response_type=code&scope=read"',
  },
  router,
};
