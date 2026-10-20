'use strict';
// PKCE Downgrade: the authorize endpoint records a code_challenge, but the
// token endpoint never requires the code_verifier, so a challenge-bound code
// can be exchanged with no verifier at all.
// Note: the vulnerable exchange lives in the shared token endpoint
// (doTokenExchange in the module shared code), not in this file; the award
// condition is rec.challenge set with no code_verifier in the request.
// VULN: the token endpoint never requires the PKCE code_verifier, so a
// challenge-bound code can be exchanged by anyone who holds the code alone.
const express = require('express');
const { page, esc, hintLadder, payloadBlock, appShell } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'pkce-skip',
  name: 'PKCE Downgrade',
  difficulty: 'Medium',
  hint: 'The authorize endpoint accepts code_challenge, but the token endpoint never requires the code_verifier. Exchange a bound code without one.',
  hints: ["The flow uses PKCE (code_challenge). Send the token exchange through Burp Repeater so you control every parameter.", "In Repeater, replay the token POST with no code_verifier parameter at all. What does the IdP say back?", "Shape: a code that was issued against a code_challenge, exchanged with the verifier parameter simply absent. If a token comes back, the binding was never checked."],
  tools: 'BZ, B',
  est: 'about 10 to 20 minutes',
  how: 'The token endpoint never asks for the PKCE verifier, so the challenge bound to the code proves nothing at all.',
  link: '/oauth#pkce-skip',
  start: 'Open Burp and route your browser through the proxy. Log in to the IdP as bob, authorize with a code_challenge, then send the token exchange to Repeater.',
};

// Same code_challenge the original lab hands out.
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

const AUTHZ_URL = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' +
  encodeURIComponent('http://app.pentrix.lab/callback') +
  '&response_type=code&scope=read' +
  '&code_challenge=' + CHALLENGE + '&code_challenge_method=S256';

router.get('/pkce-skip', (req, res) => {
  res.send(page('Lab 8: PKCE downgrade', `
    ${appShell('PenTrix Identity', `
      <h2>Lab 8: PKCE downgrade</h2>
      <p>PKCE binds the authorization code to a secret verifier: the client sends a
      <code>code_challenge</code> when the code is issued, and later proves ownership
      by sending the matching <code>code_verifier</code> at the token endpoint. This
      IdP records the challenge on the approval page, but take a close look at what
      the token endpoint actually asks for.</p>
      <div class="card">
        <div class="card-top"><b>Steps</b></div>
        <ol>
          <li>Log in to the IdP as <a href="/oauth/login/bob">bob</a>.</li>
          <li><a href="${esc(AUTHZ_URL)}">Authorize with a code_challenge</a>
          (method S256, challenge <code>${esc(CHALLENGE)}</code>) and approve the
          request. Copy the issued code from the redirect target shown on the
          approval page.</li>
          <li>Exchange the code at the token endpoint, sending
          <b>no</b> <code>code_verifier</code> parameter at all:</li>
        </ol>
      </div>
      ${payloadBlock('Burp Repeater (no verifier at all)', `POST /oauth/idp/token HTTP/1.1
Host: <your-lab-address>
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<PASTE_YOUR_SESSION_COOKIE>

client_id=pentrix-spa&code=<CODE>`)}
      <p>The exchange succeeds even though the verifier is missing, and the
      token response confirms the challenge-bound code was accepted without it.</p>
    `, { nav: ['Authorize', 'Token', 'Log'], crumb: 'IdP developer console' })}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = { vuln, router };
