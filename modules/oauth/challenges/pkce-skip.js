'use strict';
// PKCE Downgrade: the authorize endpoint records a code_challenge, but the
// token endpoint never requires the code_verifier, so a challenge-bound code
// can be exchanged with no verifier at all.
// Note: the vulnerable exchange lives in the shared token endpoint
// (doTokenExchange in the module shared code), not in this file; the award
// condition is rec.challenge set with no code_verifier in the request.
const express = require('express');
const { page, esc, hintLadder, payloadBlock, appShell } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'pkce-skip',
  name: 'PKCE Downgrade',
  difficulty: 'Medium',
  hint: 'The authorize endpoint accepts code_challenge, but the token endpoint never requires the code_verifier. Exchange a bound code without one.',
  hints: ["The flow uses PKCE (code_challenge). But is the verifier checked?", "No. Exchange without a verifier.", "POST the token exchange with no code_verifier. It works."],
  tools: 'C',
  how: 'Authorize with a code_challenge, then exchange the code with no code_verifier parameter.',
  link: '/oauth#pkce-skip',
  start: 'curl -s -b jar -c jar http://localhost:3000/oauth/login/bob',
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
      ${payloadBlock('Token exchange without a verifier', "curl -s -X POST http://localhost:3000/oauth/idp/token \\\n  -d 'client_id=pentrix-spa&code=PASTE_YOUR_CODE_HERE'")}
      <p>The exchange succeeds even though the verifier is missing. The flag is
      awarded when a challenge-bound code is exchanged with no verifier, and it
      arrives inside the token response JSON, in the <code>flag</code> field.</p>
    `, { nav: ['Authorize', 'Token', 'Log'], crumb: 'IdP developer console' })}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = { vuln, router };
