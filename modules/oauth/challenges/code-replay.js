'use strict';
// Authorization Code Replay: authorization codes are meant to be single-use,
// but the IdP only counts exchanges and never invalidates the code, so the
// same code can be exchanged for fresh tokens again and again.
// Note: the vulnerable exchange lives in the shared token endpoint
// (doTokenExchange in the module shared code), not in this file; the award
// condition is rec.uses >= 1 on a direct exchange of an owned code that was
// issued inside this challenge's own flow (rec.flow === 'code-replay', a
// plain pentrix-spa read code for the trusted callback, not PKCE-bound).
// Codes issued by other challenges' flows never earn this flag.
// VULN: the IdP never invalidates an authorization code after use, so the
// same code can be exchanged for fresh tokens again and again.
const express = require('express');
const { page, esc, hintLadder, payloadBlock, appShell } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'code-replay',
  name: 'Authorization Code Replay',
  difficulty: 'Medium',
  hint: 'Codes are supposed to be single-use. This IdP counts uses but never invalidates the code. Send the token exchange in Repeater, then send it again.',
  hints: ["Are authorization codes single-use? Capture the exchange in Repeater and watch what the IdP does on the second send.", "Resend the identical exchange request in Repeater and compare the two token responses.", "The IdP counts uses but never marks the code as spent, so a replayed exchange mints another fresh token. Two sends, two live tokens, the flag rides in the second response."],
  tools: 'BZ, C',
  how: 'Exchange the same authorization code at /oauth/idp/token twice and compare the two valid tokens. In Repeater, send the exchange, then resend the identical request: the second exchange returns a fresh token with the flag.',
  link: '/oauth#code-replay',
  start: 'Proxy /oauth/login/bob through Burp, authorize pentrix-spa (response_type=code), then send the token exchange to Repeater and resend it.',
};

// Same authorization URL the module index uses for the SPA code flow.
const AUTHZ_URL = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' +
  encodeURIComponent('http://app.pentrix.lab/callback') +
  '&response_type=code&scope=read';

router.get('/code-replay', (req, res) => {
  res.send(page('Lab 7: Authorization code replay', `
    ${appShell('PenTrix Identity', `
      <h2>Lab 7: Authorization code replay</h2>
      <p>Authorization codes are supposed to be single-use: the moment a code is
      exchanged for a token, it dies. This identity provider counts how many times
      a code has been used, but it never invalidates the code. What does that make
      possible?</p>
      <div class="card">
        <div class="card-top"><b>Steps</b></div>
        <ol>
          <li>Log in to the IdP as <a href="/oauth/login/bob">bob</a>.</li>
          <li><a href="${esc(AUTHZ_URL)}">Authorize pentrix-spa</a>
          (response_type=code) and approve the request. The approval page shows the
          redirect target with your code in it; copy the code.</li>
          <li>Exchange the code at the token endpoint, twice. Run the same request
          two times in a row:</li>
        </ol>
      </div>
      ${payloadBlock('Burp Repeater (send it twice)', `POST /oauth/idp/token HTTP/1.1
Host: <your-lab-address>
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<PASTE_YOUR_SESSION_COOKIE>

client_id=pentrix-spa&code=<CODE>`)}
      <p class="note">The exchange identifies you by the IdP session cookie: log in through the proxied browser (or copy the session cookie from Proxy into Repeater's Cookie header), then send the exchange and resend the identical request.</p>
      <p>Compare the two responses: both return valid, different access tokens. The
      flag is awarded on the second successful exchange of the same code and arrives
      inside the token response JSON, in the <code>flag</code> field.</p>
    `, { nav: ['Authorize', 'Token', 'Log'], crumb: 'IdP developer console' })}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = { vuln, router };
