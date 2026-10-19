'use strict';
// Authorization Code Replay: authorization codes are meant to be single-use,
// but the IdP only counts exchanges and never invalidates the code, so the
// same code can be exchanged for fresh tokens again and again.
// Note: the vulnerable exchange lives in the shared token endpoint
// (doTokenExchange in the module shared code), not in this file; the award
// condition is rec.uses >= 1 on a direct exchange of an owned code.
const express = require('express');
const { page, esc, hintLadder, payloadBlock, appShell } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'code-replay',
  name: 'Authorization Code Replay',
  difficulty: 'Medium',
  hint: 'Codes are supposed to be single-use. This IdP counts uses but never invalidates the code. Exchange the same code twice.',
  hints: ["Are authorization codes single-use? Try using one twice.", "They're not. Exchange the same code twice and compare tokens.", "Exchange the code, then exchange it again. Two valid tokens = flag."],
  tools: 'C',
  how: 'POST the same code to /oauth/idp/token two times and compare the two valid tokens.',
  link: '/oauth#code-replay',
  start: 'curl -s -b jar -c jar http://localhost:3000/oauth/login/bob',
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
      ${payloadBlock('Token exchange (run twice)', "curl -s -b jar -X POST http://localhost:3000/oauth/idp/token \\\n  -d 'client_id=pentrix-spa&code=PASTE_YOUR_CODE_HERE'")}
      <p class="note">The exchange identifies you by the IdP session cookie: create the jar first with <code>curl -s -b jar -c jar http://localhost:3000/oauth/login/bob</code>, then send both exchanges with <code>-b jar</code>.</p>
      <p>Compare the two responses: both return valid, different access tokens. The
      flag is awarded on the second successful exchange of the same code and arrives
      inside the token response JSON, in the <code>flag</code> field.</p>
    `, { nav: ['Authorize', 'Token', 'Log'], crumb: 'IdP developer console' })}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = { vuln, router };
