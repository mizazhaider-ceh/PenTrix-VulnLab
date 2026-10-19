'use strict';
// Lab 2: Authorization code leaked in the server log. Every issued code is
// written to the world-readable IdP request log, so a stolen code can be
// exchanged for a token by anyone. This file owns the challenge page only.
// The leak (issueCode writes the code to REQ_LOG) and the flag award (the
// token endpoint accepts a code owned by a different IdP user) live in the
// shared IdP handlers (shared.js), kept identical to the original router.
const express = require('express');
const { page, briefPanel, payloadBlock } = require('../../../lib/page');

const router = express.Router();

// GET /oauth/code-leak -> the Lab 2 challenge page.
router.get('/code-leak', (req, res) => {
  res.send(page('Lab 2: Authorization code leaked in the server log', `
    ${briefPanel('The setup', `
      <p>Authorization codes are secrets: whoever holds one can swap it for an
      access token. But this IdP writes every issued code into its request log,
      and the log is readable by anyone.</p>
      <p>A fresh login by <b>alice</b> was already recorded when the lab booted,
      so the log is not empty. Find her code, then spend it yourself.</p>`, 'Lab 2: Code leaked in the server log')}
    <div class="clay-card">
      <h3>Steal the code</h3>
      <ol>
        <li><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/idp/log">Open the IdP server log</a>
        and find the code from alice's recent login. Look for the line with
        <code>authorize user_id=</code> and a <code>?code=</code> at the end.</li>
        <li>Exchange it at <code>POST /oauth/idp/token</code> with
        <code>client_id=pentrix-spa</code> (a public client, so no secret is needed).</li>
      </ol>
      ${payloadBlock('Token exchange', 'curl -s -b jar -X POST http://localhost:3000/oauth/idp/token \\\n  -d "client_id=pentrix-spa" \\\n  -d "code=<code-from-the-log>"')}
    </div>
    <div class="clay-card">
      <h3>Flag condition</h3>
      <p>The flag is awarded when the token endpoint accepts a code that belongs to a
      different IdP user than the one making the request. The seeded code belongs to
      alice, so run the exchange while logged in as
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/login/bob">bob</a>
      (or with no IdP session at all), never as alice.</p>
    </div>
    <p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'code-leak',
    name: 'Authorization Code Leaked in Server Log',
    difficulty: 'Easy',
    hint: 'Every issued code is written to /oauth/idp/log, which anyone can read. A recent login by alice is already in there.',
    hints: ["The IdP keeps a request log that anyone can read. Open it in your proxied browser and look for the line with authorize user_id= and a ?code= at the end.", "A login by alice is already in the log. Copy her 32-character code and send it to POST /oauth/idp/token with Burp Repeater.", "Spend the stolen code while logged in as bob (or logged out entirely). Exchanging your own code earns nothing."],
    tools: "BZ, B",
    how: 'Read the IdP server log, copy alice’s code, and exchange it at POST /oauth/idp/token with client_id=pentrix-spa while logged in as someone else (or logged out).',
    link: '/oauth#code-leak',
    start: 'Set Burp as your browser proxy and enable intercept. In the browser, open the IdP server log at http://localhost:3000/oauth/idp/log. Find alice’s authorize line and copy the 32-character code after ?code=. Send that request to Repeater (or open a new Repeater tab) and POST the code to /oauth/idp/token with client_id=pentrix-spa, from a session that is not alice (bob, or no IdP login at all).',
  },
  router,
};
