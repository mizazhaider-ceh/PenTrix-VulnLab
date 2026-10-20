'use strict';
// Lab 2: Authorization code leaked in the server log. Every issued code is
// written to the world-readable IdP request log, so a stolen code can be
// exchanged for a token by anyone. This file owns the challenge page only.
// The leak (issueCode writes the code to REQ_LOG) and the flag award (the
// token endpoint accepts a code owned by a different IdP user) live in the
// shared IdP handlers (shared.js), kept identical to the original router.
// VULN: issued authorization codes are written to a world-readable request
// log, so anyone can steal a code and exchange it for a token.
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
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/idp/log">Open the IdP server log</a>
      and study what an authorize line records. Find one that belongs to another
      user, then think about what the token endpoint at
      <code>POST /oauth/idp/token</code> would need to see to hand you a token
      for it. A public client such as <code>pentrix-spa</code> needs no secret
      at the token endpoint.</p>
      ${payloadBlock('Burp Repeater', 'POST /oauth/idp/token HTTP/1.1\nHost: <your-lab-address>\nContent-Type: application/x-www-form-urlencoded\nCookie: <your-session-cookie>\n\nclient_id=pentrix-spa&code=<code-from-the-log>')}
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
    hints: ["The IdP keeps a request log that anyone can read. Open it in your proxied browser and look for the line with authorize user_id= and a ?code= at the end.", "A login by alice is already in the log. Copy her 32-character code and send it to POST /oauth/idp/token with Burp Repeater.", "Spend the stolen code while logged in as bob (or logged out entirely). Exchanging a code that belongs to you earns nothing here, on any use; this flag only pays for a code that belongs to a different user."],
    tools: "BZ, B",
    est: 'about 5 to 10 minutes',
    how: 'Authorization codes are written into a request log that anyone can read, so a code stops being a secret the moment it is issued.',
    link: '/oauth#code-leak',
    start: 'Set Burp as your browser proxy. In the browser, open the IdP server log at /oauth/idp/log and study what a single authorize line records. Then experiment at the token endpoint, from a session that is not the code owner, with what you find there.',
  },
  router,
};
