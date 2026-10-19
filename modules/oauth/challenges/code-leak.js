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
    hints: ["Authorization codes are written to a server log. Can you read the log?", "The log is at /oauth/log (or similar). Codes are in plaintext.", "Read the log, steal a code, and exchange it for a token."],
    tools: "B, C",
    how: 'Read the log, copy alice\u2019s code, and exchange it at the token endpoint with client_id=pentrix-spa.',
    link: '/oauth#code-leak',
    start: 'curl -s -b jar -c jar http://localhost:3000/oauth/login/bob\ncurl -s -b jar http://localhost:3000/oauth/idp/log',
  },
  router,
};
