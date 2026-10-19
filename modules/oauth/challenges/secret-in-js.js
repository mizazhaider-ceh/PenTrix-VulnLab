'use strict';
// Client secret in public JavaScript: the "confidential" client's secret is
// served in /oauth/client/app.js, so anyone can read it and do the token
// exchange directly. The flag condition lives in the shared token endpoint:
// doTokenExchange awards 'secret-in-js' when a direct (non-callback) request
// presents the matching client_secret. This file owns only the challenge page.
const express = require('express');
const { page, esc, hintLadder, toolsPill, difficultyPill, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const TRUSTED_PREFIX = 'http://app.pentrix.lab';

const vuln = {
  id: 'secret-in-js',
  name: 'Client Secret in Public JavaScript',
  difficulty: 'Easy',
  hint: 'The "confidential" client ships its secret inside /oauth/client/app.js, which anyone can download.',
  hints: ["The client secret is in the public app.js. Why is that bad?", "Confidential clients must keep the secret server-side. Yours is public.", "Extract the secret and do the token exchange directly."],
  tools: 'DT, C',
  how: 'Copy CLIENT_SECRET from app.js and exchange your own code with a direct POST to the token endpoint.',
  link: '/oauth#secret-in-js',
  start: 'curl -s "http://localhost:3000/oauth/idp/authorize?client_id=pentrix-client&redirect_uri=http%3A%2F%2Fapp.pentrix.lab%2Fcallback&response_type=code"\ncurl -s -b jar http://localhost:3000/oauth/client/app.js\ncurl -s -b jar -X POST http://localhost:3000/oauth/idp/token -d "client_id=pentrix-client&client_secret=<SECRET>&code=<CODE>"',
};

// GET /oauth/secret-in-js -> Lab 6 challenge page.
router.get('/secret-in-js', (req, res) => {
  const href = '/oauth/idp/authorize?client_id=pentrix-client&redirect_uri=' +
    encodeURIComponent(TRUSTED_PREFIX + '/callback') +
    '&response_type=code&scope=read';
  res.send(page('Lab 6: Client secret in public JavaScript', `
    <div class="card app-shell">
      <div class="card-top"><span class="orb" aria-hidden="true">🔐</span>
        <b>PenTrix IdP</b><span class="app-nav"><span class="dim">Authorize</span><span class="dim"> · </span><span class="dim">Token</span><span class="dim"> · </span><span class="dim">Client app</span></span></div>
      <p class="dim">Labs / Lab 6</p>
      <h2>Client secret in public JavaScript</h2>
      <div>${difficultyPill(vuln.difficulty)} ${toolsPill(vuln)}</div>
      <p>The <code>pentrix-client</code> is a "confidential" client: it must present its
      <code>client_secret</code> to exchange codes. But the secret is embedded in the
      public JavaScript bundle, which every visitor can download.</p>
      <ol>
        <li>Log in to the IdP as
          <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/login/bob">bob</a>.</li>
        <li><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(href)}">Authorize pentrix-client</a>
          with <code>response_type=code</code> and approve; copy the code.</li>
        <li>Open
          <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/client/app.js">app.js</a>
          and copy <code>CLIENT_SECRET</code>.</li>
        <li><code>POST /oauth/idp/token</code> with <code>client_id=pentrix-client</code>,
          the stolen secret, and your code, directly (not through the client callback).</li>
      </ol>
      ${payloadBlock('Read the secret from the public bundle', 'curl -s -b jar http://localhost:3000/oauth/client/app.js')}
      ${payloadBlock('Direct token exchange', 'curl -s -b jar -X POST http://localhost:3000/oauth/idp/token -d "client_id=pentrix-client&client_secret=<SECRET>&code=<CODE>"')}
      <p class="dim">The flag is awarded when the token endpoint is used directly with the leaked secret.</p>
    </div>
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = { vuln, router };
