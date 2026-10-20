'use strict';
// Client secret in public JavaScript: the "confidential" client's secret is
// served in /oauth/client/app.js, so anyone can read it and do the token
// exchange directly. The flag condition lives in the shared token endpoint:
// doTokenExchange awards 'secret-in-js' when a direct (non-callback) request
// presents the matching client_secret. This file owns only the challenge page.
// VULN: the "confidential" client's secret is served inside public
// JavaScript, so anyone can read it and perform the token exchange directly.
const express = require('express');
const { page, esc, hintLadder, toolsPill, difficultyPill, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const TRUSTED_PREFIX = 'http://app.pentrix.lab';

const vuln = {
  id: 'secret-in-js',
  name: 'Client Secret in Public JavaScript',
  difficulty: 'Easy',
  hint: 'The "confidential" client ships its secret inside /oauth/client/app.js, which anyone can download.',
  hints: ["In Burp's browser, log in as bob and authorize pentrix-client normally. Then send a GET for the client's public JavaScript bundle to Repeater and read it the way any visitor could.", "What you find in the bundle is the whole credential the token endpoint asks this client for. Think about what the endpoint cannot distinguish: a direct call with the right secret looks exactly like the real client.", "Shape: a code of your own, exchanged with a direct POST to the token endpoint from Repeater, presenting what the bundle gave away. Compare that exchange with the normal callback one."],
  tools: 'BZ, B, DT, C',
  est: 'about 5 to 10 minutes',
  how: 'A confidential client shipped its secret inside code every visitor downloads, so anyone can impersonate the client.',
  link: '/oauth#secret-in-js',
  start: 'With Burp Proxy on, log in to the IdP as bob in the browser, authorize pentrix-client once, and fetch /oauth/client/app.js through Repeater.',
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
        <li>Approve <code>pentrix-client</code> with <code>response_type=code</code>; copy the code.</li>
        <li>Open
          <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/client/app.js">app.js</a>
          and copy <code>CLIENT_SECRET</code>.</li>
        <li><code>POST /oauth/idp/token</code> with <code>client_id=pentrix-client</code>,
          the stolen secret, and your code, directly (not through the client callback).</li>
      </ol>
      <p><a class="clay-btn clay-btn-primary" href="${esc(href)}">Authorize pentrix-client</a></p>
      <p class="dim">Approve and copy the code with the button above, then exchange it directly with the stolen secret.</p>
      <p>Open the bundle URL in your proxied browser (or Repeater) and read it:</p>
      ${payloadBlock('Burp Repeater (read the public bundle)', `GET /oauth/client/app.js HTTP/1.1
Host: <your-lab-address>

`)}
      ${payloadBlock('Burp Repeater (direct token exchange)', `POST /oauth/idp/token HTTP/1.1
Host: <your-lab-address>
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<PASTE_YOUR_SESSION_COOKIE>

client_id=pentrix-client&client_secret=<SECRET>&code=<CODE>`)}
      <p class="dim">The flag is awarded when the token endpoint is used directly with the leaked secret.</p>
    </div>
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth">Back to the OAuth module</a></p>
  `));
});

module.exports = { vuln, router };
