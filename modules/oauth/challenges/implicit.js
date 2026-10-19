'use strict';
// Implicit Flow Token in URL Fragment: GET /oauth/implicit is the lab page.
// With response_type=token the IdP issues the access token straight into the
// URL fragment (module-level shared route /oauth/idp/approve), the simulated
// victim browser records the full URL, fragment included, in the in-lab
// history (shared /oauth/client/implicit-callback and /oauth/client/history),
// and the flag is awarded by the shared /oauth/idp/userinfo route when an
// implicit-flow token belonging to someone else is presented. No award logic
// lives in this file.
const express = require('express');
const { page, esc, brief, hintLadder, payloadBlock } = require('../../../lib/page');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'implicit',
  name: 'Implicit Flow Token in URL Fragment',
  difficulty: 'Medium',
  hint: 'response_type=token puts the access token in the URL fragment. The in-lab browser history records full URLs, fragments included.',
  hints: ["The token is in the URL fragment. Where do fragments end up?", "Browser history, logs, referer. The token leaks.", "Use the leaked fragment token at the userinfo endpoint."],
  tools: 'B, DT',
  how: 'Run the implicit flow, find the token in /oauth/client/history, and call userinfo with it.',
  link: '/oauth#implicit',
  start: 'curl -s -c alice.jar http://localhost:3000/oauth/login/alice\ncurl -s -b alice.jar "http://localhost:3000/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=http%3A%2F%2Fapp.pentrix.lab%2Fcallback&response_type=token&scope=read"',
};

router.get('/implicit', (req, res) => {
  // Same authorize URL construction as router.js.
  const href = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' + encodeURIComponent(shared.TRUSTED_PREFIX + '/callback') +
    '&response_type=token&scope=read';
  res.send(page('Lab 4: Implicit flow token in the fragment',
    brief('Lab 4: Implicit flow token in the fragment',
      `With <code>response_type=token</code> the IdP returns the access token directly
      in the URL fragment. Fragments never reach the server, but they do end up in browser
      history, and this lab simulates exactly that.`) +
    `<div class="clay-card">
      <h3>Attack plan</h3>
      <ol>
        <li>Log in to the IdP as <a href="/oauth/login/alice">alice</a> (the victim).</li>
        <li><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(href)}">Run the implicit flow</a> and approve it; copy the fragment URL.</li>
        <li>Simulate the victim browser: open <a href="/oauth/client/implicit-callback">the implicit callback page</a> with that fragment (paste it after the <code>#</code>), so the URL is recorded.</li>
        <li>As the attacker, open <a href="/oauth/client/history">the browser history</a>, steal the token, and call the userinfo endpoint with it.</li>
      </ol>
      ${payloadBlock('Call userinfo with the stolen token (replace TOKEN)', 'curl -s "http://localhost:3000/oauth/idp/userinfo?access_token=TOKEN"')}
      <p class="dim">The flag is awarded when userinfo is called with an implicit-flow token that belongs to someone else.</p>
    </div>` +
    hintLadder(vuln) +
    `<p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>`
  ));
});

module.exports = { vuln, router };
