'use strict';
// Implicit Flow Token in URL Fragment: GET /oauth/implicit is the lab page.
// With response_type=token the IdP issues the access token straight into the
// URL fragment (module-level shared route /oauth/idp/approve), the simulated
// victim browser records the full URL, fragment included, in the in-lab
// history (shared /oauth/client/implicit-callback and /oauth/client/history),
// and the flag is awarded by the shared /oauth/idp/userinfo route when an
// implicit-flow token belonging to someone else is presented. No award logic
// lives in this file.
// VULN: the implicit flow delivers the access token in the URL fragment,
// which leaks through browser history to anyone who can read it.
const express = require('express');
const { page, esc, brief, hintLadder, payloadBlock } = require('../../../lib/page');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'implicit',
  name: 'Implicit Flow Token in URL Fragment',
  difficulty: 'Medium',
  hint: 'response_type=token puts the access token in the URL fragment. Drive the flow in a Burp-proxied browser: the simulated victim browser records the full URL, fragment included, and userinfo awards the flag when an implicit token belonging to someone else is presented.',
  hints: ["Fragments never reach the server, so Repeater cannot fetch one directly. Which in-lab page records the victim's full URL, fragment included, and through which Burp Proxy history entry does that record travel?", "In Proxy history, find the POST to /oauth/client/history-log. Its JSON body carries the victim's URL with the fragment still attached. Lift the access_token out of it.", "Open Repeater on GET /oauth/idp/userinfo and present the stolen token using a session that is not alice's. A token that belongs to someone else earns the flag."],
  tools: 'BZ, B, DT',
  how: 'Run the implicit flow in a Burp-proxied browser as alice, let the simulated victim browser record the fragment-bearing URL in /oauth/client/history, then call userinfo in Repeater with the stolen token as a different session.',
  link: '/oauth#implicit',
  start: 'Proxy your browser through Burp and open /oauth#implicit. Log in as alice, click "Run the implicit flow" and approve the consent. The browser lands on the callback URL with #access_token=... in the fragment. Then open /oauth/client/implicit-callback with that fragment so the simulated victim browser records the full URL, and watch Burp Proxy history for where the token resurfaces.',
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
      ${payloadBlock('Burp Repeater (call userinfo with the stolen token)', `GET /oauth/idp/userinfo?access_token=<TOKEN> HTTP/1.1
Host: <your-lab-address>
Cookie: connect.sid=<PASTE_YOUR_SESSION_COOKIE>

`)}
      <p class="dim">The flag is awarded when userinfo is called with an implicit-flow token that belongs to someone else.</p>
    </div>` +
    hintLadder(vuln) +
    `<p><a class="clay-btn clay-btn-secondary" href="/oauth">Back to the OAuth module</a></p>`
  ));
});

module.exports = { vuln, router };
