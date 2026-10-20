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
  hint: 'response_type=token puts the access token in the URL fragment. Fragments never reach a server, so where else does a full URL get written down?',
  hints: ["Fragments never reach the server, so Repeater cannot fetch one directly. Which in-lab page records the victim's full URL, fragment included, and through which Burp Proxy history entry does that record travel?", "In Proxy history, watch for the request that records the victim's visit. Its body carries the full URL, fragment still attached.", "Shape: a token lifted out of a recorded URL, presented at the userinfo endpoint from a session that is not its owner's. The endpoint trusts the token itself, not the story of how you got it."],
  tools: 'BZ, B, DT',
  est: 'about 15 to 25 minutes',
  how: 'The implicit flow delivers tokens inside URL fragments, and fragments leak into every place a full URL gets recorded.',
  link: '/oauth#implicit',
  start: 'Proxy your browser through Burp and open /oauth#implicit. Run the implicit flow as alice and approve the consent, then study in Proxy history every place the resulting URL turns up.',
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
      <h3>The scenario</h3>
      <p>Run the flow as the victim
      (<a href="/oauth/login/alice">alice</a>):
      <a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(href)}">Run the implicit flow</a>
      and approve it. The lab then simulates the victim browser recording the
      full landing URL: see <a href="/oauth/client/implicit-callback">the implicit callback page</a>
      and <a href="/oauth/client/history">the browser history</a>. Your job is to
      find where the token resurfaces, and what the userinfo endpoint accepts.</p>
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
