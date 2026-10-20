'use strict';
// OAuth Flaws: a miniature identity provider plus a flawed OAuth client.
// Eight labs covering the classic OAuth failure modes: redirect URI
// validation bypass, codes leaked in logs, login CSRF from a missing state
// parameter, implicit-flow tokens in browser history, scope tampering, the
// client secret in public JavaScript, code replay, and PKCE downgrade.
const express = require('express');
const { brief, esc, difficultyPill, hintLadder, page, toolsPill, trackBanner, easyFirst, cardConsoles, startBlock, fixSection, capturedPill } = require('../../lib/page');
const shared = require('./shared');

const challenges = [
  require('./challenges/redirect-bypass'),
  require('./challenges/code-leak'),
  require('./challenges/no-state'),
  require('./challenges/implicit'),
  require('./challenges/scope-upgrade'),
  require('./challenges/secret-in-js'),
  require('./challenges/code-replay'),
  require('./challenges/pkce-skip'),
];

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

// Track which challenge the student is working through: visiting a
// challenge page stamps the session, and codes issued afterwards carry
// that flow (see idp.js approve and shared.js issueCode). The token
// endpoint scopes the code-replay award to codes issued inside the
// code-replay challenge's own flow, so a replayed code from another
// challenge (PKCE, scope tampering, and so on) never pops that flag
// in a lab the student was not aiming at.
const CHALLENGE_IDS = new Set(challenges.map((c) => c.vuln.id));
router.use((req, res, next) => {
  const seg = req.path.replace(/^\/+|\/+$/g, '');
  if (req.session && CHALLENGE_IDS.has(seg)) req.session.oauth_flow = seg;
  next();
});

// IdP endpoints (authorize/token/userinfo/log) live in ./idp.js and the
// flawed demo client endpoints in ./client.js; this index stays a thin
// aggregator (challenges + module home page) per the module contract.
const idpRouter = require('./idp');
const clientRouter = require('./client');
router.use(idpRouter);
router.use(clientRouter);

// ---------------------------------------------------------------------------
// Module index
// ---------------------------------------------------------------------------

// GET /oauth -> module index page.
router.get('/', (req, res) => {
  const me = shared.idpUser(req);
  const c = req.session.oauth_client;
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('oauth', ordered);
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'oauth', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/oauth/${esc(v.id)}">Open challenge</a></p>
    </article>`).join('');

  res.send(page('OAuth Flaws', `
    ${brief('OAuth Flaws', `
      <b>OAuth in 30 seconds:</b> a client wants to act on your behalf. It sends you to the
      <b>identity provider (IdP)</b>, you log in and approve, and the IdP hands the client an
      <b>authorization code</b> (via your browser) which the client swaps for an
      <b>access token</b> at the token endpoint. Every step has classic failure modes, and this
      lab has all of them.<br><br>
      <b>The setup:</b> this module contains both sides. The IdP lives under
      <code>/oauth/idp/</code> (authorize, token, userinfo, log) and the flawed client under
      <code>/oauth/client/</code>. <code>${esc(shared.TRUSTED_PREFIX)}</code> is the fictional client
      host; issued codes and tokens are shown on the approval pages because the redirect never
      resolves in your browser.<br><br>
      <b>Your two hats:</b> IdP session: ${me ? `<b>${esc(me.username)}</b>` : 'not logged in'}<br>
      <span class="quick-login" aria-label="Quick IdP login"><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/login/alice">alice (victim)</a> <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/login/bob">bob (attacker)</a> <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/login/admin">admin</a> <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/oauth/logout">logout</a></span><br>
      Client session: ${c ? `<b>${esc(c.username)}</b>` : 'not logged in'}.`)}
    ${trackBanner(module.exports)}

    <h2>Endpoints</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">OAuth module endpoints</caption>
      <thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Description</th></tr></thead>
      <tbody>
        <tr><td>GET</td><td><code>/oauth/login/:user</code></td><td>Log in to the IdP as alice, bob, or admin (demo only)</td></tr>
        <tr><td>GET</td><td><code>/oauth/idp/authorize</code></td><td>Authorization endpoint (consent screen)</td></tr>
        <tr><td>POST</td><td><code>/oauth/idp/approve</code></td><td>Approve a grant, issues the code or token</td></tr>
        <tr><td>POST</td><td><code>/oauth/idp/token</code></td><td>Token endpoint: exchange a code for a token</td></tr>
        <tr><td>GET</td><td><code>/oauth/idp/userinfo</code></td><td>User info for a presented access token</td></tr>
        <tr><td>GET</td><td><code>/oauth/idp/admin-data</code></td><td>Admin data (requires admin scope)</td></tr>
        <tr><td>GET</td><td><code>/oauth/idp/log</code></td><td>World-readable IdP request log</td></tr>
        <tr><td>GET</td><td><code>/oauth/client/</code></td><td>Demo client home page</td></tr>
        <tr><td>GET</td><td><code>/oauth/client/callback</code></td><td>Client OAuth callback (no state check)</td></tr>
        <tr><td>GET</td><td><code>/oauth/client/app.js</code></td><td>Public JavaScript bundle</td></tr>
        <tr><td>GET</td><td><code>/oauth/client/history</code></td><td>Simulated browser history</td></tr>
      </tbody>
    </table></div>

    <h2>Challenges</h2>
    <p>Eight flaws hide in the flows above. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    shape of the attack.</p>
    ${cards}
  ${fixSection('oauth', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'oauth',
  name: 'OAuth Flaws',
  tagline: 'Break a miniature OAuth deployment: redirects, codes, tokens, and scopes.',
  description: 'A simulated identity provider and a flawed OAuth client in one module. Eight labs covering the classic OAuth failure modes: redirect URI validation bypass, codes leaked in logs, login CSRF from a missing state parameter, implicit-flow tokens in browser history, scope tampering, the client secret in public JavaScript, code replay, and PKCE downgrade.',
  difficulty: 'Intermediate',
  track: 'Auth and Sessions',
  prerequisites: ['auth', 'jwt'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
