'use strict';
// OAuth Flaws: a miniature identity provider plus a flawed OAuth client.
// Eight labs covering the classic OAuth failure modes: redirect URI
// validation bypass, codes leaked in logs, login CSRF from a missing state
// parameter, implicit-flow tokens in browser history, scope tampering, the
// client secret in public JavaScript, code replay, and PKCE downgrade.
const express = require('express');
const { getDb } = require('../../lib/db');
const { fixCta, brief, esc, difficultyPill, fixPanel, flagBox, hintLadder, page, payloadBlock, toolsPill, trackBanner } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');
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

// ---------------------------------------------------------------------------
// IdP account helpers (the "identity provider" side of the lab)
// ---------------------------------------------------------------------------
router.get('/login/:who', (req, res) => {
  const who = req.params.who;
  if (!['alice', 'bob', 'admin'].includes(who)) {
    return res.status(404).send(page('Login', '<p>Unknown test account. Use alice, bob, or admin.</p>'));
  }
  const u = getDb().prepare('SELECT id, username, role FROM users WHERE username = ?').get(who);
  req.session.idp_user = { id: u.id, username: u.username, role: u.role };
  res.send(page('IdP login', `
    <h2>Logged in to the identity provider</h2>
    <p>You are now <b>${esc(u.username)}</b> (role: ${esc(u.role)}) at the IdP.</p>
    <p><a href="/oauth">Back to the OAuth module</a></p>
  `));
});

router.get('/logout', (req, res) => {
  req.session.idp_user = null;
  req.session.oauth_client = null;
  res.send(page('Logged out', `
    <h2>Logged out</h2>
    <p>Both the IdP session and the client session were cleared.</p>
    <p><a href="/oauth">Back to the OAuth module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// IdP: authorization endpoint (shows a consent screen)
// ---------------------------------------------------------------------------
router.get('/idp/authorize', (req, res) => {
  const p = req.query;
  const client = shared.CLIENTS[p.client_id];
  const me = shared.idpUser(req);
  let err = '';
  if (!client) err = 'Unknown client_id. Registered clients: pentrix-client, pentrix-spa.';
  else if (!shared.redirectOk(p.redirect_uri)) err = 'redirect_uri rejected by the IdP.';
  else if (p.response_type !== 'code' && p.response_type !== 'token') err = 'response_type must be "code" or "token".';

  const hidden = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state', 'code_challenge', 'code_challenge_method']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(p[k] || '')}" />`).join('\n');

  res.send(page('Authorize application', `
    <h2>Identity provider: authorization request</h2>
    ${err ? `<p class="note"><b>Error:</b> ${esc(err)}</p><p><a href="/oauth">Back</a></p>`
      : `
    <p>Application <b>${esc(client.name)}</b> (${esc(client.kind)}) is asking for access.</p>
    <ul>
      <li>redirect_uri: <code>${esc(p.redirect_uri || '')}</code></li>
      <li>response_type: <code>${esc(p.response_type || '')}</code></li>
      <li>scope: <code>${esc(p.scope || 'read')}</code></li>
      <li>state: <code>${esc(p.state || '(none)')}</code></li>
      ${p.code_challenge ? `<li>code_challenge: <code>${esc(p.code_challenge)}</code> (${esc(p.code_challenge_method || 'plain')})</li>` : ''}
    </ul>
    ${me ? `<p>Logged in to the IdP as <b>${esc(me.username)}</b>.</p>
      <form method="POST" action="/oauth/idp/approve">
        ${hidden}
        <button type="submit">Approve and continue</button>
      </form>`
      : `<p class="note">You are not logged in to the IdP. Log in as
        <a href="/oauth/login/alice">alice</a> (victim),
        <a href="/oauth/login/bob">bob</a> (attacker), or
        <a href="/oauth/login/admin">admin</a>, then reload this page.</p>`}
    `}
  `));
});

// ---------------------------------------------------------------------------
// IdP: approve the grant (issues the code or token)
// ---------------------------------------------------------------------------
router.post('/idp/approve', (req, res) => {
  const p = req.body;
  const me = shared.idpUser(req);
  const client = shared.CLIENTS[p.client_id];
  if (!me) return res.status(403).send(page('Denied', '<p>Log in to the IdP first.</p>'));
  if (!client || !shared.redirectOk(p.redirect_uri) || (p.response_type !== 'code' && p.response_type !== 'token')) {
    return res.status(400).send(page('Denied', '<p>Invalid authorization request.</p>'));
  }
  const scope = p.scope || 'read';
  const state = p.state ? '&state=' + encodeURIComponent(p.state) : '';

  if (p.response_type === 'code') {
    const code = shared.issueCode({
      clientId: client.id, ownerId: me.id, redirectUri: p.redirect_uri,
      scope, challenge: p.code_challenge || null,
    });
    const target = p.redirect_uri + '?code=' + code + state;
    let extra = '';
    // VULN: the naive prefix check passed, yet the code is leaving for a
    // foreign host. The bypass genuinely succeeded: a code was issued to an
    // attacker-controlled redirect URI.
    if (shared.bypassHost(p.redirect_uri)) {
      extra = flagBox(award(req, 'oauth', 'redirect-bypass')) + fixPanel('oauth', 'redirect-bypass');
    }
    return res.send(page('Authorization granted', `
      <h2>Authorization granted</h2>
      ${extra}
      <p>The IdP issued an authorization code and redirects to:</p>
      <p><code>${esc(target)}</code></p>
      <p><a href="${esc(target)}">Continue to the redirect target</a></p>
      <p class="note">${esc(shared.TRUSTED_PREFIX)} is the fictional client host used by this lab,
      so the redirect will not resolve in your browser. The code is shown above; copy it
      for the token exchange.</p>
    `));
  }

  // Implicit flow: the token goes straight into the URL fragment.
  const t = shared.issueToken({ ownerId: me.id, scope, clientId: client.id, grant: 'implicit' });
  const target = p.redirect_uri + '#access_token=' + t + '&token_type=Bearer' + state;
  // Note: implicit tokens are deliberately NOT written to the server log;
  // they leak through the in-lab browser history instead (see next lab).
  return res.send(page('Authorization granted', `
    <h2>Authorization granted (implicit flow)</h2>
    <p>The IdP redirects to:</p>
    <p><code>${esc(target)}</code></p>
    <p class="note">The access token sits in the URL fragment. Fragments never reach
    the server, but they do sit in browser history. Simulate the victim browser visiting
    <a href="/oauth/client/implicit-callback">the implicit callback page</a> with this
    fragment, then check <a href="/oauth/client/history">the recorded history</a>.</p>
  `));
});

// ---------------------------------------------------------------------------
// IdP: token endpoint
// ---------------------------------------------------------------------------
function tokenRoute(req, res) {
  const p = Object.assign({}, req.query, req.body);
  const me = shared.idpUser(req);
  const sessUserId = me ? me.id : null;
  const r = shared.doTokenExchange(p, sessUserId, false);
  if (r.awardId) r.body.flag = award(req, 'oauth', r.awardId);
  res.status(r.http).json(r.body);
}
router.post('/idp/token', tokenRoute);
router.get('/idp/token', tokenRoute);

// ---------------------------------------------------------------------------
// IdP: userinfo resource endpoint
// ---------------------------------------------------------------------------
router.get('/idp/userinfo', (req, res) => {
  const t = shared.tokens.get(req.query.access_token || shared.bearerToken(req));
  if (!t) return res.status(401).json({ error: 'missing or unknown access token' });
  const u = shared.userById(t.ownerId);
  const me = shared.idpUser(req);
  const sessUserId = me ? me.id : null;
  const body = { username: u.username, email: u.email, role: u.role, scope: t.scope, grant: t.grant };
  // VULN: a token leaked through the implicit flow / browser history is
  // accepted here no matter who presents it.
  if (t.grant === 'implicit' && t.ownerId !== sessUserId) {
    body.flag = award(req, 'oauth', 'implicit');
  }
  res.json(body);
});

// ---------------------------------------------------------------------------
// IdP: world-readable request log (the code-leak attack surface)
// ---------------------------------------------------------------------------
router.get('/idp/log', (req, res) => {
  const rows = shared.REQ_LOG.map((l) => `<div class="logline">${esc(l)}</div>`).join('\n') || '<p>(empty)</p>';
  res.send(page('IdP server log', `
    <h2>Identity provider request log</h2>
    <p class="note">Debug log. In this lab it is readable by anyone, and it records
    every issued authorization code together with its full redirect target.</p>
    ${rows}
    <p><a href="/oauth">Back to the OAuth module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// Client: home, callback, public JS, implicit callback, history
// ---------------------------------------------------------------------------
router.get('/client/', (req, res) => {
  const c = req.session.oauth_client;
  const me = shared.idpUser(req);
  res.send(page('Demo client', `
    <h2>PenTrix demo client</h2>
    <p>IdP session: ${me ? `<b>${esc(me.username)}</b>` : 'not logged in'}
    (<a href="/oauth/login/alice">alice</a> / <a href="/oauth/login/bob">bob</a> / <a href="/oauth/login/admin">admin</a>)</p>
    <p>Client session: ${c ? `<b>${esc(c.username)}</b> (logged in via OAuth)` : 'not logged in'}</p>
    <ul>
      <li><a href="/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=${encodeURIComponent(shared.TRUSTED_PREFIX + '/callback')}&response_type=code&scope=read">Log in with the IdP (code flow)</a></li>
      <li><a href="/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=${encodeURIComponent(shared.TRUSTED_PREFIX + '/callback')}&response_type=token&scope=read">Log in with the IdP (implicit flow)</a></li>
      <li><a href="/oauth/client/app.js">app.js (public JavaScript bundle)</a></li>
      <li><a href="/oauth/client/history">Browser history (in-lab simulation)</a></li>
    </ul>
  `));
});

// The real client callback. It exchanges the code server-side and, critically,
// never validates the state parameter.
router.get('/client/callback', (req, res) => {
  const rec = shared.codes.get(req.query.code);
  if (!rec) {
    return res.status(400).send(page('Client callback', '<p>Missing or unknown code.</p><p><a href="/oauth/client/">Back</a></p>'));
  }
  const me = shared.idpUser(req);
  const sessUserId = me ? me.id : null;
  const r = shared.doTokenExchange({ client_id: rec.clientId, code: req.query.code }, sessUserId, true);
  if (r.http !== 200) {
    return res.status(r.http).send(page('Client callback', `<p>Token exchange failed: ${esc(r.body.error)}</p>`));
  }
  const u = shared.userById(rec.ownerId);
  req.session.oauth_client = { id: u.id, username: u.username };
  let extra = '';
  // VULN: no state check. If this code was minted for the attacker's account,
  // the victim is now logged in to the client AS THE ATTACKER (login CSRF).
  if (rec.ownerId !== sessUserId && sessUserId !== null) {
    extra = flagBox(award(req, 'oauth', 'no-state')) + fixPanel('oauth', 'no-state') +
      `<p class="note"><b>Login CSRF:</b> your IdP session is ` +
      `<b>${esc(me ? me.username : '(none)')}</b>, but the client just logged you in as ` +
      `<b>${esc(u.username)}</b>, the owner of the code in the link you visited.</p>`;
  }
  res.send(page('Client callback', `
    <h2>Client callback</h2>
    ${extra}
    <p>Code exchanged. Client session is now <b>${esc(u.username)}</b>.</p>
    <p><a href="/oauth/client/">Back to the client</a></p>
  `));
});

// VULN: the confidential client's secret is embedded in public JavaScript.
router.get('/client/app.js', (req, res) => {
  res.set('Content-Type', 'application/javascript');
  res.send(
    '// PenTrix demo SPA - public bundle. This file is served to every visitor.\n' +
    "var OAUTH_CLIENT_ID = 'pentrix-client';\n" +
    "var CLIENT_SECRET = 'sk_live_9f2c7b41d8e0a5c6'; // VULN: confidential secret shipped to the browser\n" +
    'function exchangeCode(code) {\n' +
    "  return fetch('/oauth/idp/token', {\n" +
    "    method: 'POST',\n" +
    "    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n" +
    "    body: 'client_id=' + OAUTH_CLIENT_ID + '&client_secret=' + CLIENT_SECRET + '&code=' + encodeURIComponent(code)\n" +
    '  }).then(function (r) { return r.json(); });\n' +
    '}\n'
  );
});

// Simulates the victim's browser landing on the implicit callback with the
// token in the fragment, then recording the full URL in its history.
router.get('/client/implicit-callback', (req, res) => {
  res.send(page('Implicit callback', `
    <h2>Implicit flow callback (simulated victim browser)</h2>
    <p>This page reads the access token out of the URL fragment and records the
    full visited URL, fragment included, in the in-lab browser history.</p>
    <div id="out"><p>Waiting for a fragment...</p></div>
    <script>
      var frag = location.hash.slice(1);
      var params = new URLSearchParams(frag);
      var tok = params.get('access_token');
      var box = document.getElementById('out');
      if (tok) {
        box.innerHTML = '<p>Access token captured from fragment: <code>' + tok.slice(0, 12) + '...</code></p>';
        fetch('/oauth/client/history-log', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: location.href })
        }).then(function () {
          box.innerHTML += '<p>URL recorded in <a href="/oauth/client/history">browser history</a>.</p>';
        });
      } else {
        box.innerHTML = '<p class="note">No access_token in the fragment. Run the implicit flow first: ' +
          '<a href="/oauth/implicit">lab 4</a>.</p>';
      }
    </script>
  `));
});

router.post('/client/history-log', (req, res) => {
  const url = req.body && req.body.url ? String(req.body.url) : '';
  if (url) {
    shared.HISTORY.unshift({ url, at: new Date().toISOString() });
    if (shared.HISTORY.length > 50) shared.HISTORY.pop();
  }
  res.json({ ok: !!url });
});

router.get('/client/history', (req, res) => {
  const rows = shared.HISTORY.map((h) =>
    `<div class="logline">${esc(h.at)}<br /><code>${esc(h.url)}</code></div>`).join('\n') || '<p>(no history yet)</p>';
  res.send(page('Browser history', `
    <h2>Browser history (in-lab simulation)</h2>
    <p class="note">A real browser history keeps full URLs, including fragments.
    The implicit flow puts the access token in the fragment. Anyone who can read
    this history owns those tokens.</p>
    ${rows}
    <p><a href="/oauth">Back to the OAuth module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// Module index
// ---------------------------------------------------------------------------

// GET /oauth -> module index page.
router.get('/', (req, res) => {
  const me = shared.idpUser(req);
  const c = req.session.oauth_client;
  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/oauth/${esc(v.id)}">Open challenge</a></p>
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('oauth', c.vuln.id)).join('')}
    </section>`;
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
      <b>Your two hats:</b> IdP session: ${me ? `<b>${esc(me.username)}</b>` : 'not logged in'}
      (<a href="/oauth/login/alice">alice</a> = victim, <a href="/oauth/login/bob">bob</a> = attacker,
      <a href="/oauth/login/admin">admin</a>, <a href="/oauth/logout">logout</a>).
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
  ${fixSectionHtml}
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
