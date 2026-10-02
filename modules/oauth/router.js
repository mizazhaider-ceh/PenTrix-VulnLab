// PenTrix VulnLab module: OAuth Flaws (oauth)
// A miniature identity provider plus a flawed OAuth client, all inside this
// module. Deliberately broken: naive redirect_uri prefix check, issued codes
// written to a world-readable log, no state validation (login CSRF), implicit
// flow with a leaky in-lab browser history, unenforced scopes, the client
// secret shipped in public JavaScript, reusable authorization codes, and
// optional PKCE. Local lab use only.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

// The fictional client host used throughout this lab. It never resolves;
// students read issued codes/tokens from the approval pages instead of
// following the redirect.
const TRUSTED_PREFIX = 'http://app.pentrix.lab';

const CLIENTS = {
  'pentrix-client': {
    id: 'pentrix-client', name: 'PenTrix Demo App', kind: 'confidential client',
    // VULN: the confidential client's secret is also shipped in public app.js.
    secret: 'sk_live_9f2c7b41d8e0a5c6',
    redirectUri: TRUSTED_PREFIX + '/callback',
  },
  'pentrix-spa': {
    id: 'pentrix-spa', name: 'PenTrix SPA', kind: 'public client (no secret)',
    secret: null,
    redirectUri: TRUSTED_PREFIX + '/callback',
  },
};

// In-memory IdP state (per boot; fine for a lab).
const codes = new Map();  // code -> { code, clientId, ownerId, redirectUri, scope, challenge, uses }
const tokens = new Map(); // token -> { token, ownerId, scope, clientId, grant }
const REQ_LOG = [];       // server request log (world-readable; leaks codes)
const HISTORY = [];       // simulated in-lab browser history (records full URLs)

function rid(n) { return crypto.randomBytes(n || 16).toString('hex'); }
function idpUser(req) { return req.session.idp_user || null; }
function userById(id) {
  return getDb().prepare('SELECT id, username, role, email FROM users WHERE id = ?').get(id);
}

// VULN: redirect_uri is validated with a naive prefix check instead of an
// exact match against the registered redirect URI.
function redirectOk(uri) {
  return typeof uri === 'string' && uri.startsWith(TRUSTED_PREFIX);
}
function bypassHost(uri) {
  try { return new URL(uri).host !== 'app.pentrix.lab'; }
  catch (e) { return false; }
}
function bearerToken(req) {
  const m = /^Bearer (.+)$/i.exec(req.headers.authorization || '');
  return m ? m[1] : null;
}
function logLine(s) {
  REQ_LOG.unshift(new Date().toISOString() + ' ' + s);
  if (REQ_LOG.length > 60) REQ_LOG.pop();
}

function issueCode(o) {
  const code = rid(16);
  codes.set(code, {
    code, clientId: o.clientId, ownerId: o.ownerId, redirectUri: o.redirectUri,
    scope: o.scope || 'read', challenge: o.challenge || null, uses: 0,
  });
  // VULN: every issued authorization code is written to the readable server
  // log, full redirect target included.
  logLine('authorize user_id=' + o.ownerId + ' client=' + o.clientId +
    ' scope=' + (o.scope || 'read') + ' -> 302 ' + o.redirectUri + '?code=' + code);
  return code;
}

function issueToken(o) {
  const t = rid(24);
  tokens.set(t, { token: t, ownerId: o.ownerId, scope: o.scope, clientId: o.clientId, grant: o.grant });
  return t;
}

// Shared code-exchange logic. viaCallback=true means the first-party client
// did the exchange server-side (normal flow: no lab flags). Direct hits to
// /idp/token go through the award checks below, first match wins.
function doTokenExchange(p, sessUserId, viaCallback) {
  const client = CLIENTS[p.client_id];
  if (!client) return { http: 400, body: { error: 'unknown client_id' } };
  if (client.secret && p.client_secret !== client.secret) {
    return { http: 401, body: { error: 'invalid client_secret' } };
  }
  const rec = codes.get(p.code);
  if (!rec || rec.clientId !== client.id) {
    return { http: 400, body: { error: 'invalid or expired code' } };
  }
  let awardId = null;
  if (!viaCallback) {
    if (rec.challenge && !p.code_verifier) awardId = 'pkce-skip';   // VULN: PKCE verifier never required
    else if (rec.ownerId !== sessUserId) awardId = 'code-leak';     // VULN: a stolen code is accepted
    else if (rec.uses >= 1) awardId = 'code-replay';                // VULN: codes are never single-use
    else if (client.secret && p.client_secret === client.secret) awardId = 'secret-in-js';
  }
  // VULN: the code is counted but never invalidated, so it stays reusable.
  rec.uses += 1;
  const t = issueToken({ ownerId: rec.ownerId, scope: rec.scope, clientId: client.id, grant: 'code' });
  return { http: 200, body: { access_token: t, token_type: 'Bearer', scope: rec.scope }, awardId };
}

// Seed one recent victim login so the log-leak lab works on a fresh boot.
(function seedVictimLogin() {
  const alice = getDb().prepare('SELECT id FROM users WHERE username = ?').get('alice');
  if (!alice) return;
  issueCode({ clientId: 'pentrix-spa', ownerId: alice.id, redirectUri: TRUSTED_PREFIX + '/callback', scope: 'read' });
})();

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
  const client = CLIENTS[p.client_id];
  const me = idpUser(req);
  let err = '';
  if (!client) err = 'Unknown client_id. Registered clients: pentrix-client, pentrix-spa.';
  else if (!redirectOk(p.redirect_uri)) err = 'redirect_uri rejected by the IdP.';
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
  const me = idpUser(req);
  const client = CLIENTS[p.client_id];
  if (!me) return res.status(403).send(page('Denied', '<p>Log in to the IdP first.</p>'));
  if (!client || !redirectOk(p.redirect_uri) || (p.response_type !== 'code' && p.response_type !== 'token')) {
    return res.status(400).send(page('Denied', '<p>Invalid authorization request.</p>'));
  }
  const scope = p.scope || 'read';
  const state = p.state ? '&state=' + encodeURIComponent(p.state) : '';

  if (p.response_type === 'code') {
    const code = issueCode({
      clientId: client.id, ownerId: me.id, redirectUri: p.redirect_uri,
      scope, challenge: p.code_challenge || null,
    });
    const target = p.redirect_uri + '?code=' + code + state;
    let extra = '';
    // VULN: the naive prefix check passed, yet the code is leaving for a
    // foreign host. The bypass genuinely succeeded: a code was issued to an
    // attacker-controlled redirect URI.
    if (bypassHost(p.redirect_uri)) {
      extra = flagBox(award(req, 'oauth', 'redirect-bypass'));
    }
    return res.send(page('Authorization granted', `
      <h2>Authorization granted</h2>
      ${extra}
      <p>The IdP issued an authorization code and redirects to:</p>
      <p><code>${esc(target)}</code></p>
      <p><a href="${esc(target)}">Continue to the redirect target</a></p>
      <p class="note">${esc(TRUSTED_PREFIX)} is the fictional client host used by this lab,
      so the redirect will not resolve in your browser. The code is shown above; copy it
      for the token exchange.</p>
    `));
  }

  // Implicit flow: the token goes straight into the URL fragment.
  const t = issueToken({ ownerId: me.id, scope, clientId: client.id, grant: 'implicit' });
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
  const sessUserId = idpUser(req) ? idpUser(req).id : null;
  const r = doTokenExchange(p, sessUserId, false);
  if (r.awardId) r.body.flag = award(req, 'oauth', r.awardId);
  res.status(r.http).json(r.body);
}
router.post('/idp/token', tokenRoute);
router.get('/idp/token', tokenRoute);

// ---------------------------------------------------------------------------
// IdP: userinfo and admin-data resource endpoints
// ---------------------------------------------------------------------------
router.get('/idp/userinfo', (req, res) => {
  const t = tokens.get(req.query.access_token || bearerToken(req));
  if (!t) return res.status(401).json({ error: 'missing or unknown access token' });
  const u = userById(t.ownerId);
  const sessUserId = idpUser(req) ? idpUser(req).id : null;
  const body = { username: u.username, email: u.email, role: u.role, scope: t.scope, grant: t.grant };
  // VULN: a token leaked through the implicit flow / browser history is
  // accepted here no matter who presents it.
  if (t.grant === 'implicit' && t.ownerId !== sessUserId) {
    body.flag = award(req, 'oauth', 'implicit');
  }
  res.json(body);
});

router.get('/idp/admin-data', (req, res) => {
  const t = tokens.get(req.query.access_token || bearerToken(req));
  if (!t) return res.status(401).json({ error: 'missing or unknown access token' });
  if (!String(t.scope || '').split(' ').includes('admin')) {
    return res.status(403).json({ error: 'admin scope required' });
  }
  const u = userById(t.ownerId);
  const body = {
    admin_secret: 'LAB FICTION: production deploy keys are stored in /opt/pentrix (do not try this at home)',
    granted_to: u.username, scope: t.scope,
  };
  // VULN: the IdP grants whatever scope is requested without checking whether
  // the user is entitled to it.
  if (u.role !== 'admin') body.flag = award(req, 'oauth', 'scope-upgrade');
  res.json(body);
});

// ---------------------------------------------------------------------------
// IdP: world-readable request log (the code-leak attack surface)
// ---------------------------------------------------------------------------
router.get('/idp/log', (req, res) => {
  const rows = REQ_LOG.map((l) => `<div class="logline">${esc(l)}</div>`).join('\n') || '<p>(empty)</p>';
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
  const me = idpUser(req);
  res.send(page('Demo client', `
    <h2>PenTrix demo client</h2>
    <p>IdP session: ${me ? `<b>${esc(me.username)}</b>` : 'not logged in'}
    (<a href="/oauth/login/alice">alice</a> / <a href="/oauth/login/bob">bob</a> / <a href="/oauth/login/admin">admin</a>)</p>
    <p>Client session: ${c ? `<b>${esc(c.username)}</b> (logged in via OAuth)` : 'not logged in'}</p>
    <ul>
      <li><a href="/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=${encodeURIComponent(TRUSTED_PREFIX + '/callback')}&response_type=code&scope=read">Log in with the IdP (code flow)</a></li>
      <li><a href="/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=${encodeURIComponent(TRUSTED_PREFIX + '/callback')}&response_type=token&scope=read">Log in with the IdP (implicit flow)</a></li>
      <li><a href="/oauth/client/app.js">app.js (public JavaScript bundle)</a></li>
      <li><a href="/oauth/client/history">Browser history (in-lab simulation)</a></li>
    </ul>
  `));
});

// The real client callback. It exchanges the code server-side and, critically,
// never validates the state parameter.
router.get('/client/callback', (req, res) => {
  const rec = codes.get(req.query.code);
  if (!rec) {
    return res.status(400).send(page('Client callback', '<p>Missing or unknown code.</p><p><a href="/oauth/client/">Back</a></p>'));
  }
  const sessUserId = idpUser(req) ? idpUser(req).id : null;
  const r = doTokenExchange({ client_id: rec.clientId, code: req.query.code }, sessUserId, true);
  if (r.http !== 200) {
    return res.status(r.http).send(page('Client callback', `<p>Token exchange failed: ${esc(r.body.error)}</p>`));
  }
  const u = userById(rec.ownerId);
  req.session.oauth_client = { id: u.id, username: u.username };
  let extra = '';
  // VULN: no state check. If this code was minted for the attacker's account,
  // the victim is now logged in to the client AS THE ATTACKER (login CSRF).
  if (rec.ownerId !== sessUserId && sessUserId !== null) {
    extra = flagBox(award(req, 'oauth', 'no-state')) +
      `<p class="note"><b>Login CSRF:</b> your IdP session is ` +
      `<b>${esc(idpUser(req) ? idpUser(req).username : '(none)')}</b>, but the client just logged you in as ` +
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
    HISTORY.unshift({ url, at: new Date().toISOString() });
    if (HISTORY.length > 50) HISTORY.pop();
  }
  res.json({ ok: !!url });
});

router.get('/client/history', (req, res) => {
  const rows = HISTORY.map((h) =>
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
// Per-vuln challenge pages (attack surface, discoverable from the index)
// ---------------------------------------------------------------------------
function chal(title, inner) {
  return page(title, `<h2>${esc(title)}</h2>${inner}<p><a href="/oauth">Back to the OAuth module</a></p>`);
}

router.get('/redirect-bypass', (req, res) => {
  const evil = TRUSTED_PREFIX + '.evil.com/cb';
  const href = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' + encodeURIComponent(evil) +
    '&response_type=code&scope=read';
  res.send(chal('Lab 1: Redirect URI prefix bypass', `
    <p>The IdP validates <code>redirect_uri</code> with a prefix check against
    <code>${esc(TRUSTED_PREFIX)}</code>. Find a URI that passes the check but delivers
    the authorization code to an attacker host.</p>
    <p><a class="btn" href="${esc(href)}">Start authorization with redirect_uri=${esc(evil)}</a></p>
    <p>Log in to the IdP first (as <a href="/oauth/login/alice">alice</a>), approve the
    request, and watch where the code goes. The flag is awarded when the IdP issues a
    code to a redirect URI whose host is not the registered one.</p>
  `));
});

router.get('/code-leak', (req, res) => {
  res.send(chal('Lab 2: Code leaked in the server log', `
    <p>Authorization codes are secrets, but this IdP writes every issued code into its
    request log, and the log is readable by anyone.</p>
    <ul>
      <li><a href="/oauth/idp/log">Open the IdP server log</a> and find the code from alice's recent login.</li>
      <li>Exchange it at <code>POST /oauth/idp/token</code> with
      <code>client_id=pentrix-spa</code> (a public client, no secret needed).</li>
    </ul>
    <p>The flag is awarded when the token endpoint accepts a code that belongs to a
    different IdP user than the one making the request.</p>
  `));
});

router.get('/no-state', (req, res) => {
  res.send(chal('Lab 3: Login CSRF (missing state)', `
    <p>The client callback exchanges any <code>code</code> it is given and never checks
    a <code>state</code> parameter. So an attacker can mint a code for <i>their own</i>
    account and trick the victim into visiting the callback with it: the victim ends up
    logged in to the client as the attacker.</p>
    <ol>
      <li>Log in to the IdP as <a href="/oauth/login/bob">bob</a> (the attacker).</li>
      <li><a href="/oauth/no-state/attacker">Generate the malicious login link</a>.</li>
      <li>Open that link in a second session where the IdP user is
      <a href="/oauth/login/alice">alice</a> (the victim).</li>
    </ol>
    <p>The flag is awarded when the callback logs the session in as someone other than
    its own IdP user.</p>
  `));
});

// Attacker link generator for the login-CSRF lab.
router.get('/no-state/attacker', (req, res) => {
  const me = idpUser(req);
  if (!me) {
    return res.send(chal('Login-CSRF link generator', `
      <p class="note">Log in to the IdP as the attacker first:
      <a href="/oauth/login/bob">log in as bob</a>, then come back here.</p>`));
  }
  const code = issueCode({
    clientId: 'pentrix-spa', ownerId: me.id,
    redirectUri: TRUSTED_PREFIX + '/callback', scope: 'read',
  });
  const evil = '/oauth/client/callback?code=' + code;
  res.send(chal('Login-CSRF link generator', `
    <p>A code for the attacker account <b>${esc(me.username)}</b> was minted
    (no <code>state</code> involved anywhere).</p>
    <p>Malicious link to send the victim:</p>
    <p><code>${esc(evil)}</code></p>
    <p>When the victim (logged in to the IdP as alice) visits it, the client logs
    them in as <b>${esc(me.username)}</b>.</p>
  `));
});

router.get('/implicit', (req, res) => {
  const href = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' + encodeURIComponent(TRUSTED_PREFIX + '/callback') +
    '&response_type=token&scope=read';
  res.send(chal('Lab 4: Implicit flow token in the fragment', `
    <p>With <code>response_type=token</code> the IdP returns the access token directly
    in the URL fragment. Fragments never reach the server, but they do end up in browser
    history, and this lab simulates exactly that.</p>
    <ol>
      <li>Log in to the IdP as <a href="/oauth/login/alice">alice</a> (the victim).</li>
      <li><a href="${esc(href)}">Run the implicit flow</a> and approve it; copy the fragment URL.</li>
      <li>Simulate the victim browser: open <a href="/oauth/client/implicit-callback">the implicit
      callback page</a> with that fragment (paste it after the <code>#</code>), so the URL is recorded.</li>
      <li>As the attacker, open <a href="/oauth/client/history">the browser history</a>, steal the token,
      and call <code>GET /oauth/idp/userinfo?access_token=...</code>.</li>
    </ol>
    <p>The flag is awarded when userinfo is called with an implicit-flow token that
    belongs to someone else.</p>
  `));
});

router.get('/scope-upgrade', (req, res) => {
  const href = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' + encodeURIComponent(TRUSTED_PREFIX + '/callback') +
    '&response_type=code&scope=admin';
  res.send(chal('Lab 5: Scope tampering', `
    <p>The authorization request carries a <code>scope</code> parameter, and the IdP
    grants whatever is asked for without checking the user's role.</p>
    <ol>
      <li>Log in to the IdP as <a href="/oauth/login/bob">bob</a> (a plain user).</li>
      <li><a href="${esc(href)}">Authorize with scope=admin</a> and approve it.</li>
      <li>Exchange the code at <code>POST /oauth/idp/token</code>
      (<code>client_id=pentrix-spa</code>).</li>
      <li>Call <code>GET /oauth/idp/admin-data?access_token=...</code>.</li>
    </ol>
    <p>The flag is awarded when admin-data is read with an admin-scoped token held by a
    non-admin user.</p>
  `));
});

router.get('/secret-in-js', (req, res) => {
  res.send(chal('Lab 6: Client secret in public JavaScript', `
    <p>The "confidential" client needs its <code>client_secret</code> to exchange codes,
    but the secret is embedded in the public JavaScript bundle, so it is not secret at all.</p>
    <ol>
      <li>Log in to the IdP as <a href="/oauth/login/bob">bob</a>.</li>
      <li>Authorize the <b>pentrix-client</b> (response_type=code) and approve; copy the code.</li>
      <li>Open <a href="/oauth/client/app.js">app.js</a> and copy <code>CLIENT_SECRET</code>.</li>
      <li><code>POST /oauth/idp/token</code> with <code>client_id=pentrix-client</code>,
      the stolen secret, and your code, directly (not through the client callback).</li>
    </ol>
    <p>The flag is awarded when the token endpoint is used directly with the leaked secret.</p>
  `));
});

router.get('/code-replay', (req, res) => {
  res.send(chal('Lab 7: Authorization code replay', `
    <p>Authorization codes are supposed to be single-use. This IdP never invalidates them.</p>
    <ol>
      <li>Log in to the IdP as <a href="/oauth/login/bob">bob</a>.</li>
      <li>Authorize <b>pentrix-spa</b> (response_type=code) and approve; copy the code.</li>
      <li><code>POST /oauth/idp/token</code> with <code>client_id=pentrix-spa</code> and the code, twice.</li>
    </ol>
    <p>Compare the two responses: both return valid, different access tokens. The flag is
    awarded on the second successful exchange of the same code.</p>
  `));
});

router.get('/pkce-skip', (req, res) => {
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  const href = '/oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=' + encodeURIComponent(TRUSTED_PREFIX + '/callback') +
    '&response_type=code&scope=read&code_challenge=' + challenge + '&code_challenge_method=S256';
  res.send(chal('Lab 8: PKCE downgrade', `
    <p>PKCE binds the authorization code to a secret verifier. This IdP records the
    <code>code_challenge</code> but the token endpoint never asks for the verifier.</p>
    <ol>
      <li>Log in to the IdP as <a href="/oauth/login/bob">bob</a>.</li>
      <li><a href="${esc(href)}">Authorize with a code_challenge</a> and approve; copy the code.</li>
      <li><code>POST /oauth/idp/token</code> with <code>client_id=pentrix-spa</code> and the code,
      <b>without</b> any <code>code_verifier</code>.</li>
    </ol>
    <p>The flag is awarded when a challenge-bound code is exchanged with no verifier.</p>
  `));
});

// ---------------------------------------------------------------------------
// Module index
// ---------------------------------------------------------------------------
const PATHS = {
  'redirect-bypass': 'redirect-bypass',
  'code-leak': 'code-leak',
  'no-state': 'no-state',
  'implicit': 'implicit',
  'scope-upgrade': 'scope-upgrade',
  'secret-in-js': 'secret-in-js',
  'code-replay': 'code-replay',
  'pkce-skip': 'pkce-skip',
};

router.get('/', (req, res) => {
  const me = idpUser(req);
  const c = req.session.oauth_client;
  const rows = module.exports.vulns.map((v) => {
    const done = captured(req, 'oauth', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/oauth/${PATHS[v.id]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('OAuth Flaws', `
    ${brief('Module briefing', `
      <p><b>OAuth in 30 seconds:</b> a client wants to act on your behalf. It sends you to the
      <b>identity provider (IdP)</b>, you log in and approve, and the IdP hands the client an
      <b>authorization code</b> (via your browser) which the client swaps for an
      <b>access token</b> at the token endpoint. Every step has classic failure modes, and this
      lab has all of them.</p>
      <p><b>The setup:</b> this module contains both sides. The IdP lives under
      <code>/oauth/idp/</code> (authorize, token, userinfo, log) and the flawed client under
      <code>/oauth/client/</code>. <code>${esc(TRUSTED_PREFIX)}</code> is the fictional client
      host; issued codes and tokens are shown on the approval pages because the redirect never
      resolves in your browser.</p>
      <p><b>Your two hats:</b> IdP session: ${me ? `<b>${esc(me.username)}</b>` : 'not logged in'}
      (<a href="/oauth/login/alice">alice</a> = victim, <a href="/oauth/login/bob">bob</a> = attacker,
      <a href="/oauth/login/admin">admin</a>, <a href="/oauth/logout">logout</a>).
      Client session: ${c ? `<b>${esc(c.username)}</b>` : 'not logged in'}.</p>`)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

module.exports = {
  id: 'oauth',
  name: 'OAuth Flaws',
  tagline: 'Break a miniature OAuth deployment: redirects, codes, tokens, and scopes.',
  description: 'A simulated identity provider and a flawed OAuth client in one module. Eight labs covering the classic OAuth failure modes: redirect URI validation bypass, codes leaked in logs, login CSRF from a missing state parameter, implicit-flow tokens in browser history, scope tampering, the client secret in public JavaScript, code replay, and PKCE downgrade.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'redirect-bypass',
      name: 'Redirect URI Prefix Bypass',
      difficulty: 'Medium',
      hint: 'The IdP checks redirect_uri with a naive prefix match against http://app.pentrix.lab. What string starts with that but points at an attacker host?',
      how: 'Request an authorization code with redirect_uri=http://app.pentrix.lab.evil.com/cb and watch the code go to the attacker host.',
    },
    {
      id: 'code-leak',
      name: 'Authorization Code Leaked in Server Log',
      difficulty: 'Easy',
      hint: 'Every issued code is written to /oauth/idp/log, which anyone can read. A recent login by alice is already in there.',
      how: 'Read the log, copy alice\u2019s code, and exchange it at the token endpoint with client_id=pentrix-spa.',
    },
    {
      id: 'no-state',
      name: 'Login CSRF (Missing state Parameter)',
      difficulty: 'Medium',
      hint: 'The client callback exchanges any code it is given and never validates state. Mint a code for YOUR account, then get the victim to visit the callback with it.',
      how: 'Use the attacker link generator as bob, then open the generated link in a session whose IdP user is alice.',
    },
    {
      id: 'implicit',
      name: 'Implicit Flow Token in URL Fragment',
      difficulty: 'Medium',
      hint: 'response_type=token puts the access token in the URL fragment. The in-lab browser history records full URLs, fragments included.',
      how: 'Run the implicit flow, find the token in /oauth/client/history, and call userinfo with it.',
    },
    {
      id: 'scope-upgrade',
      name: 'Scope Tampering',
      difficulty: 'Easy',
      hint: 'The authorize request takes a scope parameter and the IdP never checks whether your role allows it. Try scope=admin.',
      how: 'Authorize with scope=admin as bob, exchange the code, then read /oauth/idp/admin-data.',
    },
    {
      id: 'secret-in-js',
      name: 'Client Secret in Public JavaScript',
      difficulty: 'Easy',
      hint: 'The "confidential" client ships its secret inside /oauth/client/app.js, which anyone can download.',
      how: 'Copy CLIENT_SECRET from app.js and exchange your own code with a direct POST to the token endpoint.',
    },
    {
      id: 'code-replay',
      name: 'Authorization Code Replay',
      difficulty: 'Medium',
      hint: 'Codes are supposed to be single-use. This IdP counts uses but never invalidates the code. Exchange the same code twice.',
      how: 'POST the same code to /oauth/idp/token two times and compare the two valid tokens.',
    },
    {
      id: 'pkce-skip',
      name: 'PKCE Downgrade',
      difficulty: 'Medium',
      hint: 'The authorize endpoint accepts code_challenge, but the token endpoint never requires the code_verifier. Exchange a bound code without one.',
      how: 'Authorize with a code_challenge, then exchange the code with no code_verifier parameter.',
    },
  ],
  router,
};
