'use strict';
// OAuth module: the identity provider side. This router owns the demo IdP
// account helpers plus every /idp/* endpoint (authorize, approve, token,
// userinfo, log). It was split out of index.js, which stays a thin
// aggregator per MODULE_CONTRACT.md; the route code below is unchanged.
// The vulnerable grant logic itself lives in ./shared (doTokenExchange,
// redirectOk, issueCode); this file only wires HTTP to it.
const express = require('express');
const { getDb } = require('../../lib/db');
const { esc, fixPanel, flagBox, page } = require('../../lib/page');
const { award } = require('../../lib/flags');
const shared = require('./shared');

const router = express.Router();

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
      // Stamp the code with the challenge flow the session is working in,
      // so token-endpoint awards stay scoped to the issuing flow.
      flow: req.session.oauth_flow || null,
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

module.exports = router;
