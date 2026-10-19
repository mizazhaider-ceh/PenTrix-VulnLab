'use strict';
// PenTrix VulnLab module: OAuth Flaws (oauth) - shared IdP state and helpers.
// A miniature identity provider plus a flawed OAuth client, all inside this
// module. Deliberately broken: naive redirect_uri prefix check, issued codes
// written to a world-readable log, no state validation (login CSRF), implicit
// flow with a leaky in-lab browser history, unenforced scopes, the client
// secret shipped in public JavaScript, reusable authorization codes, and
// optional PKCE. Local lab use only.
//
// This file holds the non-route logic that used to live in router.js, kept
// identical. The challenge files require it for TRUSTED_PREFIX, idpUser,
// issueCode, tokens, bearerToken and userById; index.js uses the rest for the
// module-level IdP and client routes.
const crypto = require('crypto');
const { getDb } = require('../../lib/db');

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

module.exports = {
  TRUSTED_PREFIX, CLIENTS, codes, tokens, REQ_LOG, HISTORY,
  rid, idpUser, userById, redirectOk, bypassHost, bearerToken, logLine,
  issueCode, issueToken, doTokenExchange,
};
