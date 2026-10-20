'use strict';
// OAuth module: the flawed demo client side. This router owns every
// /client/* endpoint (home, callback, public JS bundle, implicit callback,
// simulated browser history). It was split out of index.js, which stays a
// thin aggregator per MODULE_CONTRACT.md; the route code below is unchanged.
const express = require('express');
const { esc, fixPanel, flagBox, page } = require('../../lib/page');
const { award } = require('../../lib/flags');
const shared = require('./shared');

const router = express.Router();

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

module.exports = router;
