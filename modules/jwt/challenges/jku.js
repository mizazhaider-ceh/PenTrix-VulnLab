'use strict';
// Untrusted jku Key Server: GET/POST /jku supports federated signers by
// fetching the jku URL from the token header with no allowlist, then trusting
// the keys it finds. The attacker key-server helper routes live in the module
// index/shared file, not here.
const express = require('express');
const jwt = require('jsonwebtoken');
const { award } = require('../../../lib/flags');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');

const router = express.Router();

const PORT = process.env.PORT || 3000;

// --- helpers ---
function b64uDecode(seg) {
  return JSON.parse(Buffer.from(String(seg), 'base64url').toString('utf8'));
}
function decodeFull(token) {
  const parts = String(token || '').trim().split('.');
  if (parts.length !== 3) return null;
  try {
    return { header: b64uDecode(parts[0]), claims: b64uDecode(parts[1]) };
  } catch (e) {
    return null;
  }
}
function tokenForm(action, note) {
  return `
    <form method="POST" action="${esc(action)}">
      <label>Paste a JWT:<br />
      <textarea class="clay-input" name="token" rows="5" cols="72" placeholder="eyJhbGciOi..."></textarea></label><br /><br />
      <button type="submit" class="clay-btn clay-btn-primary">Submit token</button>
    </form>
    ${note || ''}`;
}
function denied(title, msg) {
  return page(title, `
    <h2>Access denied</h2>
    <div class="warn"><p>${msg}</p></div>
    <p><a href="/jwt">Back to the JWT module</a></p>`);
}

// GET /jku -> the admin panel demo page for the jku challenge.
router.get('/jku', (req, res) => {
  const jkuUrl = `http://localhost:${PORT}/jwt/attacker-keys/jwks?kid=evil`;
  res.send(page('Admin panel (jku)', `
    <div class="brief">
      <h2>Admin panel</h2>
      <p>This endpoint supports federated signers: if a token carries a
      <code>jku</code> header, the server fetches that URL, reads the JSON Web Key
      Set, and verifies the token with the published key. No allowlist.</p>
    </div>
    ${tokenForm('/jwt/jku', `
      <p class="note">You can run your own key server at
      <a href="/jwt/attacker-keys">/jwt/attacker-keys</a> and register a kid and
      secret there. Think about what a token would have to say to send this
      verifier to your server instead of the real one.</p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

// POST /jku -> fetch the token's jku URL, verify with the published key.
router.post('/jku', async (req, res) => {
  const token = String(req.body.token || '').trim();
  const d = decodeFull(token);
  let claims = null;
  if (d && typeof d.header.jku === 'string' && d.header.jku.length > 0) {
    try {
      // VULN: the jku URL is fetched with no allowlist, so the attacker can
      // point it at their own key server and supply the verifying key.
      const r = await fetch(d.header.jku);
      const jwks = await r.json();
      const entry = (jwks.keys || []).find((k) => k.kty === 'oct' && k.kid === d.header.kid);
      if (entry && entry.k) {
        const secret = Buffer.from(entry.k, 'base64url');
        claims = jwt.verify(token, secret, { algorithms: ['HS256'] });
      }
    } catch (e) { /* fetch or verification failed */ }
  }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'jku');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>The server fetched your <code>jku</code> URL and verified your token
      with the key you published.</p>
      ${flagBox(flag)}
      ${fixPanel('jwt', 'jku')}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'jku fetch failed, key not found, signature invalid, or role is not admin.'));
});

module.exports = {
  vuln: {
    id: 'jku',
    name: 'Untrusted jku Key Server',
    difficulty: 'Hard',
    hint: 'The server fetches whatever URL the jku header names and trusts the keys it finds. You run a key server in this lab.',
    hints: ["The jku header is a URL. Who controls that URL? Think about which requests you can watch in the Proxy tab.", "This lab gives you a key server of your own at /jwt/attacker-keys. Publish a key there and think about how a token could send the verifier to fetch it.", "Shape: a key published under a kid of your choosing on a server you control, plus a token whose header names that location and that kid, signed to match what you published. The server fetches the keys itself; watch Proxy for its request."],
    tools: "BZ, N, C",
    est: 'about 20 to 35 minutes',
    how: 'The verifier downloads its verification keys from a URL named inside the token itself, and never asks whether that URL belongs to the real issuer.',
    link: '/jwt#jku',
    start: 'In Burp, route the lab traffic through Proxy and browse to /jwt/attacker-keys to see the in-lab key server. Publish a key there, then send the token submit for /jwt/jku to Repeater and work from there.',
  },
  router,
};
