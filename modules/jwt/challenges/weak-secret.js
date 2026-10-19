'use strict';
// Weak HMAC Secret: POST /jwt/weak verifies HS256 with a guessable signing secret.
const express = require('express');
const jwt = require('jsonwebtoken');
const { award } = require('../../../lib/flags');
const { esc, fixPanel, flagBox, page } = require('../../../lib/page');

const router = express.Router();
// NOTE: this router expects urlencoded form parsing (express.urlencoded) to be
// applied by the mounting index, as it was router-scoped in modules/jwt/router.js.

const WEAK_SECRET = 'secret123';      // VULN lab 2: guessable HMAC secret

// ------------------------------------------------------- page helpers (own pages)
function tokenForm(action, note) {
  return `
    <form method="POST" action="${esc(action)}">
      <div class="clay-field">
        <label for="token">Paste a JWT:</label>
        <textarea class="clay-input" id="token" name="token" rows="5" placeholder="eyJhbGciOi..."></textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Submit token</button>
    </form>
    ${note || ''}`;
}
function denied(title, msg) {
  return page(title, `
    <h2>Access denied</h2>
    <div class="warn"><p>${msg}</p></div>
    <p><a href="/jwt">Back to the JWT module</a></p>`);
}

// Sample token minted at boot for the demo, exactly as in the module router.
const sampleWeakGuest = jwt.sign({ user: 'guest', role: 'user' }, WEAK_SECRET, { algorithm: 'HS256' });

// --------------------------------------------------------- v2: weak secret
router.get('/weak', (req, res) => {
  res.send(page('Admin panel (weak secret)', `
    <h2>Admin panel</h2>
    <p>Tokens here are signed with <code>HS256</code>. The operations team swears
    the signing secret is strong. It is not.</p>
    ${tokenForm('/jwt/weak', `
      <p class="note">A legitimate guest token, signed by the server:
      <code>${esc(sampleWeakGuest)}</code><br />
      Decode it, then forge your own admin token offline once you guess the secret.</p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

router.post('/weak', (req, res) => {
  let claims = null;
  try {
    claims = jwt.verify(String(req.body.token || '').trim(), WEAK_SECRET, { algorithms: ['HS256'] });
  } catch (e) { /* bad signature */ }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'weak-secret');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>Your forged token verified against the real signing secret.</p>
      ${flagBox(flag)}
      ${fixPanel('jwt', 'weak-secret')}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Signature invalid or role is not admin.'));
});

module.exports = {
  vuln: {
    id: 'weak-secret',
    name: 'Weak HMAC Secret',
    difficulty: 'Medium',
    hint: 'HS256 security is only as strong as the secret. This one is a classic default. Guess it, then sign your own token offline.',
    hints: ["The HMAC secret is a classic default. What are the usual suspects?", "'secret', 'password', '123456'. Try them offline to sign a forged token.", "Crack the secret offline (it is a short classic default that falls to a tiny wordlist), then forge an admin token and sign it with any JWT tooling or a small script before submitting."],
    tools: "N, W",
    how: 'Recover the weak secret, mint an admin token with jsonwebtoken locally, and submit it.',
    link: '/jwt#weak-secret',
    start: 'curl -s http://localhost:3000/jwt/weak\n# decode the guest token, guess the secret, sign {"role":"admin"} offline, then:\ncurl -s -X POST --data-urlencode "token=<signed-admin-token>" http://localhost:3000/jwt/weak',
  },
  router,
};
