'use strict';
// Weak HMAC Secret: POST /jwt/weak verifies HS256 with a guessable signing secret.
const express = require('express');
const jwt = require('jsonwebtoken');
const { award } = require('../../../lib/flags');
const { esc, fixPanel, flagBox, page } = require('../../../lib/page');

const router = express.Router();
// NOTE: this router expects urlencoded form parsing (express.urlencoded) to be
// applied by the mounting index, as it was router-scoped in modules/jwt/router.js.

// VULN: tokens are signed and verified with a weak, guessable shared secret,
// so anyone who guesses it can forge a valid admin token offline.
const WEAK_SECRET = 'secret123';      // the guessable HMAC secret

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
    hints: ["The HMAC secret is a classic default. What are the usual suspects?", "Sign the same admin claims with each candidate secret, then feed the signed tokens to Intruder as a sniper payload list on the token field.", "In Intruder, grep every response for the success marker. The candidate whose response welcomes you as admin used the right secret."],
    tools: "BZ, N, W",
    est: 'about 10 to 20 minutes',
    how: 'HS256 is only as strong as its secret, and this secret is the kind developers leave behind in tutorials and test configs.',
    link: '/jwt#weak-secret',
    start: 'Browse to /jwt/weak with Burp running. Decode the sample token, intercept the token submit, and send it to Repeater or Intruder so you can test candidate tokens quickly once you start guessing secrets offline.',
  },
  router,
};
