'use strict';
// JWT aud bypass: the admin panel verifies the signature but never checks the
// aud (audience) claim, so a token minted for another service is accepted here.
// Includes the token vending machine that mints signed tokens for any audience.
const express = require('express');
const jwt = require('jsonwebtoken');
const { award } = require('../../../lib/flags');
const { esc, page, flagBox, fixPanel, hintLadder, toolsPill, payloadBlock } = require('../../../lib/page');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const WEAK_SECRET = 'secret123';

// A legitimately minted partner token, shown on the challenge page. It was
// issued for billing-service, not for this app.
const partnerToken = jwt.sign(
  { user: 'partner-admin', role: 'admin', aud: 'billing-service' },
  WEAK_SECRET,
  { algorithm: 'HS256' }
);

// ------------------------------------------------------------------ helpers
function tokenForm(action, note) {
  return `
    <form method="POST" action="${esc(action)}">
      <div class="clay-field">
        <label for="token">Paste a JWT:</label>
        <textarea id="token" name="token" class="clay-input" rows="5" placeholder="eyJhbGciOi..."></textarea>
      </div>
      <button type="submit" class="clay-btn clay-btn-primary">Submit token</button>
    </form>
    ${note || ''}`;
}

function denied(title, msg) {
  return page(title, `
    <div class="card">
      <h2>Access denied</h2>
      <div class="warn"><p>${msg}</p></div>
      <p><a href="/jwt">Back to the JWT module</a></p>
    </div>`);
}

const vuln = {
  id: 'aud-bypass',
  name: 'Audience Not Validated',
  difficulty: 'Medium',
  hint: 'A token minted for billing-service is still a validly signed token. Which claim names the intended recipient, and does this service ever read it?',
  hints: ["The partner token's payload carries an aud claim for 'billing-service'. Does this app ever compare aud?", "Decode the token in Burp's Decoder (JWT tab): the aud names a different service, yet the signature verifies under a key this app trusts. A signature proves who minted a token, not who it was minted for.", "Shape: a token minted for a different audience, presented at this service unchanged. If it is accepted, the audience claim was decoration."],
  tools: "BZ, N",
  est: 'about 10 to 20 minutes',
  how: 'A valid signature is treated as enough: the service never checks that the token was actually minted for it.',
  link: '/jwt#aud-bypass',
  start: 'In Burp Proxy, browse to /jwt/aud and study the tokens the page shows you, including one minted for a partner service. Submit the login form once and send the POST to Repeater (Ctrl+R) to experiment from there.',
};

// --------------------------------------------------------------- challenge
router.get('/aud', (req, res) => {
  res.send(page('Admin panel (audience)', `
    <div class="card app-shell">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span>
        <b>Partner Token Service</b>
        <span class="app-nav"><span class="dim">Admin</span><span class="dim"> · </span><span class="dim">Vending</span><span class="dim"> · </span><span class="dim">Login</span></span>
      </div>
      <h2>Admin panel</h2>
      <p>This service accepts tokens minted for other services, as long as the
      signature is valid. Tokens carry an <code>aud</code> (audience) claim naming
      the intended service.</p>
      ${hintLadder(vuln)}
      ${toolsPill(vuln)}
      <h3>Token vending machine</h3>
      <p class="dim">Issue a signed token for any audience, exactly like the
      shared SSO issuer the partner teams use.</p>
      <form method="POST" action="/jwt/aud/mint">
        <div class="clay-field">
          <label for="aud">Audience:</label>
          <input id="aud" type="text" name="aud" class="clay-input" placeholder="audience, e.g. billing-service" required />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Mint token for that audience</button>
      </form>
      <h3>Issued for a partner</h3>
      <p class="dim">A token minted for our partner <code>billing-service</code> (admin role):</p>
      ${payloadBlock('Partner admin token (billing-service)', partnerToken)}
      <h3>Submit a token</h3>
      ${tokenForm('/jwt/aud/login')}
      <p><a href="/jwt">Back to the JWT module</a></p>
    </div>
  `));
});

router.post('/aud/mint', (req, res) => {
  const aud = String(req.body.aud || '').slice(0, 80);
  if (!aud.trim()) {
    return res.status(400).send(page('Token vending machine', `
      <div class="card"><p>Audience is required.</p><p><a href="/jwt/aud">Back</a></p></div>`));
  }
  const token = jwt.sign({ user: 'guest', role: 'user', aud }, WEAK_SECRET, { algorithm: 'HS256' });
  res.send(page('Token vending machine', `
    <div class="card app-shell">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>Partner Token Service</b></div>
      <h2>Token minted</h2>
      <p>Audience: <code>${esc(aud)}</code></p>
      ${payloadBlock('Your minted token', token)}
      <p><a href="/jwt/aud">Back to the challenge</a></p>
    </div>
  `));
});

router.post('/aud/login', (req, res) => {
  let claims = null;
  try {
    // VULN: the aud claim is never checked, so a token meant for another
    // service is accepted here.
    claims = jwt.verify(String(req.body.token || '').trim(), WEAK_SECRET, { algorithms: ['HS256'] });
  } catch (e) { /* bad signature */ }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'aud-bypass');
    return res.send(page('Admin panel', `
      <div class="card">
        <h2>Welcome, admin</h2>
        <p>Token accepted even though its audience is
        <code>${esc(claims.aud || '(none)')}</code>, not this service.</p>
        ${flagBox(flag)}
        ${fixPanel('jwt', 'aud-bypass')}
        <p><a href="/jwt">Back to the JWT module</a></p>
      </div>`));
  }
  res.status(403).send(denied('Admin panel', 'Signature invalid or role is not admin.'));
});

module.exports = { vuln, router };
