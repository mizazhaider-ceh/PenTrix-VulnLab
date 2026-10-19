'use strict';
// JWT Attacks: module-scoped helpers shared by the challenge files. No routes,
// no award() calls. Logic copied from modules/jwt/router.js so the split
// challenge files behave exactly as the combined router did.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { esc, page } = require('../../lib/page');

const WEAK_SECRET = 'secret123';      // VULN lab 2: guessable HMAC secret

// VULN lab 5: RSA key pair generated at boot; the public half is published and
// later misused as an HMAC secret.
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUB_PEM = publicKey.export({ type: 'spki', format: 'pem' });
const PRIV_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });

// --------------------------------------------------------------- small tools
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

// Sample tokens minted at boot for the demos, exactly as in the module router.
const sampleRsGuest = jwt.sign({ user: 'guest', role: 'user' }, PRIV_PEM, { algorithm: 'RS256', header: { kid: 'rsa-main' } });
const expiredAdminToken = jwt.sign(
  { user: 'admin', role: 'admin', exp: Math.floor(Date.now() / 1000) - 3600 },
  WEAK_SECRET,
  { algorithm: 'HS256' }
);

module.exports = {
  WEAK_SECRET,
  PUB_PEM,
  decodeFull,
  tokenForm,
  denied,
  sampleRsGuest,
  expiredAdminToken,
};
