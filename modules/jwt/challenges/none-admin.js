'use strict';
// alg=none Accepted: POST /jwt/none trusts unsigned tokens with no signature check.
const express = require('express');
const { award } = require('../../../lib/flags');
const { esc, fixPanel, flagBox, page, trackBanner } = require('../../../lib/page');

const router = express.Router();
// NOTE: this router expects urlencoded form parsing (express.urlencoded) to be
// applied by the mounting index, as it was router-scoped in modules/jwt/router.js.

// ------------------------------------------------------- page helpers (own pages)
function b64u(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}
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

// ------------------------------------------------------- v1: alg=none admin
router.get('/none', (req, res) => {
  const sample = b64u({ alg: 'none', typ: 'JWT' }) + '.' + b64u({ user: 'guest', role: 'user' }) + '.';
  res.send(page('Admin panel (alg=none)', `
    <h2>Admin panel</h2>
    <p>This endpoint checks the token's claims to decide if you are an admin.
    It supports <code>alg=none</code> for "internal" unsigned tokens.</p>
    ${tokenForm('/jwt/none', `
      <p class="note">An unsigned token looks like this (header, payload, empty
      signature): <code>${esc(sample)}</code>. Notice what it claims, and ask
      yourself what, if anything, proves those claims.</p>`)}
    ${trackBanner({ id: 'jwt' })}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

router.post('/none', (req, res) => {
  const d = decodeFull(req.body.token);
  // VULN: tokens with alg=none are trusted with no signature check at all.
  if (d && d.header.alg === 'none' && d.claims && d.claims.role === 'admin') {
    const flag = award(req, 'jwt', 'none-admin');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>An unsigned token with <code>role: "admin"</code> was accepted.</p>
      ${flagBox(flag)}
      ${fixPanel('jwt', 'none-admin')}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Token rejected. It must be a well-formed unsigned (alg=none) token with role "admin".'));
});

module.exports = {
  vuln: {
    id: 'none-admin',
    name: 'alg=none Accepted',
    difficulty: 'Easy',
    hint: 'The verifier trusts tokens with "alg": "none" and never checks a signature. What stops you from writing your own claims?',
    hints: ["The verifier trusts alg:none. Intercept the token submit in Burp Proxy and send the POST to Repeater so you can replay it fast.", "Use Burp Decoder (Smart decode) on the sample token to see the header and payload shape.", "Hand-craft an unsigned token: a base64 header claiming alg none, a base64 payload carrying admin claims, and an empty signature segment. Replay it from Repeater. The verifier never checks signatures, so your self-written claims are trusted."],
    tools: "BZ, N",
    est: 'about 5 to 10 minutes',
    how: 'The verifier accepts the none algorithm, so a token can claim anything without a signature proving anything.',
    link: '/jwt#none-admin',
    start: 'Browse to /jwt/none with Burp running. Intercept the token submit and send it to Repeater so you can replay and edit freely. Decode the sample token in Burp Decoder first to learn its shape.',
  },
  router,
};
