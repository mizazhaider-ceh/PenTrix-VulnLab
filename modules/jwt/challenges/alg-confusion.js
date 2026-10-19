'use strict';
// RS256 / HS256 algorithm confusion: the verifier accepts HS256 tokens and uses
// the RSA *public* key bytes as the HMAC secret, so anyone who can read the
// published public key can forge admin tokens.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { page, brief, flagBox, fixPanel, hintLadder, payloadBlock, appShell } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'alg-confusion',
  name: 'RS256 / HS256 Algorithm Confusion',
  difficulty: 'Hard',
  hint: 'The server verifies RS256 but also accepts HS256. For HS256 it needs a shared secret. Which "secret" does it use, and who else can read it?',
  hints: ["The server has an RSA public key. What if you use it as an HMAC secret?", "RS256 public key -> HS256 secret. Sign with HS256 using the public key bytes.", "Get the public key, sign {\"role\":\"admin\"} with HS256 and the public key as secret."],
  tools: 'N',
  how: 'Take the published RSA public key, use it as the HMAC secret to sign an HS256 admin token, and submit it.',
  link: '/jwt#alg-confusion',
  start: 'curl -s http://localhost:3000/jwt/confusion\ncurl -s http://localhost:3000/jwt/confusion-pubkey',
};

// GET /jwt/confusion -> admin panel. Tokens are verified with RS256, and for
// compatibility with older clients HS256 is accepted too.
router.get('/confusion', (req, res) => {
  res.send(page('Admin panel (alg confusion)', `
    ${brief('Mission brief', `This admin panel accepts JWTs verified with <code>RS256</code>,
      and still accepts older <code>HS256</code> tokens for compatibility. The RSA
      public key is published for transparency. Your goal: get the panel to accept
      a token with <code>role: "admin"</code>.`)}
    ${appShell('Nebula SSO', `
      <h2>Admin panel</h2>
      <p>This endpoint verifies tokens with <code>RS256</code> using the RSA public
      key below. It also "helpfully" accepts <code>HS256</code> tokens.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/jwt/confusion-pubkey">View the RSA public key</a></p>
      ${shared.tokenForm('/jwt/confusion', `
        ${payloadBlock('A legitimate RS256 guest token', shared.sampleRsGuest)}
        <p class="note">Think about what the server uses as the HMAC secret when
        you send <code>alg: "HS256"</code>.</p>`)}
    `, { mark: '◈', crumb: 'Admin panel' })}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/jwt">Back to the JWT module</a></p>
  `));
});

// GET /jwt/confusion-pubkey -> the RSA public key, published "for transparency".
router.get('/confusion-pubkey', (req, res) => {
  res.send(page('RSA public key', `
    ${appShell('Nebula SSO', `
      <h2>RSA public key</h2>
      <p>Published for signature verification transparency (and exploited below):</p>
      ${payloadBlock('RSA public key (PEM)', shared.PUB_PEM)}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/jwt/confusion">Back to the challenge</a></p>
    `, { mark: '◈', crumb: 'RSA public key' })}
  `));
});

// POST /jwt/confusion -> verify the submitted token.
router.post('/confusion', (req, res) => {
  const token = String(req.body.token || '').trim();
  const d = shared.decodeFull(token);
  let claims = null;
  if (d) {
    try {
      if (d.header.alg === 'HS256') {
        // VULN: the RSA *public* key bytes are used as the HMAC secret, so anyone
        // who can read the public key (it is public) can forge HS256 tokens.
        // createSecretKey mirrors the vulnerable pattern: raw key bytes as HMAC key.
        claims = jwt.verify(token, crypto.createSecretKey(Buffer.from(shared.PUB_PEM)), { algorithms: ['HS256'] });
      } else {
        claims = jwt.verify(token, shared.PUB_PEM, { algorithms: ['RS256'] });
      }
    } catch (e) { /* bad signature */ }
  }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'alg-confusion');
    return res.send(page('Admin panel', `
      ${appShell('Nebula SSO', `
        <h2>Welcome, admin</h2>
        <p>Your <code>HS256</code> token verified: the public key worked as an HMAC secret.</p>
        ${flagBox(flag)}
        ${fixPanel('jwt', 'alg-confusion')}
      `, { mark: '◈', crumb: 'Admin panel' })}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(shared.denied('Admin panel', 'Signature invalid or role is not admin.'));
});

module.exports = { vuln, router };
