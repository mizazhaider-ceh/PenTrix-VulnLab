'use strict';
// Expiry never checked: the verifier passes ignoreExpiration to jsonwebtoken,
// so a leaked admin token keeps working long after its exp claim has passed.
const express = require('express');
const jwt = require('jsonwebtoken');
const { page, brief, flagBox, fixPanel, hintLadder, payloadBlock, appShell } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'no-expiry',
  name: 'Expiry Never Checked',
  difficulty: 'Easy',
  hint: 'The leaked admin token expired an hour ago. The verifier never looks at the exp claim. Replay it.',
  hints: ["The token has an exp claim. Does the server check it?", "No. An expired admin token still works. Replay it.", "Present the expired admin token. It's accepted."],
  tools: 'B',
  how: 'Copy the expired admin token from the challenge page and submit it as-is.',
  link: '/jwt#no-expiry',
  start: 'curl -s http://localhost:3000/jwt/noexpiry',
};

// GET /jwt/noexpiry -> admin panel. Tokens carry an exp claim; the one shown
// below expired an hour ago, so it should be useless now.
router.get('/noexpiry', (req, res) => {
  res.send(page('Admin panel (expiry)', `
    ${brief('Mission brief', `Tokens here carry an <code>exp</code> claim. An old admin
      token leaked an hour ago, right around when it expired. Your goal: get the
      panel to accept a token with <code>role: "admin"</code>.`)}
    ${appShell('Nebula SSO', `
      <h2>Admin panel</h2>
      <p>Tokens carry an <code>exp</code> claim. This one expired an hour ago, so it
      should be useless now. Should it?</p>
      ${shared.tokenForm('/jwt/noexpiry', `
        ${payloadBlock('The expired admin token, exactly as leaked', shared.expiredAdminToken)}`)}
    `, { mark: '◈', crumb: 'Admin panel' })}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/jwt">Back to the JWT module</a></p>
  `));
});

// POST /jwt/noexpiry -> verify the submitted token.
router.post('/noexpiry', (req, res) => {
  let claims = null;
  try {
    // VULN: the exp claim is never enforced; expired tokens verify forever.
    claims = jwt.verify(String(req.body.token || '').trim(), shared.WEAK_SECRET, {
      algorithms: ['HS256'],
      ignoreExpiration: true,
    });
  } catch (e) { /* bad signature */ }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'no-expiry');
    return res.send(page('Admin panel', `
      ${appShell('Nebula SSO', `
        <h2>Welcome, admin</h2>
        <p>The expired token was accepted. Expiry is not enforced here.</p>
        ${flagBox(flag)}
        ${fixPanel('jwt', 'no-expiry')}
      `, { mark: '◈', crumb: 'Admin panel' })}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(shared.denied('Admin panel', 'Signature invalid or role is not admin.'));
});

module.exports = { vuln, router };
