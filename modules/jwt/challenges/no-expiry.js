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
  hint: 'The leaked admin token expired an hour ago. What would have to happen, inside the verifier, for that to matter?',
  hints: ["Proxy on, open the /jwt/noexpiry page and find the leaked admin token in the response. It expired an hour ago, so it should be useless.", "Submit that token in the page form, or send the POST to Repeater and replay it there. Watch the response: does the server check the exp claim?", "Shape: the leaked token, unchanged. If it is accepted as-is, nothing in the verifier ever compared its expiry with the current time."],
  tools: 'BZ, B',
  est: 'about 5 to 10 minutes',
  how: 'A token carries an expiry time the verifier never enforces, so yesterday\'s token keeps working today.',
  link: '/jwt#no-expiry',
  start: 'Open /jwt/noexpiry in the Burp browser with Proxy on and copy the leaked token from the page.',
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
