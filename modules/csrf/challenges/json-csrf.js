'use strict';
// JSON API CSRF via text/plain: the "JSON-only" endpoint also mines text/plain bodies, so a plain form can drive it.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, hintLadder, hintBox, toolsPill, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { currentUser, emailOf, postbox, attackerSite, backLink, notLoggedInPage } = require('../shared');

const router = express.Router();

const FORGED_BODY = '{"email":"attacker@evil.com"}';

// A cross-site <form enctype="text/plain"> is a CORS simple request (no
// preflight, cookies attached), so it can drive this "JSON" API.
router.get('/json-email', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage('Email API'));
  res.send(page('Email API', `
    <h1>Email API</h1>
    ${brief('Scenario', `
      Postbox's own web client updates your address by sending JSON to
      <code>POST /csrf/api/email</code>. The developers assumed only their own
      JavaScript could ever call it, so the endpoint has no token. Your goal:
      change <b>${esc(user.username)}</b>'s email from a page the victim opens,
      even though browsers will not let that page send a JSON request.
    `)}
    ${postbox('API console', `
      <p>Signed in as <b>${esc(user.username)}</b>. Current email:
      <code>${esc(emailOf(user))}</code></p>
      ${payloadBlock('What the Postbox client sends', 'POST /csrf/api/email\nContent-Type: application/json\n\n{"email":"new@example.com"}')}
    `)}
    ${attackerSite('evil.example', `
      <h3>Win a free upgrade</h3>
      <p>The attacker's page submits this form as soon as the victim lands on it.</p>
      <form method="POST" action="/csrf/api/email" enctype="text/plain">
        <input type="hidden" name="${esc(FORGED_BODY)}" value="ignored" />
        <button type="submit" class="clay-btn clay-btn-primary">Fire the forged request</button>
      </form>
      <p class="dim">The browser encodes the form as one <code>name=value</code> line.
      Watch what the server does with it.</p>
    `)}
    ${hintLadder(module.exports.vuln)}
    ${hintBox('Simple requests (plain forms) skip CORS preflight, so the missing token is the only thing that had to fail, and it did.')}
    ${backLink()}
  `));
});

router.post('/api/email', express.text({ type: 'text/plain' }), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage('Email API'));

  // The real client path: a genuine JSON body. A cross-site page cannot send
  // this without a CORS preflight, so it earns nothing by itself.
  if (req.is('application/json')) {
    const email = req.body && typeof req.body.email === 'string' ? req.body.email.trim() : '';
    if (!email) return res.status(400).json({ ok: false, error: 'Missing "email".' });
    getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(email, user.id);
    return res.json({ ok: true, email });
  }

  let email = null;
  try {
    // VULN: text/plain body is mined for anything shaped like a JSON object.
    const m = /\{[\s\S]*\}/.exec(String(req.body || ''));
    if (m) email = JSON.parse(m[0]).email;
  } catch (e) { /* not JSON shaped */ }
  if (!email || String(email).trim() === '') {
    return res.status(400).send(page('Email API', `
      <h1>Email API</h1>
      ${postbox('API console', '<p>No usable email found in the request body.</p>')}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csrf/json-email">Back</a></p>
    `));
  }
  // VULN: state-changing JSON API with no CSRF token, reachable by a simple form.
  getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(String(email), user.id);
  const flag = award(req, 'csrf', 'json-csrf');
  res.send(page('Email API', `
    <h1>Email changed</h1>
    ${flagBox(flag)}
    ${fixPanel('csrf', 'json-csrf')}
    ${postbox('API console', `<p>Your account email is now: <code>${esc(String(email))}</code></p>`)}
    ${toolsPill(module.exports.vuln)}
    ${backLink()}
  `));
});

module.exports = {
  vuln: {
    id: 'json-csrf',
    name: 'JSON API CSRF via text/plain (simple request)',
    difficulty: 'Medium',
    hint: 'The endpoint accepts text/plain bodies and extracts JSON from them. The key insight: a cross-site form can be a CORS "simple request" (no preflight, cookies attached), so shape a form whose submitted body content is the JSON the API expects.',
    hints: ["The API wants JSON, but it also accepts text/plain. Why does that matter for CSRF?", "text/plain POSTs are CORS 'simple requests': no preflight, cookies attached. A plain HTML form can send JSON.", "Build a cross-site form that the browser treats as a simple request, then shape its submitted body so the server parses out the JSON the email API expects."],
    tools: "BZ, C",
    how: 'Submit the text/plain form so its body carries a JSON email change to /csrf/api/email.',
    link: '/csrf/json-email',
    start: 'curl -s -c jar http://localhost:3000/csrf/login/alice\ncurl -s -b jar -X POST -H "Content-Type: application/json" -d \'{"email":"me@example.com"}\' http://localhost:3000/csrf/api/email',
  },
  router,
};
