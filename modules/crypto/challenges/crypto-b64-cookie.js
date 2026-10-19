'use strict';
// Base64 "Encryption": the session cookie is just base64-encoded JSON, no
// encryption at all. Decode it, change role to admin, re-encode, and the
// server accepts the forged session.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, copyButton } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'crypto-b64-cookie',
  name: 'Base64 "Encryption"',
  difficulty: 'Easy',
  hint: 'Look closely at the "encrypted" cookie. Does it look random, or does it look like something you can decode?',
  hints: ["The 'encrypted' cookie is just base64. Decode it.", "base64(username:role). Decode, change role to admin, re-encode.", "Decode your cookie, edit to admin, re-encode, and present it."],
  tools: 'B, DT',
  how: 'Decode the cookie, change role to admin in the JSON, re-encode, and submit it.',
  link: '/crypto#crypto-b64-cookie',
  start: 'curl -s -c jar -b jar -X POST http://localhost:3000/crypto/b64/login\ncurl -s -b jar http://localhost:3000/crypto/b64',
};

// In-app chrome: the challenge reads as a small real product, not a harness.
function appCard(appName, mark, crumb, body) {
  return `<section class="clay-card">
  <div class="card-top"><span class="orb" aria-hidden="true">${esc(mark)}</span><b>${esc(appName)}</b><span class="dim">${esc(crumb)}</span></div>
  ${body}
</section>`;
}

function submit(label) {
  return `<button type="submit" class="clay-btn clay-btn-primary">${esc(label)}</button>`;
}

function moduleBack() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto">Module index</a></p>`;
}

router.get('/b64', (req, res) => {
  let seen = null;
  try {
    seen = JSON.parse(Buffer.from(req.cookies.vlab_b64 || '', 'base64').toString('utf8'));
  } catch (e) { /* no/invalid cookie */ }
  res.send(page('Base64 "Encryption"',
    brief('Become the admin',
      `SnapDash keeps pages fast by packing your whole session into a cookie.
      Grab a session cookie, see what the server reads from it, and get the
      dashboard to recognize you as an admin.`) +
    appCard('SnapDash', 'S', 'Session manager', `
      <h2>Encrypted session cookie</h2>
      <p>For performance, sessions are "encrypted" into a cookie. Take a look:</p>
      <form method="POST" action="/crypto/b64/login">
        ${submit('Get a session cookie')}
      </form>
      <p>Server decodes your current cookie as: <code>${esc(seen === null ? '(no valid cookie)' : JSON.stringify(seen))}</code></p>
      <hr />
      <h3>Forge a session</h3>
      <p>Paste a modified cookie. If it decodes to JSON with
      <code>role === 'admin'</code>, you win.</p>
      <form method="POST" action="/crypto/b64/check">
        <div class="clay-field">
          <label for="cookie">Session cookie</label>
          <textarea class="clay-input" id="cookie" name="cookie" rows="3" placeholder="base64 session cookie"></textarea>
        </div>
        ${submit('Submit forged cookie')}
      </form>`) +
    hintLadder(vuln) +
    moduleBack()));
});

router.post('/b64/login', (req, res) => {
  // VULN: the "encryption" is just base64: decode it, edit the JSON, re-encode.
  const v = Buffer.from(JSON.stringify({ user: 'guest', role: 'user' }), 'utf8').toString('base64');
  res.cookie('vlab_b64', v, { httpOnly: false });
  res.send(page('Session issued',
    appCard('SnapDash', 'S', 'Session manager', `
      <h2>Session cookie issued</h2>
      <p>Your "encrypted" session (also set as <code>vlab_b64</code>):</p>
      <p><code id="ck">${v}</code> ${copyButton('Copy')}</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto/b64">Back to the challenge</a></p>`)));
});

router.post('/b64/check', (req, res) => {
  const c = (req.body.cookie || '').toString().trim();
  let data;
  try {
    data = JSON.parse(Buffer.from(c, 'base64').toString('utf8'));
  } catch (e) {
    return res.status(400).send(page('Bad cookie',
      appCard('SnapDash', 'S', 'Session manager', `
        <h2>Cookie rejected</h2>
        <p class="clay-err" role="alert">Not valid base64 JSON: <code>${esc(e.message)}</code></p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto/b64">Back</a></p>`)));
  }
  if (data && data.role === 'admin') {
    const flag = award(req, 'crypto', 'crypto-b64-cookie');
    return res.send(page('Admin session accepted',
      appCard('SnapDash', 'S', 'Session manager', `
        <h2>Welcome, admin</h2>
        <p>You decoded the cookie, flipped <code>role</code> to
        <code>admin</code>, and re-encoded it. There was never any encryption.</p>`) +
      flagBox(flag) +
      fixPanel('crypto', 'crypto-b64-cookie') +
      moduleBack()));
  }
  res.send(page('Session checked',
    appCard('SnapDash', 'S', 'Session manager', `
      <h2>Valid session, wrong role</h2>
      <p>Decoded session: <code>${esc(JSON.stringify(data))}</code>. You need
      <code>role = 'admin'</code>.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto/b64">Back</a></p>`)));
});

module.exports = { vuln, router };
