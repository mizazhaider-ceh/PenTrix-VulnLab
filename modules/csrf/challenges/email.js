'use strict';
// Change Email with No CSRF Token: a state-changing GET that any third-party page can trigger.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, hintLadder, hintBox, toolsPill, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { currentUser, emailOf, postbox, attackerSite, backLink, notLoggedInPage } = require('../shared');

const router = express.Router();

const FORGED_URL = '/csrf/change-email?email=attacker@evil.com';

// v1: change email through a plain GET request.
// VULN: state-changing action accepts GET, so any third-party page the victim
// visits can fire it. VULN: no anti-CSRF token anywhere in the flow.
router.get('/change-email', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage('Email settings'));

  const email = req.query.email === undefined ? null : String(req.query.email);

  if (email === null) {
    return res.send(page('Email settings', `
      <h1>Email settings</h1>
      ${brief('Scenario', `
        Postbox lets you change the address on your account from the settings
        page. Whoever controls that address controls password resets, so it is
        the first thing an account thief goes after. Your goal: change
        <b>${esc(user.username)}</b>'s email without the account owner ever
        using the settings form.
      `)}
      ${postbox('Settings', `
        <p>Signed in as <b>${esc(user.username)}</b>. Current email:
        <code>${esc(emailOf(user))}</code></p>
        <form method="get" action="/csrf/change-email">
          <div class="clay-field">
            <label for="new-email">New email address</label>
            <input class="clay-input" id="new-email" name="email" type="email" placeholder="you@example.com" required />
          </div>
          <button type="submit" class="clay-btn clay-btn-primary">Save email</button>
        </form>
      `)}
      ${attackerSite('evil.example', `
        <h3>Totally harmless cat pictures</h3>
        <p>The victim only has to load this page while signed in to Postbox.
        Somewhere in its HTML sits a tag like the one below.</p>
        ${payloadBlock('Hidden tag on the attacker page', `<img src="${FORGED_URL}" width="1" height="1">`)}
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(FORGED_URL)}">Load the forged request</a></p>
      `)}
      ${hintLadder(module.exports.vuln)}
      ${backLink()}
    `));
  }

  if (email.trim() === '') {
    return res.send(page('Email settings', `
      <h1>Email settings</h1>
      ${postbox('Settings', `
        <p>The email address was empty, so nothing was changed.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csrf/change-email">Try again</a></p>
      `)}
      ${backLink()}
    `));
  }

  // VULN: state change performed over GET with no CSRF token, so a forged
  // cross-site request from any third-party page succeeds silently.
  getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(email, user.id);
  const flag = award(req, 'csrf', 'email');
  res.send(page('Email settings', `
    <h1>Email changed</h1>
    ${flagBox(flag)}
    ${fixPanel('csrf', 'email')}
    ${postbox('Settings', `
      <p>Your account email is now: <code>${esc(email)}</code></p>
    `)}
    ${hintBox('That request carried no token and did not even need a form submit. This is exactly what an attacker\'s forged link or image tag would have done from another site.')}
    ${toolsPill(module.exports.vuln)}
    ${backLink()}
  `));
});

module.exports = {
  vuln: {
    id: 'email',
    name: 'Change Email with No CSRF Token (state-changing GET)',
    difficulty: 'Easy',
    hint: 'The email change is a plain GET request with no anti-CSRF token. Any page the victim visits can trigger it: a link, an image tag, anything. The key insight: with no token required, any request carrying the logged-in cookie performs the change, so you never need the real form.',
    hints: ["The email change is a GET request with no token. In Burp Proxy, watch what the settings form actually sends.", "Any request that carries your session cookie performs the change. Send that request to Repeater and try changing the query value.", "Repeater can forge the whole attack: the browser is not needed. Or use Burp's Generate CSRF PoC tool on the captured request to build the attacker's page."],
    tools: "BZ, B",
    how: 'In Repeater, send GET /csrf/change-email with an email query parameter while carrying the logged-in session cookie. No token or confirmation is required, so the email changes immediately.',
    link: '/csrf/change-email',
    start: 'Route your browser through Burp Proxy, log in as alice, and open the Email settings page. Find the change-email GET in Proxy HTTP history, then send it to Repeater.',
  },
  router,
};
