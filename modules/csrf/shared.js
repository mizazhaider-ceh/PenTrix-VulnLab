'use strict';
// Shared helpers for the CSRF module: the fictional "Postbox" webmail chrome,
// session helpers and the login-required page. No routes, no vulns here.
const { getDb } = require('../../lib/db');
const { esc, emptyState, page } = require('../../lib/page');

function currentUser(req) {
  return req.session && req.session.user ? req.session.user : null;
}

// Email address currently stored for the logged-in user.
function emailOf(user) {
  if (!user) return '(unknown)';
  const row = getDb().prepare('SELECT email FROM users WHERE id = ?').get(user.id);
  return row && row.email ? row.email : '(unknown)';
}

// Chrome for the fictional Postbox webmail app that hosts every challenge.
// `section` is the settings area shown next to the brand; `bodyHtml` is trusted.
function postbox(section, bodyHtml) {
  return `<div class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">P</span><b>Postbox</b><span class="dim">${esc(section)}</span></div>
    <div>${bodyHtml}</div>
  </div>`;
}

// Chrome for the attacker-hosted page used to demonstrate each forgery.
function attackerSite(host, bodyHtml) {
  return `<div class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">E</span><b>${esc(host)}</b><span class="dim">attacker-controlled site</span></div>
    <div>${bodyHtml}</div>
  </div>`;
}

function backLink() {
  return '<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csrf">Back to the CSRF module</a></p>';
}

// Shown when a challenge page is opened without a session.
function notLoggedInPage(title) {
  return page(title || 'Not logged in', `
    <h1>${esc(title || 'Not logged in')}</h1>
    ${emptyState('You are not logged in',
      '<p>These pages act on the account of the logged-in user. Log in as alice, then come back.</p>',
      '<p><a class="clay-btn clay-btn-primary" href="/csrf/login/alice">Log in as alice</a></p>')}
    ${backLink()}
  `);
}

module.exports = { currentUser, emailOf, postbox, attackerSite, backLink, notLoggedInPage };
