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

// Cross-site evidence: true when the request carries an Origin or Referer
// header whose host differs from the Host the request was sent to. That is
// what a genuine cross-site browser request looks like (an <img> tag or a
// form on the attacker's page). A same-origin header, or no header at all,
// proves nothing: it is exactly what a student replaying the request inside
// their own session (Burp Repeater with no header tweaks, a same-origin
// form) produces, and it must never count as a forgery.
function crossSiteEvidence(req) {
  const host = String(req.get('host') || '').toLowerCase();
  if (!host) return false;
  const origin = req.get('origin');
  if (origin) {
    try { return new URL(origin).host.toLowerCase() !== host; } catch (e) { return false; }
  }
  const referer = req.get('referer');
  if (referer) {
    try { return new URL(referer).host.toLowerCase() !== host; } catch (e) { return false; }
  }
  return false;
}

// Shown when a request reached a forgery-only endpoint but carried no
// cross-site evidence, so the state change was refused or earned no flag.
function notForgedPage(challengeName, whatHappened) {
  return page(challengeName || 'No forgery detected', `
    <h1>No forgery detected</h1>
    ${postbox('Security check', `
      <p>${whatHappened}</p>
      <p class="dim">The flag only fires when the request really arrives from
      another site: forge the request with a foreign <code>Referer</code> or
      <code>Origin</code> header (in Burp Repeater, edit the header before
      re-sending), or host the attack page off this site.</p>
    `)}
    ${backLink()}
  `);
}

module.exports = { currentUser, emailOf, postbox, attackerSite, backLink, notLoggedInPage, crossSiteEvidence, notForgedPage };
