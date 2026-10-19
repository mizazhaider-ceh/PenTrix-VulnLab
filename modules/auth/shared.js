'use strict';
// Module-scoped helpers shared by the Broken Authentication challenges.
// No routes, no vuln. Everything here renders through the clay UI classes only.
const { getDb } = require('../../lib/db');
const { esc } = require('../../lib/page');

// Fictional product that hosts every challenge in this module.
const APP = 'Northwind Accounts';

function findUser(username) {
  return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

// Login identity shared by the auth labs (set by the login, enum-login and
// support-impersonation flows).
function authSessionUser(req) {
  return req.session && req.session.authUser ? req.session.authUser : null;
}

// In-app chrome: a clay card with the product name and the current screen.
// `body` is trusted HTML.
function portal(crumb, body, appName) {
  return `<section class="clay-card">
  <div class="card-top"><span class="orb" aria-hidden="true">N</span><b>${esc(appName || APP)}</b><span class="dim">${esc(crumb)}</span></div>
  ${body}
</section>`;
}

// One labelled form field. opts: { id, name, label, type, value, required, attrs }.
function field(opts) {
  const o = opts || {};
  const type = o.type || 'text';
  const value = o.value !== undefined && o.value !== null ? ` value="${esc(o.value)}"` : '';
  const req = o.required === false ? '' : ' required';
  const attrs = o.attrs ? ` ${o.attrs}` : '';
  return `<div class="clay-field">
    <label for="${esc(o.id)}">${esc(o.label)}</label>
    <input class="clay-input" id="${esc(o.id)}" name="${esc(o.name)}" type="${esc(type)}"${value}${req}${attrs}>
  </div>`;
}

function submitButton(label) {
  return `<button type="submit" class="clay-btn clay-btn-primary">${esc(label)}</button>`;
}

// Secondary navigation row. links: [[href, label], ...]. The module index is
// always appended so every page has a way back.
function navLinks(links) {
  const all = (links || []).concat([['/auth', 'Module index']]);
  return `<p>${all.map(([href, label]) =>
    `<a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(href)}">${esc(label)}</a>`).join(' ')}</p>`;
}

function errorLine(html) {
  return html ? `<p class="clay-err" role="alert">${html}</p>` : '';
}

module.exports = { APP, findUser, authSessionUser, portal, field, submitButton, navLinks, errorLine };
