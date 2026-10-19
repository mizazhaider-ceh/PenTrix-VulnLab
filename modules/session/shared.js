'use strict';
// Shared session-module helpers (moved from the old modules/session/router.js).
// The session cookie name lab_sid is shared across the six labs so techniques
// transfer between them; each lab keeps its own server-side session store.
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { esc, page } = require('../../lib/page');

const COOKIE = 'lab_sid';

function genSid() {
  return crypto.randomBytes(16).toString('hex');
}

function setSid(res, sid) {
  // The session cookie is readable by JavaScript, mirroring the lab posture
  // for cookie-theft demos.
  res.cookie(COOKIE, sid, { httpOnly: false, path: '/' });
}

function sidOf(req) {
  return req.cookies ? req.cookies[COOKIE] : undefined;
}

function checkCreds(username, password) {
  const db = getDb();
  return db.prepare('SELECT username, role FROM users WHERE username = ? AND password = ?')
    .get(String(username || ''), String(password || ''));
}

function denied(msg) {
  return page('Denied', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">!</span><b>Acme Portal</b><span class="dim">Access denied</span></div>
      <h2>Access denied</h2>
      <div class="warn"><p>${esc(msg)}</p></div>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session">Back to the Session module</a></p>
    </section>`);
}

module.exports = { COOKIE, genSid, setSid, sidOf, checkCreds, denied };
