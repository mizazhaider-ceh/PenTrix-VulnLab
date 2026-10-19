'use strict';
// Sessions Never Expire: sessions live for 10 years, and a decade-old
// archived admin session id is still accepted.
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'never-expires',
  name: 'Sessions Never Expire',
  difficulty: 'Easy',
  hint: 'Sessions live for 10 years here. The archive keeps a decade-old admin session, and it still works.',
  hints: ["The session lasts 10 years. What about an old archived sid?", "A leaked old sid still works. Expiry is the only thing that kills sessions.", "Use the archived admin sid from the hints. It's still valid."],
  tools: 'B, DT',
  how: 'Copy the archived admin session id, set it as your lab_sid cookie, and open the legacy admin panel.',
  link: '/session#never-expires',
  start: 'curl -s http://localhost:3000/session/neverexpires',
};

const TEN_YEARS_MS = 10 * 365 * 24 * 3600 * 1000;

// Lab-scoped session store, seeded once at load with the decade-old admin
// session (mirrors the router.js boot seed).
const legacyStore = new Map();
const LEGACY_SID = '7f3a9c1e4b2d48f0a6e5c3b9d1f7a2e4';
legacyStore.set(LEGACY_SID, { user: 'admin', role: 'admin', createdAt: Date.now() - TEN_YEARS_MS + 30 * 24 * 3600 * 1000 });

function backLink() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session">Back to the Session module</a></p>`;
}

// GET /session/neverexpires -> explains the 10-year lifetime and links the archive.
router.get('/neverexpires', (req, res) => {
  res.send(page('Sessions (never expire)', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◷</span><b>Acme Portal</b><span class="dim">Session lifetimes</span></div>
      <h2>Session lifetimes</h2>
      <p>Sessions here live for <b>10 years</b>. The operations team keeps an archive
      of old sessions "for nostalgia". One of them belongs to an admin.</p>
      <p><a class="clay-btn clay-btn-primary" href="/session/legacy-archive">Browse the session archive</a></p>
    </section>
    ${backLink()}
  `));
});

// GET /session/legacy-archive -> shows the archived admin session id.
router.get('/legacy-archive', (req, res) => {
  res.send(page('Session archive', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◷</span><b>Acme Portal</b><span class="dim">Session archive</span></div>
      <h2>Session archive</h2>
      <table class="tbl">
        <tr><th>Session id</th><th>Owner</th><th>Created</th></tr>
        <tr><td><code>${esc(LEGACY_SID)}</code></td><td>admin</td><td>2016 (10 years ago)</td></tr>
      </table>
      <p>Set your <code>lab_sid</code> cookie to the archived value and open the
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session/legacy-admin">legacy admin panel</a>.</p>
    </section>
    ${backLink()}
  `));
});

// GET /session/legacy-admin -> accepts the decade-old sid while it is under
// 10 years old, and awards the flag.
router.get('/legacy-admin', (req, res) => {
  const s = legacyStore.get(shared.sidOf(req));
  if (!s || s.role !== 'admin') {
    return res.status(403).send(shared.denied('Admins only. The archived session id is shown in the session archive.'));
  }
  const ageMs = Date.now() - s.createdAt;
  // VULN: a 10-year session lifetime means a decade-old stolen session still works.
  if (ageMs < TEN_YEARS_MS) {
    const flag = award(req, 'session', 'never-expires');
    return res.send(page('Legacy admin panel', `
      <section class="clay-card">
        <div class="card-top"><span class="orb" aria-hidden="true">◷</span><b>Acme Portal</b><span class="dim">Legacy admin panel</span></div>
        <h2>Welcome back, admin</h2>
        <p>Session age: about <b>${Math.floor(ageMs / (365 * 24 * 3600 * 1000))} years</b>.
        Still accepted, because sessions live for 10 years.</p>
        ${flagBox(flag)}
        ${fixPanel('session', 'never-expires')}
      </section>
      ${backLink()}`));
  }
  res.status(403).send(shared.denied('Session expired.'));
});

module.exports = { vuln, router };
