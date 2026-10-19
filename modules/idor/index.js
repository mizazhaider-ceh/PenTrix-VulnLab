'use strict';
// Broken Access Control (IDOR): a small fictional store whose endpoints trust ids from the client.
const express = require('express');
const { getDb } = require('../../lib/db');
const { fixCta, brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill } = require('../../lib/page');
const { currentUser, deny } = require('./shared');

const challenges = [
  require('./challenges/profile'),
  require('./challenges/admin'),
  require('./challenges/idor-download'),
  require('./challenges/idor-email-change'),
  require('./challenges/idor-apikey-regen'),
  require('./challenges/function-browse'),
  require('./challenges/idor-comment-delete'),
];

const router = express.Router();
// Router-scoped form parsing (the app also parses globally; harmless).
router.use(express.urlencoded({ extended: false }));

// GET /idor/login/:who -> quick login for lab convenience. Module-level demo
// login, not a challenge: it lets students start without a password form.
router.get('/login/:who', (req, res) => {
  const who = req.params.who.toLowerCase();
  const row = getDb().prepare('SELECT id, username, role FROM users WHERE username = ?').get(who);
  if (!row) {
    return deny(res, 404, 'Sign in failed', '<p class="muted">No such member: ' + esc(req.params.who) + '</p>');
  }
  req.session.user = { id: row.id, username: row.username, role: row.role };
  res.redirect('/idor');
});

router.get('/logout', (req, res) => {
  if (req.session) delete req.session.user;
  res.redirect('/idor');
});

// GET /idor -> module index page.
router.get('/', (req, res) => {
  const u = currentUser(req);
  const who = u
    ? `Signed in as <b>${esc(u.username)}</b> (id ${Number(u.id)}, role <code>${esc(u.role)}</code>).`
    : 'You are not signed in.';
  const entry = {
    profile: '/idor/users/2',
    admin: '/idor/admin',
    'idor-download': '/idor/invoice/1',
    'idor-email-change': '/idor/account',
    'idor-apikey-regen': '/idor/apikey',
    'function-browse': '/idor/admin/users',
    'idor-comment-delete': '/idor/comments',
  };
  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(entry[v.id])}">Open the page</a></p>
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('idor', c.vuln.id)).join('')}
    </section>`;
  res.send(page('Broken Access Control', `
    ${brief('Broken Access Control (IDOR)', `
      PenShop is a tiny store with member profiles, invoices, account settings,
      API keys and a comment wall. Several of its endpoints identify a resource
      by an id but never ask whether you are allowed to touch it. Sign in as a
      normal shopper, then look closely at what your browser sends.
      Flags appear on the page itself once you have really crossed a boundary.`)}
    ${trackBanner(module.exports)}

    <h2>Session</h2>
    <p>${who}</p>
    <p>
      <a class="clay-btn clay-btn-primary clay-btn-sm" href="/idor/login/alice">Log in as alice</a>
      <a class="clay-btn clay-btn-primary clay-btn-sm" href="/idor/login/bob">Log in as bob</a>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/idor/login/admin">Log in as admin</a>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/idor/logout">Log out</a>
    </p>

    <h2>Pages in the store</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">PenShop pages</caption>
      <thead><tr><th scope="col">Page</th><th scope="col">Path</th><th scope="col">What it does</th></tr></thead>
      <tbody>
        <tr><td><a href="/idor/users/2">Member profile</a></td><td><code>/idor/users/:id</code></td><td>Shows a member's profile</td></tr>
        <tr><td><a href="/idor/invoice/1">Invoice</a></td><td><code>/idor/invoice/:id</code></td><td>Receipt for an order</td></tr>
        <tr><td><a href="/idor/account">Account settings</a></td><td><code>/idor/account</code></td><td>Change your email address</td></tr>
        <tr><td><a href="/idor/apikey">API keys</a></td><td><code>/idor/apikey</code></td><td>View, rotate and check keys</td></tr>
        <tr><td><a href="/idor/comments">Comments</a></td><td><code>/idor/comments</code></td><td>Community comment wall</td></tr>
        <tr><td><a href="/idor/admin">Admin panel</a></td><td><code>/idor/admin</code></td><td>Staff overview of members and orders</td></tr>
        <tr><td><a href="/idor/admin/users">Member directory</a></td><td><code>/idor/admin/users</code></td><td>Staff tool listing member emails</td></tr>
      </tbody>
    </table></div>

    <h2>Challenges</h2>
    <p>Seven access-control flaws hide in the pages above. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the shape of the request.</p>
    ${cards}
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'idor',
  name: 'Broken Access Control',
  tagline: 'Change the id in the URL and read someone else\'s data.',
  description: 'Broken access control lets a normal user reach other users\' ' +
    'profiles, orders, and even the admin panel, just by guessing ids in the ' +
    'URL. This module teaches Insecure Direct Object Reference (IDOR) ' +
    'through genuinely unprotected endpoints.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['misconfig'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
