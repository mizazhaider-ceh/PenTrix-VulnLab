// IDOR (Broken Access Control) module for the PenTrix VulnLab.
// Seeded users: admin (id 1), alice (id 2), bob (id 3). Orders belong to alice and bob.
const express = require('express');
const router = express.Router();

const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

// ---------- auth helpers ----------

function currentUser(req) {
  return req.session && req.session.user ? req.session.user : null;
}

function authBar() {
  const u = arguments[0];
  if (!u) {
    return '<p class="muted">You are not logged in. ' +
      'Use a quick-login button below.</p>';
  }
  return '<p>Logged in as <strong>' + esc(u.username) + '</strong> ' +
    '(id ' + Number(u.id) + ', role <code>' + esc(u.role) + '</code>) ' +
    '&middot; <a href="/idor/logout">log out</a></p>';
}

// ---------- quick login / logout ----------

router.get('/login/:who', (req, res) => {
  const who = req.params.who.toLowerCase();
  const db = getDb();
  const row = db.prepare('SELECT id, username, role FROM users WHERE username = ?').get(who);
  if (!row) {
    return res.status(404).send(page('Login failed',
      '<h1>Login failed</h1><p class="muted">No such user: ' + esc(req.params.who) + '</p>' +
      '<p><a href="/idor">Back to the module index</a></p>'));
  }
  req.session.user = { id: row.id, username: row.username, role: row.role };
  res.redirect('/idor');
});

router.get('/logout', (req, res) => {
  if (req.session) delete req.session.user;
  res.redirect('/idor');
});

// ---------- v1: user profiles ----------

router.get('/users/:id', (req, res) => {
  const u = currentUser(req);
  const db = getDb();
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    return res.status(400).send(page('Bad request',
      '<h1>Bad request</h1><p class="muted">User id must be a number.</p>'));
  }
  // VULN: profile is fetched by id with no ownership check. Any logged-in user
  // can read any other user's record, including the secret field.
  const row = db.prepare('SELECT id, username, role, secret FROM users WHERE id = ?').get(id);
  if (!row) {
    return res.status(404).send(page('Not found',
      '<h1>Not found</h1><p class="muted">No user with id ' + esc(req.params.id) + '.</p>'));
  }
  let flagHtml = '';
  if (u && (u.id !== row.id)) {
    // Award: viewing a profile that is not your own.
    const flag = award(req, 'idor', 'profile');
    flagHtml = flagBox(flag);
  }
  res.send(page('User profile #' + row.id,
    '<h1>User profile</h1>' + authBar(u) +
    '<table>' +
    '<tr><th>ID</th><td>' + Number(row.id) + '</td></tr>' +
    '<tr><th>Username</th><td>' + esc(row.username) + '</td></tr>' +
    '<tr><th>Role</th><td>' + esc(row.role) + '</td></tr>' +
    '<tr><th>Secret</th><td><code>' + esc(row.secret) + '</code></td></tr>' +
    '</table>' + flagHtml +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- v2: orders ----------

router.get('/orders/:id', (req, res) => {
  const u = currentUser(req);
  const db = getDb();
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    return res.status(400).send(page('Bad request',
      '<h1>Bad request</h1><p class="muted">Order id must be a number.</p>'));
  }
  // VULN: order is fetched by id with no ownership check. Any logged-in user
  // can read any other user's order by guessing or incrementing the id.
  const row = db.prepare('SELECT id, user_id, item, total, address FROM orders WHERE id = ?').get(id);
  if (!row) {
    return res.status(404).send(page('Not found',
      '<h1>Not found</h1><p class="muted">No order with id ' + esc(req.params.id) + '.</p>'));
  }
  let flagHtml = '';
  if (u && (u.id !== row.user_id)) {
    // Award: viewing an order that belongs to someone else.
    const flag = award(req, 'idor', 'order');
    flagHtml = flagBox(flag);
  }
  res.send(page('Order #' + row.id,
    '<h1>Order #' + Number(row.id) + '</h1>' + authBar(u) +
    '<table>' +
    '<tr><th>Order ID</th><td>' + Number(row.id) + '</td></tr>' +
    '<tr><th>Owner (user_id)</th><td>' + Number(row.user_id) + '</td></tr>' +
    '<tr><th>Item</th><td>' + esc(row.item) + '</td></tr>' +
    '<tr><th>Total</th><td>' + esc(String(row.total)) + '</td></tr>' +
    '<tr><th>Shipping address</th><td>' + esc(row.address) + '</td></tr>' +
    '</table>' + flagHtml +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- v3: admin panel ----------

router.get('/admin', (req, res) => {
  const u = currentUser(req);
  // VULN: the panel only checks that a session exists; it never checks the
  // user's role, so any logged-in user can open the admin panel.
  if (!u) {
    return res.status(401).send(page('Admin panel',
      '<h1>Admin panel</h1><p class="muted">You must be logged in to view this page. ' +
      '<a href="/idor">Log in via the module index</a>.</p>'));
  }
  const db = getDb();
  const users = db.prepare('SELECT id, username, role FROM users').all();
  const orders = db.prepare('SELECT id, user_id, item, total, address FROM orders').all();
  let flagHtml = '';
  if (u.role !== 'admin') {
    // Award: a non-admin user reached the admin panel.
    const flag = award(req, 'idor', 'admin');
    flagHtml = flagBox(flag);
  }
  const userRows = users.map(x =>
    '<tr><td>' + Number(x.id) + '</td><td>' + esc(x.username) + '</td><td>' +
    esc(x.role) + '</td></tr>').join('');
  const orderRows = orders.map(x =>
    '<tr><td>' + Number(x.id) + '</td><td>' + Number(x.user_id) + '</td><td>' +
    esc(x.item) + '</td><td>' + esc(String(x.total)) + '</td></tr>').join('');
  res.send(page('Admin panel',
    '<h1>Admin panel</h1>' + authBar(u) + flagHtml +
    '<h2>All users</h2><table><tr><th>ID</th><th>Username</th><th>Role</th></tr>' +
    userRows + '</table>' +
    '<h2>All orders</h2><table><tr><th>ID</th><th>User ID</th><th>Item</th><th>Total</th></tr>' +
    orderRows + '</table>' +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- module index ----------

router.get('/', (req, res) => {
  const u = currentUser(req);
  const vulnList = [
    { id: 'profile', route: '/idor/users/1', label: '/idor/users/:id' },
    { id: 'order', route: '/idor/orders/1', label: '/idor/orders/:id' },
    { id: 'admin', route: '/idor/admin', label: '/idor/admin' },
  ].map(v => {
    const meta = idorMeta.vulns.find(x => x.id === v.id);
    return '<li><a href="' + v.route + '"><code>' + esc(v.label) + '</code></a> ' +
      '&mdash; <strong>' + esc(meta.name) + '</strong> [' + esc(meta.difficulty) + ']<br>' +
      hintBox(meta.hint) + '</li>';
  }).join('');

  const loginButtons =
    '<a class="btn" href="/idor/login/alice">Log in as alice</a> ' +
    '<a class="btn" href="/idor/login/bob">Log in as bob</a> ' +
    '<a class="btn" href="/idor/login/admin">Log in as admin</a> ' +
    '<a class="btn" href="/idor/logout">Log out</a>';

  const samples =
    '<ul>' +
    '<li><a href="/idor/users/1"><code>/idor/users/1</code></a> (admin profile)</li>' +
    '<li><a href="/idor/users/2"><code>/idor/users/2</code></a> (alice profile)</li>' +
    '<li><a href="/idor/users/3"><code>/idor/users/3</code></a> (bob profile)</li>' +
    '<li><a href="/idor/orders/1"><code>/idor/orders/1</code></a></li>' +
    '<li><a href="/idor/orders/2"><code>/idor/orders/2</code></a></li>' +
    '<li><a href="/idor/admin"><code>/idor/admin</code></a></li>' +
    '</ul>';

  res.send(page('Broken Access Control',
    brief('Broken Access Control (IDOR)',
      '<p>This module has broken access control: several endpoints identify a ' +
      'resource by its id but never check whether you are allowed to see it. ' +
      'Log in as a normal user, then try changing ids in the URL.</p>') +
    '<h2>Session</h2>' + authBar(u) + loginButtons +
    '<h2>Challenges</h2><ul>' + vulnList + '</ul>' +
    '<h2>Try these URLs</h2>' + samples));
});

// ---------- exports ----------

// NOTE: named const (not `const exports = ...`) so the file stays valid
// CommonJS inside Node's module wrapper, which already declares `exports`.
const idorMeta = {
  id: 'idor',
  name: 'Broken Access Control',
  tagline: 'Change the id in the URL and read someone else\'s data.',
  description: 'Broken access control lets a normal user reach other users\' ' +
    'profiles, orders, and even the admin panel, just by guessing ids in the ' +
    'URL. This module teaches Insecure Direct Object Reference (IDOR) ' +
    'through genuinely unprotected endpoints.',
  difficulty: 'Beginner',
  vulns: [
    { id: 'profile', name: 'Profile IDOR', difficulty: 'Easy',
      hint: 'Log in as alice (id 2), then open a different user id in the URL, e.g. /idor/users/1.',
      how: 'Change the :id in /idor/users/:id to another user and read their secret.' },
    { id: 'order', name: 'Order IDOR', difficulty: 'Easy',
      hint: 'Log in as bob, then open /idor/orders/1 (which belongs to alice) and compare.',
      how: 'Change the :id in /idor/orders/:id to an order that is not yours.' },
    { id: 'admin', name: 'Unprotected Admin Panel', difficulty: 'Easy',
      hint: 'The admin panel only checks "logged in", not your role. Log in as alice or bob and visit /idor/admin.',
      how: 'Log in as any non-admin user and open /idor/admin.' },
  ],
  router,
};

module.exports = idorMeta;
