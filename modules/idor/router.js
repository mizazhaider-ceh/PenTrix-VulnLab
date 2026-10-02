// IDOR (Broken Access Control) module for the PenTrix VulnLab.
// Seeded users: admin (id 1), alice (id 2), bob (id 3). Orders belong to alice and bob.
const express = require('express');
const crypto = require('crypto');
const router = express.Router();
// Router-scoped form parsing (the app also parses globally; harmless).
router.use(express.urlencoded({ extended: false }));

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

// ---------- new labs: seeded tables ----------

function idorHint(id) {
  const m = idorMeta.vulns.find((x) => x.id === id);
  return m ? hintBox(m.hint) : '';
}

function ensureIdorTables() {
  const db = getDb();
  db.exec(`CREATE TABLE IF NOT EXISTS idor_invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    ref TEXT NOT NULL, body TEXT NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS idor_carts (
    user_id INTEGER NOT NULL, item TEXT NOT NULL, qty INTEGER NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS idor_apikeys (
    user_id INTEGER PRIMARY KEY, api_key TEXT NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS idor_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    label TEXT NOT NULL, address TEXT NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS idor_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    title TEXT NOT NULL, body TEXT NOT NULL)`);
  const idOf = (n) => db.prepare('SELECT id FROM users WHERE username = ?').get(n).id;

  if (db.prepare('SELECT COUNT(*) AS c FROM idor_invoices').get().c === 0) {
    const ins = db.prepare('INSERT INTO idor_invoices (user_id, ref, body) VALUES (?,?,?)');
    ins.run(idOf('alice'), 'INV-2026-001',
      'Invoice INV-2026-001\nBilled to: alice (alice@pentrix.lab)\nItem: PenTrix Hoodie\nTotal: 39.99 EUR\nStatus: PAID');
    ins.run(idOf('bob'), 'INV-2026-002',
      'Invoice INV-2026-002\nBilled to: bob (bob@pentrix.lab)\nItem: Sticker Pack\nTotal: 4.99 EUR\nStatus: PAID');
    ins.run(idOf('admin'), 'INV-2026-003',
      'Invoice INV-2026-003\nBilled to: admin (admin@pentrix.lab)\nItem: USB Rubber Ducky (Training)\nTotal: 79.99 EUR\nStatus: PAID');
  }
  if (db.prepare('SELECT COUNT(*) AS c FROM idor_carts').get().c === 0) {
    const ins = db.prepare('INSERT INTO idor_carts (user_id, item, qty) VALUES (?,?,?)');
    ins.run(idOf('alice'), 'PenTrix Hoodie', 1);
    ins.run(idOf('alice'), 'Sticker Pack', 3);
    ins.run(idOf('bob'), 'USB Rubber Ducky (Training)', 1);
    ins.run(idOf('admin'), 'Bug Bounty Field Notes', 5);
  }
  if (db.prepare('SELECT COUNT(*) AS c FROM idor_apikeys').get().c === 0) {
    const ins = db.prepare('INSERT INTO idor_apikeys (user_id, api_key) VALUES (?,?)');
    ins.run(idOf('admin'), 'idor_admin_key_9f8e7d6c5b4a');
    ins.run(idOf('alice'), 'idor_alice_key_1a2b3c4d5e6f');
    ins.run(idOf('bob'), 'idor_bob_key_0f9e8d7c6b5a');
  }
  if (db.prepare('SELECT COUNT(*) AS c FROM idor_addresses').get().c === 0) {
    const ins = db.prepare('INSERT INTO idor_addresses (user_id, label, address) VALUES (?,?,?)');
    ins.run(idOf('alice'), 'Home', '123 Hacker Lane, Brussels');
    ins.run(idOf('bob'), 'Home', '456 Binary Blvd, Antwerp');
    ins.run(idOf('admin'), 'Office', '1 Root Street, Ghent (do not share)');
  }
  if (db.prepare('SELECT COUNT(*) AS c FROM idor_notes').get().c === 0) {
    const ins = db.prepare('INSERT INTO idor_notes (user_id, title, body) VALUES (?,?,?)');
    ins.run(idOf('alice'), 'Shopping list', 'eggs, milk, nmap cheat sheet');
    ins.run(idOf('bob'), 'Todo', 'finish lab 3, water the plants');
    ins.run(idOf('admin'), 'Vault code', 'Server room code is 4815. Change it soon.');
  }
  // Extra comments so the delete lab has other users' comments to target.
  if (db.prepare("SELECT COUNT(*) AS c FROM comments WHERE author = 'alice'").get().c === 0) {
    db.prepare('INSERT INTO comments (author, body) VALUES (?,?)')
      .run('alice', 'Alice here. These labs are great.');
  }
  if (db.prepare("SELECT COUNT(*) AS c FROM comments WHERE author = 'bob'").get().c === 0) {
    db.prepare('INSERT INTO comments (author, body) VALUES (?,?)')
      .run('bob', 'Bob was here. Hello from Antwerp.');
  }
}
ensureIdorTables();

// ---------- v4: invoice download ----------

router.get('/invoice/:id', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    return res.status(400).send(page('Bad request',
      '<h1>Bad request</h1><p class="muted">Invoice id must be a number.</p>'));
  }
  // VULN: the invoice is served by id with no ownership check, so any
  // logged-in user can download anyone else's invoice.
  const row = getDb().prepare('SELECT * FROM idor_invoices WHERE id = ?').get(id);
  if (!row) {
    return res.status(404).send(page('Not found',
      '<h1>Not found</h1><p class="muted">No invoice with id ' + esc(req.params.id) + '.</p>'));
  }
  let flagHtml = '';
  if (u.id !== row.user_id) {
    // Award: downloading an invoice that belongs to someone else.
    const flag = award(req, 'idor', 'idor-download');
    flagHtml = flagBox(flag);
  }
  res.send(page('Invoice ' + row.ref,
    '<h1>Invoice ' + esc(row.ref) + '</h1>' + authBar(u) +
    '<pre>' + esc(row.body) + '</pre>' + flagHtml +
    '<p class="muted">Owner user_id: ' + Number(row.user_id) +
    '. Try /idor/invoice/1, /idor/invoice/2, /idor/invoice/3.</p>' +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- v5: email change ----------

router.get('/account', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const row = getDb().prepare('SELECT id, username, email FROM users WHERE id = ?').get(u.id);
  res.send(page('Account settings',
    '<h1>Account settings</h1>' + authBar(u) +
    '<p>Username: <strong>' + esc(row.username) + '</strong><br>' +
    'Email: <strong>' + esc(row.email) + '</strong></p>' +
    '<h2>Change email</h2>' +
    '<form method="POST" action="/idor/account/email">' +
    '<label>User ID<br><input name="user_id" value="' + Number(u.id) + '"></label><br><br>' +
    '<label>New email<br><input name="email" type="email" required></label><br><br>' +
    '<button type="submit">Update email</button></form>' +
    '<p class="muted">The user_id field is submitted by your browser, and the server trusts it.</p>' +
    idorHint('idor-email-change') +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

router.post('/account/email', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first.</p>'));
  }
  const targetId = parseInt(req.body.user_id, 10);
  const email = String(req.body.email || '').trim();
  const target = getDb().prepare('SELECT id, username FROM users WHERE id = ?').get(targetId);
  if (!target || !email) {
    return res.status(400).send(page('Bad request',
      '<h1>Bad request</h1><p class="muted">A valid user_id and email are required.</p>' +
      '<p><a href="/idor/account">Back</a></p>'));
  }
  // VULN: the target account comes from a client-supplied user_id parameter
  // with no check that it matches the logged-in user.
  getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(email, target.id);
  let flagHtml = '';
  if (target.id !== u.id) {
    // Award: changing another user's email address.
    const flag = award(req, 'idor', 'idor-email-change');
    flagHtml = flagBox(flag);
  }
  res.send(page('Email updated',
    '<h1>Email updated</h1>' + authBar(u) +
    '<p>Email for user <strong>' + esc(target.username) + '</strong> (id ' +
    Number(target.id) + ') is now <strong>' + esc(email) + '</strong>.</p>' +
    flagHtml + '<p><a href="/idor/account">Back</a></p>'));
});

// ---------- v6: cart ----------

router.get('/cart', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const qid = req.query.user_id !== undefined ? parseInt(req.query.user_id, 10) : u.id;
  const target = getDb().prepare('SELECT id, username FROM users WHERE id = ?').get(qid);
  if (!target) {
    return res.status(404).send(page('Not found',
      '<h1>Not found</h1><p class="muted">No user with id ' + esc(String(req.query.user_id)) + '.</p>'));
  }
  // VULN: the cart is looked up by a client-supplied user_id query parameter
  // with no ownership check.
  const items = getDb().prepare('SELECT item, qty FROM idor_carts WHERE user_id = ?').all(target.id);
  let flagHtml = '';
  if (target.id !== u.id) {
    // Award: viewing another user's shopping cart.
    const flag = award(req, 'idor', 'idor-cart');
    flagHtml = flagBox(flag);
  }
  const rows = items.map((x) =>
    '<tr><td>' + esc(x.item) + '</td><td>' + Number(x.qty) + '</td></tr>').join('');
  res.send(page('Shopping cart',
    '<h1>Shopping cart of ' + esc(target.username) + '</h1>' + authBar(u) +
    '<table><tr><th>Item</th><th>Qty</th></tr>' + rows + '</table>' + flagHtml +
    '<p class="muted">Try <a href="/idor/cart?user_id=1">?user_id=1</a>, ' +
    '<a href="/idor/cart?user_id=2">?user_id=2</a>, ' +
    '<a href="/idor/cart?user_id=3">?user_id=3</a>.</p>' +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- v7: api key regenerate + use ----------

router.get('/apikey', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const mine = getDb().prepare('SELECT api_key FROM idor_apikeys WHERE user_id = ?').get(u.id);
  res.send(page('API keys',
    '<h1>API keys</h1>' + authBar(u) +
    '<p>Your key: <code>' + esc(mine.api_key) + '</code></p>' +
    '<h2>Regenerate a key</h2>' +
    '<form method="POST" action="/idor/apikey/regen">' +
    '<label>User ID<br><input name="user_id" value="' + Number(u.id) + '"></label><br><br>' +
    '<button type="submit">Regenerate</button></form>' +
    '<p class="muted">Lost your key? Try it at <code>/idor/apikey/use?key=...</code>.</p>' +
    idorHint('idor-apikey-regen') +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

router.post('/apikey/regen', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first.</p>'));
  }
  const targetId = parseInt(req.body.user_id, 10);
  const target = getDb().prepare('SELECT id, username FROM users WHERE id = ?').get(targetId);
  if (!target) {
    return res.status(400).send(page('Bad request',
      '<h1>Bad request</h1><p class="muted">A valid user_id is required.</p>' +
      '<p><a href="/idor/apikey">Back</a></p>'));
  }
  // VULN: key regeneration takes a client-supplied user_id and never checks
  // that it belongs to the caller, so you can rotate anyone's key and then
  // use the fresh value yourself.
  const fresh = 'idor_' + crypto.randomBytes(12).toString('hex');
  getDb().prepare(
    'INSERT INTO idor_apikeys (user_id, api_key) VALUES (?,?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET api_key = excluded.api_key'
  ).run(target.id, fresh);
  res.send(page('Key regenerated',
    '<h1>Key regenerated</h1>' + authBar(u) +
    '<p>New API key for <strong>' + esc(target.username) + '</strong> (id ' +
    Number(target.id) + '):</p>' +
    '<pre class="token">' + esc(fresh) + '</pre>' +
    '<p><a href="/idor/apikey/use?key=' + esc(fresh) + '">Use this key</a></p>' +
    idorHint('idor-apikey-regen') +
    '<p><a href="/idor/apikey">Back</a></p>'));
});

router.get('/apikey/use', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const key = String(req.query.key || '');
  const row = getDb().prepare(
    'SELECT k.user_id, u.username FROM idor_apikeys k JOIN users u ON u.id = k.user_id WHERE k.api_key = ?'
  ).get(key);
  if (!row) {
    return res.status(401).send(page('Bad key',
      '<h1>401</h1><p class="muted">Unknown API key.</p>' +
      '<p><a href="/idor/apikey">Back</a></p>'));
  }
  let flagHtml = '';
  if (row.user_id !== u.id) {
    // Award: authenticating with another user's key, the one you regenerated
    // for them through the IDOR.
    const flag = award(req, 'idor', 'idor-apikey-regen');
    flagHtml = flagBox(flag);
  }
  res.send(page('API key check',
    '<h1>API key accepted</h1>' + authBar(u) +
    '<p>This key belongs to <strong>' + esc(row.username) + '</strong> (id ' +
    Number(row.user_id) + ').</p>' + flagHtml +
    '<p><a href="/idor/apikey">Back</a></p>'));
});

// ---------- v8: addresses ----------

router.get('/address/:id', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    return res.status(400).send(page('Bad request',
      '<h1>Bad request</h1><p class="muted">Address id must be a number.</p>'));
  }
  // VULN: the stored address is fetched by id with no ownership check.
  const row = getDb().prepare(
    'SELECT a.*, u.username FROM idor_addresses a JOIN users u ON u.id = a.user_id WHERE a.id = ?'
  ).get(id);
  if (!row) {
    return res.status(404).send(page('Not found',
      '<h1>Not found</h1><p class="muted">No address with id ' + esc(req.params.id) + '.</p>'));
  }
  let flagHtml = '';
  if (row.user_id !== u.id) {
    // Award: viewing a stored address that belongs to someone else.
    const flag = award(req, 'idor', 'idor-address');
    flagHtml = flagBox(flag);
  }
  res.send(page('Address #' + row.id,
    '<h1>Address #' + Number(row.id) + '</h1>' + authBar(u) +
    '<table>' +
    '<tr><th>Label</th><td>' + esc(row.label) + '</td></tr>' +
    '<tr><th>Owner</th><td>' + esc(row.username) + ' (id ' + Number(row.user_id) + ')</td></tr>' +
    '<tr><th>Address</th><td>' + esc(row.address) + '</td></tr>' +
    '</table>' + flagHtml +
    '<p class="muted">Try /idor/address/1, /idor/address/2, /idor/address/3.</p>' +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- v9: forced browsing to an admin function ----------

router.get('/admin/users', (req, res) => {
  const u = currentUser(req);
  // VULN: only "logged in" is checked; the admin role is never required, so
  // any user can force-browse this admin function directly.
  if (!u) {
    return res.status(401).send(page('Admin users',
      '<h1>401</h1><p class="muted">You must be logged in to view this page. ' +
      '<a href="/idor">Log in via the module index</a>.</p>'));
  }
  const users = getDb().prepare('SELECT id, username, role, email FROM users').all();
  let flagHtml = '';
  if (u.role !== 'admin') {
    // Award: a non-admin user reached an admin-only function.
    const flag = award(req, 'idor', 'function-browse');
    flagHtml = flagBox(flag);
  }
  const rows = users.map((x) =>
    '<tr><td>' + Number(x.id) + '</td><td>' + esc(x.username) + '</td><td>' +
    esc(x.role) + '</td><td>' + esc(x.email) + '</td></tr>').join('');
  res.send(page('Admin: user list',
    '<h1>Admin: user list</h1>' + authBar(u) + flagHtml +
    '<table><tr><th>ID</th><th>Username</th><th>Role</th><th>Email</th></tr>' +
    rows + '</table>' +
    '<p class="muted">This page was only supposed to be linked from the real admin panel.</p>' +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- v10: comment delete ----------

router.get('/comments', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const comments = getDb().prepare('SELECT id, author, body FROM comments ORDER BY id').all();
  const rows = comments.map((c) =>
    '<tr><td>' + Number(c.id) + '</td><td>' + esc(c.author) + '</td><td>' + esc(c.body) + '</td><td>' +
    '<form method="POST" action="/idor/comments/delete" style="display:inline">' +
    '<input type="hidden" name="id" value="' + Number(c.id) + '">' +
    '<button type="submit">Delete</button></form></td></tr>').join('');
  res.send(page('Comments',
    '<h1>Comments</h1>' + authBar(u) +
    '<table><tr><th>ID</th><th>Author</th><th>Comment</th><th></th></tr>' +
    rows + '</table>' +
    '<p class="muted">Each delete button sends only the comment id. The server never checks authorship.</p>' +
    idorHint('idor-comment-delete') +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

router.post('/comments/delete', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first.</p>'));
  }
  const id = parseInt(req.body.id, 10);
  const c = getDb().prepare('SELECT id, author FROM comments WHERE id = ?').get(id);
  if (!c) {
    return res.status(404).send(page('Not found',
      '<h1>Not found</h1><p class="muted">No comment with that id.</p>' +
      '<p><a href="/idor/comments">Back</a></p>'));
  }
  // VULN: deletion is keyed by comment id only; authorship is never checked.
  getDb().prepare('DELETE FROM comments WHERE id = ?').run(id);
  let flagHtml = '';
  if (c.author !== u.username) {
    // Award: deleting a comment written by someone else.
    const flag = award(req, 'idor', 'idor-comment-delete');
    flagHtml = flagBox(flag);
  }
  res.send(page('Comment deleted',
    '<h1>Deleted</h1>' + authBar(u) +
    '<p>Comment <b>#' + Number(c.id) + '</b> by <b>' + esc(c.author) + '</b> was deleted.</p>' +
    flagHtml + '<p><a href="/idor/comments">Back</a></p>'));
});

// ---------- v11: private notes ----------

router.get('/notes/:id', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    return res.status(401).send(page('Login required',
      '<h1>401</h1><p class="muted">Log in first via the ' +
      '<a href="/idor">module index</a>.</p>'));
  }
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    return res.status(400).send(page('Bad request',
      '<h1>Bad request</h1><p class="muted">Note id must be a number.</p>'));
  }
  // VULN: a private note is retrieved by numeric id with no ownership check.
  const row = getDb().prepare(
    'SELECT n.*, u.username FROM idor_notes n JOIN users u ON u.id = n.user_id WHERE n.id = ?'
  ).get(id);
  if (!row) {
    return res.status(404).send(page('Not found',
      '<h1>Not found</h1><p class="muted">No note with id ' + esc(req.params.id) + '.</p>'));
  }
  let flagHtml = '';
  if (row.user_id !== u.id) {
    // Award: reading a private note that belongs to someone else.
    const flag = award(req, 'idor', 'idor-notes');
    flagHtml = flagBox(flag);
  }
  res.send(page('Note: ' + row.title,
    '<h1>' + esc(row.title) + '</h1>' + authBar(u) +
    '<div class="card"><p>' + esc(row.body) + '</p></div>' + flagHtml +
    '<p class="muted">Owner: ' + esc(row.username) + ' (id ' + Number(row.user_id) + '). ' +
    'Try /idor/notes/1, /idor/notes/2, /idor/notes/3.</p>' +
    '<p><a href="/idor">Back to the module index</a></p>'));
});

// ---------- module index ----------

router.get('/', (req, res) => {
  const u = currentUser(req);
  const vulnList = [
    { id: 'profile', route: '/idor/users/1', label: '/idor/users/:id' },
    { id: 'order', route: '/idor/orders/1', label: '/idor/orders/:id' },
    { id: 'admin', route: '/idor/admin', label: '/idor/admin' },
    { id: 'idor-download', route: '/idor/invoice/1', label: '/idor/invoice/:id' },
    { id: 'idor-email-change', route: '/idor/account', label: 'POST /idor/account/email' },
    { id: 'idor-cart', route: '/idor/cart?user_id=3', label: '/idor/cart?user_id=' },
    { id: 'idor-apikey-regen', route: '/idor/apikey', label: '/idor/apikey (+ /regen, /use)' },
    { id: 'idor-address', route: '/idor/address/1', label: '/idor/address/:id' },
    { id: 'function-browse', route: '/idor/admin/users', label: '/idor/admin/users' },
    { id: 'idor-comment-delete', route: '/idor/comments', label: '/idor/comments' },
    { id: 'idor-notes', route: '/idor/notes/1', label: '/idor/notes/:id' },
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
    '<li><a href="/idor/invoice/1"><code>/idor/invoice/1</code></a> (try 2, 3)</li>' +
    '<li><a href="/idor/account"><code>/idor/account</code></a> (email change form)</li>' +
    '<li><a href="/idor/cart?user_id=3"><code>/idor/cart?user_id=3</code></a></li>' +
    '<li><a href="/idor/apikey"><code>/idor/apikey</code></a> (regen + use)</li>' +
    '<li><a href="/idor/address/1"><code>/idor/address/1</code></a> (try 2, 3)</li>' +
    '<li><a href="/idor/admin/users"><code>/idor/admin/users</code></a></li>' +
    '<li><a href="/idor/comments"><code>/idor/comments</code></a></li>' +
    '<li><a href="/idor/notes/1"><code>/idor/notes/1</code></a> (try 2, 3)</li>' +
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
    { id: 'idor-download', name: 'Invoice Download IDOR', difficulty: 'Medium',
      hint: 'Log in as alice, then open /idor/invoice/2 (bob\'s) or /idor/invoice/3 (admin\'s). The server never checks who the invoice belongs to.',
      how: 'Change the :id in /idor/invoice/:id to download someone else\'s invoice.' },
    { id: 'idor-email-change', name: 'Email Change IDOR', difficulty: 'Easy',
      hint: 'The change-email form on /idor/account submits a user_id field. Change it to 1 (admin) and set a new email.',
      how: 'POST /idor/account/email with another user\'s id in the user_id parameter.' },
    { id: 'idor-cart', name: 'Shopping Cart IDOR', difficulty: 'Easy',
      hint: 'Your cart is fetched with ?user_id=. Log in as alice and try ?user_id=1 or ?user_id=3.',
      how: 'Change the user_id query parameter on /idor/cart to view another user\'s cart.' },
    { id: 'idor-apikey-regen', name: 'API Key Regeneration IDOR', difficulty: 'Medium',
      hint: 'The regenerate form on /idor/apikey trusts the user_id you submit. Regenerate admin\'s key (id 1), then authenticate with the fresh key at /idor/apikey/use?key=....',
      how: 'Regenerate another user\'s API key via their id, then use the new key at /idor/apikey/use.' },
    { id: 'idor-address', name: 'Stored Address IDOR', difficulty: 'Easy',
      hint: 'Log in as alice, then open /idor/address/2 or /idor/address/3. Addresses are fetched by id with no ownership check.',
      how: 'Change the :id in /idor/address/:id to read another user\'s stored address.' },
    { id: 'function-browse', name: 'Forced Browsing to Admin Function', difficulty: 'Medium',
      hint: '/idor/admin/users is not linked anywhere for normal users, but nothing stops you from typing it. Log in as alice or bob and open it directly.',
      how: 'Force-browse /idor/admin/users as a non-admin user.' },
    { id: 'idor-comment-delete', name: 'Comment Deletion IDOR', difficulty: 'Easy',
      hint: 'The delete button on /idor/comments sends only the comment id. Log in as bob and delete a comment written by someone else.',
      how: 'Delete another user\'s comment by submitting its id to /idor/comments/delete.' },
    { id: 'idor-notes', name: 'Private Notes IDOR', difficulty: 'Medium',
      hint: 'Log in as alice, then open /idor/notes/2 or /idor/notes/3. Private notes are retrieved by numeric id with no ownership check.',
      how: 'Change the :id in /idor/notes/:id to read another user\'s private note.' },
  ],
  router,
};

module.exports = idorMeta;
