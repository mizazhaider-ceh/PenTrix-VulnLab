'use strict';
// Module-scoped helpers shared by the IDOR challenges. No routes, no vuln.
const { getDb } = require('../../lib/db');
const { esc, errorPage, page } = require('../../lib/page');

// ---------- session helpers ----------

function currentUser(req) {
  return req.session && req.session.user ? req.session.user : null;
}

// Sends a styled error page with the given HTTP status.
function deny(res, status, title, html) {
  return res.status(status).send(page(title, errorPage(status, title,
    html + '<p><a href="/idor">Back to the PenShop lab index</a></p>')));
}

// Returns the session user, or answers 401 and returns null.
function requireUser(req, res) {
  const u = currentUser(req);
  if (!u) {
    deny(res, 401, 'Sign in required',
      '<p class="muted">Sign in as one of the demo shoppers on the lab index first.</p>');
    return null;
  }
  return u;
}

// ---------- seeded tables ----------

function ensureIdorTables() {
  const db = getDb();
  db.exec(`CREATE TABLE IF NOT EXISTS idor_invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    ref TEXT NOT NULL, body TEXT NOT NULL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS idor_apikeys (
    user_id INTEGER PRIMARY KEY, api_key TEXT NOT NULL)`);
  // Remembers which keys were rotated for someone else (through the IDOR),
  // so that merely reusing a key you were shown does not count as the exploit.
  db.exec(`CREATE TABLE IF NOT EXISTS idor_apikey_rotations (
    api_key TEXT PRIMARY KEY, via_idor INTEGER NOT NULL)`);
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
  if (db.prepare('SELECT COUNT(*) AS c FROM idor_apikeys').get().c === 0) {
    const ins = db.prepare('INSERT INTO idor_apikeys (user_id, api_key) VALUES (?,?)');
    ins.run(idOf('admin'), 'idor_admin_key_9f8e7d6c5b4a');
    ins.run(idOf('alice'), 'idor_alice_key_1a2b3c4d5e6f');
    ins.run(idOf('bob'), 'idor_bob_key_0f9e8d7c6b5a');
  }
  ensureComments();
}

// The shared comments table also feeds other modules. Make sure alice and
// bob always have one comment, so the delete lab can be replayed.
function ensureComments() {
  const db = getDb();
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

// ---------- page chrome ----------

function ownInvoiceId(u) {
  const row = getDb().prepare('SELECT id FROM idor_invoices WHERE user_id = ? ORDER BY id LIMIT 1').get(u.id);
  return row ? row.id : null;
}

// PenShop: the fictional store these pages belong to. Header card with the
// member badge and navigation, then the page content.
function shopPage(u, title, inner) {
  let nav;
  let badge;
  if (u) {
    const links = [['My profile', '/idor/users/' + Number(u.id)]];
    const inv = ownInvoiceId(u);
    if (inv) links.push(['Invoices', '/idor/invoice/' + inv]);
    links.push(['Account', '/idor/account'], ['API keys', '/idor/apikey'], ['Comments', '/idor/comments']);
    if (u.role === 'admin') links.push(['Admin', '/idor/admin']);
    nav = links.map(([label, href]) => `<a href="${href}">${esc(label)}</a>`).join('<span class="dim"> &middot; </span>');
    badge = `<span class="clay-pill">${esc(u.username)} &middot; ${esc(u.role)}</span>` +
      ' <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/idor/logout">Sign out</a>';
  } else {
    nav = '<a href="/idor">Sign in</a>';
    badge = '<span class="clay-pill">Guest</span>';
  }
  return page(title, `
    <div class="clay-card">
      <div class="card-top"><b>PenShop</b><span>${badge}</span></div>
      <p>${nav}</p>
    </div>
    <h1>${esc(title)}</h1>
    ${inner}
    <p class="dim"><a href="/idor">Back to the PenShop lab index</a></p>
  `);
}

// Simple two-column table of label/value pairs. Values are trusted HTML.
function kvTable(caption, rows) {
  const body = rows.map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${v}</td></tr>`).join('');
  return `<div class="tbl-scroll"><table class="tbl">
    <caption class="sr-only">${esc(caption)}</caption>
    <thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead>
    <tbody>${body}</tbody>
  </table></div>`;
}

module.exports = { currentUser, deny, requireUser, ensureComments, shopPage, kvTable };
