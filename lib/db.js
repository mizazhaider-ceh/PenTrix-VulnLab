const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'vulnlab.db');
let db = null;

function getDb() {
  if (db) return db;
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      secret TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      description TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      item TEXT NOT NULL,
      total REAL NOT NULL,
      address TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS reset_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount === 0) {
    const ins = db.prepare('INSERT INTO users (username, password, email, role, secret) VALUES (?,?,?,?,?)');
    // NOTE: weak credentials are INTENTIONAL for the auth module.
    ins.run('admin', 'admin123', 'admin@pentrix.lab', 'admin', 'PENTRIX{sqli_union}');
    ins.run('alice', 'alice123', 'alice@pentrix.lab', 'user', 'alice-secret-note-1');
    ins.run('bob', 'bob123', 'bob@pentrix.lab', 'user', 'bob-secret-note-2');
  }
  const prodCount = db.prepare('SELECT COUNT(*) AS c FROM products').get().c;
  if (prodCount === 0) {
    const ins = db.prepare('INSERT INTO products (name, price, description) VALUES (?,?,?)');
    ins.run('PenTrix Hoodie', 39.99, 'Black hoodie with embroidered logo.');
    ins.run('Bug Bounty Field Notes', 14.99, 'Waterproof notebook for 3AM ideas.');
    ins.run('USB Rubber Ducky (Training)', 79.99, 'For authorized lab use only.');
    ins.run('Sticker Pack', 4.99, 'Laptop stickers. Obviously.');
  }
  const orderCount = db.prepare('SELECT COUNT(*) AS c FROM orders').get().c;
  if (orderCount === 0) {
    const ins = db.prepare('INSERT INTO orders (user_id, item, total, address) VALUES (?,?,?,?)');
    ins.run(2, 'PenTrix Hoodie', 39.99, '123 Hacker Lane, Brussels');
    ins.run(3, 'Sticker Pack', 4.99, '456 Binary Blvd, Antwerp');
  }
  const commentCount = db.prepare('SELECT COUNT(*) AS c FROM comments').get().c;
  if (commentCount === 0) {
    db.prepare('INSERT INTO comments (author, body) VALUES (?,?)')
      .run('admin', 'Welcome to the VulnLab guestbook. Be nice.');
  }
  return db;
}

module.exports = { getDb, DB_PATH };
