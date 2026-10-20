const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'vulnlab.db');
let db = null;

// Flags are random per deployment: PENTRIX{<32 lowercase hex chars>}. They are
// generated on first boot, stored only in the SQLite file (which is
// gitignored), and never appear in source code, so reading GitHub reveals
// nothing.
function randomFlag() {
  return `PENTRIX{${crypto.randomBytes(16).toString('hex')}}`;
}

// On first boot (empty users table) the admin secret is minted as a fresh
// per-deployment value above. On later boots, a stale pre-per-deployment
// secret must be rotated without embedding the old hardcoded value anywhere:
// per-deployment secrets always match PENTRIX{<32 hex>}, so anything stored in
// another shape is by definition stale and gets replaced. Deliberately set
// values in the current format are left alone.
function rotateStaleAdminSecret() {
  const stored = db
    .prepare("SELECT secret FROM users WHERE username = 'admin'")
    .get();
  if (!stored || !/^PENTRIX\{[0-9a-f]{32}\}$/.test(stored.secret)) {
    db.prepare("UPDATE users SET secret = ? WHERE username = 'admin'").run(
      randomFlag()
    );
    console.log(
      '[ok] rotated stale pre-per-deployment admin secret to a per-deployment random value'
    );
  }
}

// Demo accounts advertised across the lab (session fixation page says
// admin/admin123, the host-header login page says alice/alice123 and
// bob/bob123, the sqli login form works with them too). Challenges
// intentionally change passwords at runtime (change-pass-noverify,
// otp-bruteforce's reset), and shared instances accumulate that drift, so
// every boot re-asserts the advertised passwords (P1-8). Missing rows are
// re-inserted; existing rows keep their email/role/secret, only the
// password is restored.
const DEMO_CREDS = [
  { username: 'admin', password: 'admin123', email: 'admin@pentrix.lab', role: 'admin' },
  { username: 'alice', password: 'alice123', email: 'alice@pentrix.lab', role: 'user' },
  { username: 'bob', password: 'bob123', email: 'bob@pentrix.lab', role: 'user' },
];

function repairDemoAccounts() {
  const get = db.prepare('SELECT id, password FROM users WHERE username = ?');
  const upd = db.prepare('UPDATE users SET password = ? WHERE username = ?');
  const ins = db.prepare('INSERT INTO users (username, password, email, role, secret) VALUES (?,?,?,?,?)');
  let repaired = 0;
  for (const c of DEMO_CREDS) {
    const row = get.get(c.username);
    if (!row) {
      ins.run(c.username, c.password, c.email, c.role, randomFlag());
      repaired++;
    } else if (row.password !== c.password) {
      upd.run(c.password, c.username);
      repaired++;
    }
  }
  if (repaired > 0) {
    console.log(`[ok] repaired ${repaired} drifted demo account(s) to their advertised passwords`);
  }
}

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
    CREATE TABLE IF NOT EXISTS flags (
      module_id TEXT NOT NULL,
      vuln_id TEXT NOT NULL,
      flag TEXT NOT NULL,
      PRIMARY KEY (module_id, vuln_id)
    );
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount === 0) {
    const ins = db.prepare('INSERT INTO users (username, password, email, role, secret) VALUES (?,?,?,?,?)');
    // NOTE: weak credentials are INTENTIONAL for the auth module.
    // The admin secret is random per deployment (exfiltration target for the
    // sqli labs); it is data, not a challenge flag.
    ins.run('admin', 'admin123', 'admin@pentrix.lab', 'admin', randomFlag());
    ins.run('alice', 'alice123', 'alice@pentrix.lab', 'user', 'alice-secret-note-1');
    ins.run('bob', 'bob123', 'bob@pentrix.lab', 'user', 'bob-secret-note-2');
  } else {
    // Rotate a stale pre-per-deployment secret (see rotateStaleAdminSecret).
    rotateStaleAdminSecret();
  }
  // P1-8: heal credential drift on every boot, not just on a fresh database.
  repairDemoAccounts();
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

  // Install identity: a random per-deployment id in the meta table. M13
  // uses it to bind verifiable artifacts (path certificates) to this
  // install. It is not a flag and reveals nothing sensitive.
  const installRow = db.prepare('SELECT value FROM meta WHERE key = ?').get('install_id');
  if (!installRow) {
    // OR IGNORE: two processes booting a fresh DB at the same time must not
    // both crash on the PRIMARY KEY; the loser reads the winner's row.
    const inserted = db.prepare('INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)').run(
      'install_id',
      crypto.randomBytes(16).toString('hex')
    );
    if (inserted.changes > 0) {
      console.log('[ok] minted install_id for this deployment');
    }
  }
  return db;
}

// This deployment's install identity. getDb() always ensures the row, so
// this is normally a plain read; the minting below only guards direct
// calls made before the first getDb().
function installId() {
  const database = getDb();
  const row = database
    .prepare('SELECT value FROM meta WHERE key = ?')
    .get('install_id');
  if (row) return row.value;
  // Fallback for a direct call before the row exists: OR IGNORE plus a
  // re-read guarantees we return the stored value, never an unstored one.
  const fresh = crypto.randomBytes(16).toString('hex');
  database
    .prepare('INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)')
    .run('install_id', fresh);
  return database
    .prepare('SELECT value FROM meta WHERE key = ?')
    .get('install_id').value;
}

// Ensure every registered challenge has a per-deployment random flag.
// Called once from app.js after modules are mounted. Existing rows are kept,
// so flags stay stable across restarts of the same deployment; a fresh
// database gets fresh flags.
function ensureFlags(vulns) {
  const database = getDb();
  const insert = database.prepare(
    'INSERT OR IGNORE INTO flags (module_id, vuln_id, flag) VALUES (?, ?, ?)'
  );
  let created = 0;
  for (const { modId, vulnId } of vulns) {
    const result = insert.run(modId, vulnId, randomFlag());
    created += result.changes;
  }
  if (created > 0) {
    console.log(`[ok] generated ${created} per-deployment challenge flags`);
  }
  return created;
}

module.exports = { getDb, DB_PATH, ensureFlags, randomFlag, installId, DEMO_CREDS };
