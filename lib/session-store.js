// SQLite-backed express-session store. The default MemoryStore forgets every
// session (and therefore every captured flag) whenever the container restarts;
// this keeps student progress on disk next to the lab database, so it survives
// restarts and is wiped only when ./data is removed. It uses its own file
// (sessions.db) so the SQL injection labs can never read other students'
// session ids out of the vulnerable application's database.
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

class SqliteStore extends session.Store {
  constructor(dbPath, opts = {}) {
    super();
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    this.db = db;
    this.ttlMs = opts.ttlMs || DEFAULT_TTL_MS;
    db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        sess TEXT NOT NULL,
        expires INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expires ON sessions (expires);
    `);
    this.stmts = {
      get: db.prepare('SELECT sess FROM sessions WHERE sid = ? AND expires > ?'),
      set: db.prepare('INSERT OR REPLACE INTO sessions (sid, sess, expires) VALUES (?, ?, ?)'),
      del: db.prepare('DELETE FROM sessions WHERE sid = ?'),
      touch: db.prepare('UPDATE sessions SET expires = ? WHERE sid = ?'),
      purge: db.prepare('DELETE FROM sessions WHERE expires <= ?'),
    };
    this.stmts.purge.run(Date.now());
  }

  _expiry(sess) {
    const exp = sess && sess.cookie && sess.cookie.expires;
    const t = exp ? new Date(exp).getTime() : NaN;
    return Number.isFinite(t) ? t : Date.now() + this.ttlMs;
  }

  get(sid, cb) {
    try {
      const row = this.stmts.get.get(sid, Date.now());
      cb(null, row ? JSON.parse(row.sess) : null);
    } catch (e) { cb(e); }
  }

  set(sid, sess, cb) {
    try {
      this.stmts.set.run(sid, JSON.stringify(sess), this._expiry(sess));
      if (cb) cb(null);
    } catch (e) { if (cb) cb(e); }
  }

  destroy(sid, cb) {
    try {
      this.stmts.del.run(sid);
      if (cb) cb(null);
    } catch (e) { if (cb) cb(e); }
  }

  touch(sid, sess, cb) {
    try {
      this.stmts.touch.run(this._expiry(sess), sid);
      if (cb) cb(null);
    } catch (e) { if (cb) cb(e); }
  }
}

module.exports = { SqliteStore };
