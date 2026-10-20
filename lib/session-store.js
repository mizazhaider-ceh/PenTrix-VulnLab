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
      getForMerge: db.prepare('SELECT sess, expires FROM sessions WHERE sid = ? AND expires > ?'),
    };
    this.stmts.purge.run(Date.now());
    // Sessions whose cookie expired are swept by express-session on read,
    // but rows for browsers that simply never come back would sit forever.
    // Purge expired rows periodically so the store cannot grow unboundedly
    // (P1-9); unref'd so the timer never keeps the process alive by itself.
    const purgeMs = opts.purgeIntervalMs || 60 * 60 * 1000;
    this.purgeTimer = setInterval(() => {
      try { this.stmts.purge.run(Date.now()); } catch (e) { /* next tick retries */ }
    }, purgeMs);
    this.purgeTimer.unref();
  }

  // Delete every expired session row right now.
  purgeExpired() {
    return this.stmts.purge.run(Date.now()).changes;
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

  // P1-6: parallel bursts on one session must not lose captures. Each
  // request loads a session snapshot at its start and the store saves the
  // whole blob at its end, so a request that held its snapshot across an
  // await used to overwrite progress another request saved in between
  // (last writer wins). Capture entries are monotonic (only ever set to
  // true), so set() unions the incoming capture map with the stored one.
  // All other keys keep last-writer-wins, preserving single-use nonce
  // semantics (consumed tokens must stay deleted).
  set(sid, sess, cb) {
    try {
      let body = sess;
      let expiry = this._expiry(sess);
      const incoming = sess && sess.flags;
      if (incoming && typeof incoming === 'object') {
        try {
          const row = this.stmts.getForMerge.get(sid, Date.now());
          if (row) {
            const stored = JSON.parse(row.sess);
            const storedFlags = stored && stored.flags;
            if (storedFlags && typeof storedFlags === 'object') {
              const union = {};
              for (const k of Object.keys(storedFlags)) union[k] = true;
              for (const k of Object.keys(incoming)) if (incoming[k]) union[k] = true;
              body = Object.assign({}, sess, { flags: union });
            }
            // Never let a stale snapshot shorten the stored expiry.
            if (typeof row.expires === 'number') expiry = Math.max(expiry, row.expires);
          }
        } catch (e) { /* a corrupt stored blob falls back to the incoming snapshot */ }
      }
      this.stmts.set.run(sid, JSON.stringify(body), expiry);
      if (cb) cb(null);
    } catch (e) { if (cb) cb(e); }
  }

  // Read the stored capture map for a session id (or null when absent), so
  // callers can re-check the merged state when a per-request snapshot is
  // stale after a parallel burst.
  getFlags(sid) {
    try {
      const row = this.stmts.get.get(sid, Date.now());
      if (!row) return null;
      const stored = JSON.parse(row.sess);
      return stored && stored.flags && typeof stored.flags === 'object' ? stored.flags : null;
    } catch (e) { return null; }
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
