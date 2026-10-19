'use strict';

// Fix badges for M11 break-then-fix mode. When a student's fix passes the
// sandboxed runner they earn a badge for that challenge. Badges are
// per-user and persistent in the same SQLite database as the flags table,
// so they survive server restarts.
//
// User identity matches the flag system in lib/flags.js: the express
// session. The session itself is SQLite-backed (lib/session-store.js), so a
// session id is a stable per-student key across restarts.

const { getDb } = require('./db');

// Create the table if it does not exist yet. Idempotent: safe to call at
// boot and before every write/read.
function ensureFixBadgeTable() {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS fix_badges (
      user_key TEXT NOT NULL,
      module TEXT NOT NULL,
      vuln_id TEXT NOT NULL,
      awarded_at INTEGER NOT NULL,
      PRIMARY KEY (user_key, module, vuln_id)
    );
  `);
}

// The same user identity mechanism the flag system uses: the session.
// award()/captured() in lib/flags.js key everything off req.session, so
// badges key off req.sessionID, the id of that same session.
function userKeyFor(req) {
  const key = req && req.sessionID;
  if (!key) {
    throw new Error('fix badges require an express session (req.sessionID is missing)');
  }
  return String(key);
}

// Award a badge for a fixed challenge. Returns the badge record
// { module, vulnId, awarded_at } when this call earned it, or null when the
// user already had it (no double award).
function awardFixBadge(req, module, vulnId) {
  ensureFixBadgeTable();
  const key = userKeyFor(req);
  const now = Date.now();
  const result = getDb()
    .prepare('INSERT OR IGNORE INTO fix_badges (user_key, module, vuln_id, awarded_at) VALUES (?, ?, ?, ?)')
    .run(key, module, vulnId, now);
  if (result.changes === 0) {
    return null; // already awarded
  }
  return { module, vulnId, awarded_at: now };
}

// True when this user already earned the badge for this challenge.
function hasFixBadge(req, module, vulnId) {
  ensureFixBadgeTable();
  const row = getDb()
    .prepare('SELECT 1 FROM fix_badges WHERE user_key = ? AND module = ? AND vuln_id = ?')
    .get(userKeyFor(req), module, vulnId);
  return !!row;
}

// Every badge this user has earned, newest first.
function fixBadgeList(req) {
  ensureFixBadgeTable();
  return getDb()
    .prepare('SELECT module, vuln_id AS vulnId, awarded_at FROM fix_badges WHERE user_key = ? ORDER BY awarded_at DESC')
    .all(userKeyFor(req));
}

// How many badges this user has earned.
function fixBadgeCount(req) {
  ensureFixBadgeTable();
  return getDb()
    .prepare('SELECT COUNT(*) AS c FROM fix_badges WHERE user_key = ?')
    .get(userKeyFor(req)).c;
}

module.exports = { ensureFixBadgeTable, awardFixBadge, hasFixBadge, fixBadgeList, fixBadgeCount };
