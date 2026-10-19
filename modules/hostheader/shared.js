'use strict';
// Host Header Injection module: helpers shared by the challenge files.
// Placed here by the module finisher, logic copied from the old
// modules/hostheader/router.js so challenge behavior is unchanged.

const { getDb } = require('../../lib/db');

// Tokens issued by the poisoned password-reset pages. Ensures the table
// exists and returns the db handle.
function tokenDb() {
  const db = getDb();
  db.exec(`CREATE TABLE IF NOT EXISTS hostheader_tokens (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    issued_host TEXT NOT NULL,
    vuln TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  return db;
}

function bareHost(h) {
  return String(h || '').split(':')[0].trim().toLowerCase();
}

// The lab app is served on localhost. Any other Host value is attacker-controlled.
function isLocalHost(h) {
  const n = bareHost(h);
  return n === '' || n === 'localhost' || n === '127.0.0.1' || n === '::1';
}

module.exports = { tokenDb, isLocalHost };
