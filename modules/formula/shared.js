'use strict';
// Per-session bookkeeping for the shared formula_entries table (P1-1).
//
// The contact list is one shared table, but each entry is tagged with the
// session that created it. The CSV export still writes the whole address
// book (that shared export is the scenario), yet a formula flag is only
// awarded for cells the requesting session supplied itself: one student's
// planted payload can no longer hand flags to every other student who
// happens to download the export. Seed rows (and rows written before this
// pass) carry no session id; they are benign and visible to everyone.
const { getDb } = require('../../lib/db');

let migrated = false;

function ensureSidColumn() {
  if (migrated) return;
  const db = getDb();
  const cols = db.prepare('PRAGMA table_info(formula_entries)').all().map((c) => c.name);
  if (cols.length && !cols.includes('sid')) {
    db.exec('ALTER TABLE formula_entries ADD COLUMN sid TEXT');
  }
  migrated = true;
}

// Store a contact for this session. Also pins the session (marks it as
// touched) so express-session persists the id the entry is tagged with.
function insertEntry(req, name, note) {
  ensureSidColumn();
  if (req.session && !req.session.__labState) req.session.__labState = 1;
  getDb().prepare('INSERT INTO formula_entries (name, note, created_at, sid) VALUES (?, ?, ?, ?)')
    .run(name, note, new Date().toISOString(), req.sessionID || null);
}

function isOwnEntry(row, req) {
  return row.sid != null && row.sid === (req.sessionID || null);
}

// Rows the contact list shows this session: its own entries plus the
// ownerless seed entries.
function visibleEntries(req, order) {
  ensureSidColumn();
  return getDb()
    .prepare('SELECT name, note, sid FROM formula_entries WHERE sid IS NULL OR sid = ? ORDER BY ' + order)
    .all(req.sessionID || null);
}

// Every row, for the export body itself.
function allEntries() {
  ensureSidColumn();
  return getDb().prepare('SELECT name, note, sid FROM formula_entries ORDER BY id').all();
}

module.exports = { insertEntry, isOwnEntry, visibleEntries, allEntries };
