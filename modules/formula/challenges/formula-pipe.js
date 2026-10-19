'use strict';
// Pipe Prefix (formula-pipe): the contact export writes user input into CSV
// cells with quoting but no formula neutralization. LibreOffice treats a cell
// starting with | as a formula trigger, so a pipe-prefixed payload reaches the
// spreadsheet live. The flag is awarded when the export contains a cell
// starting with | (or =|).
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');
const { page, appShell } = require('../../../lib/page');

const router = express.Router();

// Module-level table setup (lives in router.js today; the finisher
// consolidates this into shared.js/index.js). Idempotent: IF NOT EXISTS plus
// a count-guarded seed, so requiring several challenge files is safe.
const db = getDb();
db.exec(`CREATE TABLE IF NOT EXISTS formula_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT, note TEXT, created_at TEXT
)`);
if (db.prepare('SELECT COUNT(*) AS c FROM formula_entries').get().c === 0) {
  db.prepare('INSERT INTO formula_entries (name, note, created_at) VALUES (?, ?, ?)')
    .run('Alice Smith', 'Quarterly review notes', new Date().toISOString());
}

// RFC 4180 quoting only. Quoting does NOT neutralize formulas: a cell that
// starts with | is still a live formula trigger in LibreOffice when the CSV
// is opened.
function csvCell(s) {
  s = String(s ?? '');
  return (/[",\n\r]/.test(s)) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// Classify an injected cell into its vuln id. All four challenge routers
// register the same /export.csv path, so the first mounted router serves
// every export request: it must award every matching vuln, exactly like the
// original combined router did, or the other three challenges could never be
// solved.
function classify(cell) {
  if (/^=HYPERLINK\(/i.test(cell)) return 'formula-hyperlink';
  if (/=DDE\(/i.test(cell)) return 'formula-dde';
  if (/^=\|/.test(cell) || /^\|/.test(cell)) return 'formula-pipe';
  if (/^=/.test(cell) && /cmd\|/i.test(cell)) return 'formula-csv';
  if (/^[=+\-@]/.test(cell)) return 'formula-csv'; // generic formula trigger
  return null;
}

// Contact Manager app chrome for this challenge's pages: the feature reads as
// a small real contact app, never as a test harness.
function addErrorPage() {
  return page('Add contact', appShell('Contact Manager', `
    <h1>Add contact</h1>
    <div class="warn"><p><b>Name is required.</b> Go back and enter a name for the contact.</p></div>
    <p><a class="clay-btn clay-btn-secondary" href="/formula">Back to contacts</a></p>
  `, { nav: ['Contacts', 'Export', 'Settings'], crumb: 'Contacts / Add contact' }));
}

// POST /formula/add -> store a contact. Same behavior as router.js: name is
// required (400 + app page otherwise), fields are length-capped and stored
// raw, then redirect back to the contact list. Body parsing (urlencoded) is
// provided at module scope by the finisher's index.js, as in router.js.
router.post('/add', (req, res) => {
  const name = (req.body.name || '').toString().slice(0, 200);
  const note = (req.body.note || '').toString().slice(0, 500);
  if (!name.trim()) {
    return res.status(400).send(addErrorPage());
  }
  getDb().prepare('INSERT INTO formula_entries (name, note, created_at) VALUES (?, ?, ?)')
    .run(name, note, new Date().toISOString());
  res.redirect('/formula');
});

// GET /formula/export.csv -> download the contacts CSV. Every row is exported
// with RFC 4180 quoting and NO formula neutralization (the flaw, identical to
// router.js). When an attacker-supplied cell starts with | or =|, the
// formula-pipe flag is awarded and returned in the X-Flags header (also saved
// to the scoreboard).
router.get('/export.csv', (req, res) => {
  const rows = getDb().prepare('SELECT name, note FROM formula_entries ORDER BY id').all();
  const lines = ['Name,Note'];
  const hits = new Set();
  for (const r of rows) {
    lines.push(csvCell(r.name) + ',' + csvCell(r.note));
    // VULN: cells are quoted but never neutralized for spreadsheet formulas, so
    // attacker-controlled =, +, -, @, | prefixes reach the spreadsheet live.
    for (const cell of [String(r.name), String(r.note)]) {
      const v = classify(cell);
      if (v) hits.add(v);
    }
  }
  const csv = lines.join('\r\n') + '\r\n';
  const flags = [...hits].map((v) => award(req, 'formula', v));
  res.set({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="contacts-export.csv"',
  });
  if (flags.length) res.set('X-Flags', flags.join(', '));
  res.send(csv);
});

module.exports = {
  vuln: {
    id: 'formula-pipe',
    name: 'Pipe Prefix (LibreOffice)',
    difficulty: 'Easy',
    hint: 'LibreOffice-flavored variant: the pipe character at the start of a cell is another formula trigger.',
    hints: ["LibreOffice uses the pipe prefix for formulas. The payload starts with |.", "Once the cell is live, the rest of it is a formula, so it can invoke an application with a command, anchored by a cell reference like the other formula challenges.", "Prefix the cell with a pipe so LibreOffice reads it as a formula, then route a shell command through it with a cell reference. The key insight: the leading pipe alone is enough to turn the cell from plain text into something the spreadsheet executes."],
    tools: "B",
    how: 'Put a pipe-prefixed payload (starting with |) in a field and download the CSV export.',
    link: '/formula#formula-pipe',
    start: "curl -s -X POST http://localhost:3000/formula/add --data-urlencode \"name=|'cmd'!A0\"\ncurl -si http://localhost:3000/formula/export.csv -o /tmp/contacts.csv",
  },
  router,
};
