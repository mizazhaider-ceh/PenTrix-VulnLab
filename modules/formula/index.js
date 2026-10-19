'use strict';
// CSV Formula Injection: a contact manager exports user-controlled fields to
// CSV without neutralizing spreadsheet formula triggers. Smuggle =cmd, DDE,
// HYPERLINK, and pipe-prefixed payloads through the export and let the server
// verify they landed.
const express = require('express');
const { getDb } = require('../../lib/db');
const { fixCta, brief, difficultyPill, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner } = require('../../lib/page');

const challenges = [
  require('./challenges/formula-csv'),
  require('./challenges/formula-dde'),
  require('./challenges/formula-hyperlink'),
  require('./challenges/formula-pipe'),
];

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
// Lives here at module scope because the hyperlink and pipe challenge routers
// register their /add handlers without their own body parser.
router.use(express.urlencoded({ extended: false }));

// Module-level table setup, idempotent (IF NOT EXISTS plus a count-guarded
// seed), so requiring several challenge files plus this index is safe. The
// module page renders the current contacts table from it.
const db = getDb();
db.exec(`CREATE TABLE IF NOT EXISTS formula_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT, note TEXT, created_at TEXT
)`);
if (db.prepare('SELECT COUNT(*) AS c FROM formula_entries').get().c === 0) {
  db.prepare('INSERT INTO formula_entries (name, note, created_at) VALUES (?, ?, ?)')
    .run('Alice Smith', 'Quarterly review notes', new Date().toISOString());
}

// GET /formula -> module index page: briefing, the shared add-contact form,
// the CSV export link, the current contacts, and one card per challenge.
router.get('/', (req, res) => {
  const entries = db.prepare('SELECT name, note FROM formula_entries ORDER BY id DESC').all();
  const rows = entries.map((e) => `
    <tr><td>${esc(e.name)}</td><td>${esc(e.note)}</td></tr>`).join('\n');

  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="${esc(v.link)}">${esc(v.name)}</a> ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('formula', c.vuln.id)).join('')}
    </section>`;
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
    ${trackBanner(module.exports)}

    <h2>Add a contact</h2>
    <form method="POST" action="/formula/add">
      <div class="clay-field">
        <label for="name">Name</label>
        <input class="clay-input" type="text" id="name" name="name" placeholder="name" size="40" required />
      </div>
      <div class="clay-field">
        <label for="note">Note</label>
        <input class="clay-input" type="text" id="note" name="note" placeholder="note" size="40" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Add contact</button>
    </form>
    <p><a href="/formula/export.csv"><b>Download CSV export</b></a></p>

    <h2>Current contacts</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">Current contacts</caption>
      <thead><tr><th scope="col">Name</th><th scope="col">Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>

    <h2>Challenges</h2>
    <p>Four formula flavors hide in the export below. Each challenge card has a
    hint ladder: level 1 nudges, level 2 teaches the technique, level 3 shows
    the payload shape.</p>
    ${cards}
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'formula',
  name: 'CSV Formula Injection',
  tagline: 'Poison the export: turn spreadsheet cells into live formulas.',
  description: 'A contact manager exports user-controlled fields to CSV without neutralizing spreadsheet formula triggers. Smuggle =cmd, DDE, HYPERLINK, and pipe-prefixed payloads through the export and let the server verify they landed.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['xss'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
