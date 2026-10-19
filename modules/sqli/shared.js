'use strict';
// Module-scoped helpers shared by the SQL Injection challenges: extra tables
// for the batch-02 labs, the admin-secret lookup (the exfiltration target for
// several labs), and the storefront page chrome. No routes, no vuln exported.
const { getDb } = require('../../lib/db');
const { esc } = require('../../lib/page');

const APP_NAME = 'CraftHaven Supply Co.';
const NAV = ['Shop', 'Members', 'Insights'];

// ---------- extra tables for the batch-02 labs (prefixed, self-contained) ----------
function sqliExtraTables() {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS sqli_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sqli_sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product TEXT NOT NULL,
      region TEXT NOT NULL,
      amount REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sqli_feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  if (db.prepare('SELECT COUNT(*) AS c FROM sqli_sales').get().c === 0) {
    const ins = db.prepare('INSERT INTO sqli_sales (product, region, amount) VALUES (?,?,?)');
    ins.run('PenTrix Hoodie', 'EU', 39.99);
    ins.run('Sticker Pack', 'EU', 4.99);
    ins.run('Bug Bounty Field Notes', 'US', 14.99);
    ins.run('USB Rubber Ducky (Training)', 'US', 79.99);
    ins.run('PenTrix Hoodie', 'APAC', 39.99);
    ins.run('Sticker Pack', 'APAC', 4.99);
  }
}
sqliExtraTables();

// The admin secret is the exfiltration target for several labs below.
// It is random per deployment (see lib/db.js); never hardcode it.
function adminSecret() {
  try {
    const r = getDb().prepare("SELECT secret FROM users WHERE username='admin'").get();
    return (r && r.secret) || null;
  } catch (e) {
    return null;
  }
}

// Shared storefront chrome: consistent brand and nav across every challenge
// page, so the module reads as one small shop instead of a test harness.
// Built from approved classes only (no appShell(), whose inline style= this
// module avoids; see the SHARED REQUESTS note in the split report).
function shopShell(crumb, bodyHtml) {
  const nav = NAV.map((n) => `<span class="dim">${esc(n)}</span>`).join('<span class="dim"> \u00b7 </span>');
  return `<div class="card">
    <div class="card-top"><span class="orb" aria-hidden="true">\ud83c\udfea</span><b>${esc(APP_NAME)}</b>
    <span class="clay-pill">${esc(crumb || 'Shop')}</span></div>
    <p class="dim">${nav}</p>
  </div>
  <div>${bodyHtml || ''}</div>`;
}

module.exports = { sqliExtraTables, adminSecret, shopShell };
