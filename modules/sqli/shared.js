'use strict';
// Module-scoped helpers shared by the SQL Injection challenges: extra tables
// for the batch-02 labs, the admin-secret lookup (the exfiltration target for
// several labs), per-challenge derived targets (P0-8 FLAG BAR), and the
// storefront page chrome. No routes, no vuln exported.
const crypto = require('crypto');
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

  // P0-8: the LIMIT/OFFSET challenge's own target lives in a catalog row the
  // default page (LIMIT 2) never shows. Only genuine LIMIT-clause
  // manipulation pulls it into view; the award fires when the derived value
  // appears in the paged output. The row is refreshed if the deployment's
  // admin secret (and therefore the derived target) ever rotates.
  const loTarget = challengeTarget('limit-offset');
  if (loTarget) {
    const desc = `Internal audit token ${loTarget}. Not for the public catalog.`;
    const row = db.prepare('SELECT id FROM products WHERE name = ?').get('Archived Prototype X9');
    if (!row) {
      db.prepare('INSERT INTO products (name, price, description) VALUES (?,?,?)')
        .run('Archived Prototype X9', 0.01, desc);
    } else {
      db.prepare('UPDATE products SET description = ? WHERE id = ?').run(desc, row.id);
    }
  }
}
// NOTE: sqliExtraTables() is invoked at the bottom of this file, after the
// per-challenge target helpers are initialized, because it now seeds the
// limit-offset target row via challengeTarget().

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

// ---------- per-challenge derived targets (P0-8 FLAG BAR) ----------
// Five of this module's challenges used to share one exfiltration target
// (the admin secret), so a single UNION dump unlocked five flags: blind and
// like-wildcard accepted the secret in their submit boxes, groupby-having
// accepted it as a quoted literal, and order-by plus limit-offset awarded on
// input pattern alone. Each of those five now has its OWN target, derived
// from the admin secret with the challenge id mixed in, in the same
// PENTRIX{<32 hex>} shape. A secret extracted via one technique can no
// longer be replayed into another challenge's submit box.
function deriveTarget(admin, challengeId) {
  const hex = crypto.createHash('sha256')
    .update(`${admin}|sqli-target:${challengeId}`, 'utf8')
    .digest('hex')
    .slice(0, 32);
  return `PENTRIX{${hex}}`;
}

const TARGET_CHALLENGES = ['blind', 'like-wildcard', 'groupby-having', 'order-by', 'limit-offset'];
const derivedTargets = new Map();
let derivedForAdmin = null;
function refreshDerivedTargets() {
  const admin = adminSecret();
  if (!admin || derivedForAdmin === admin) return;
  derivedForAdmin = admin;
  derivedTargets.clear();
  for (const id of TARGET_CHALLENGES) derivedTargets.set(id, deriveTarget(admin, id));
}
// The target a submit box (or echo check) for challengeId must see.
function challengeTarget(challengeId) {
  refreshDerivedTargets();
  return derivedTargets.get(challengeId) || null;
}

// The derived targets are reachable from injected SQL through the
// sqli_target() scalar function, but ONLY inside the route of the challenge
// they belong to: that route wraps its query in withChallengeTarget(id), and
// the function returns NULL everywhere else. That binding is what makes
// cross-challenge replay impossible: sqli_target() evaluated inside the
// UNION challenge (or any other route) yields NULL, never another
// challenge's secret, and the derived values live in no table a UNION could
// dump. Only the limit-offset target additionally sits in a catalog row (see
// sqliExtraTables), because that challenge's technique reveals rows rather
// than submitting a value.
let targetContext = null;
function withChallengeTarget(challengeId, fn) {
  refreshDerivedTargets();
  const prev = targetContext;
  targetContext = challengeId;
  try {
    return fn();
  } finally {
    targetContext = prev;
  }
}
function installTargetFunction() {
  const db = getDb();
  db.function('sqli_target', () => {
    const t = targetContext ? derivedTargets.get(targetContext) : null;
    return t || null;
  });
}
installTargetFunction();

// Strip string literals and SQL comments before looking for live SQL
// keywords. Without this, keywords smuggled inside a quoted literal or a
// comment would read as real SQL tokens.
function stripSqlNoise(s) {
  return String(s || '')
    .replace(/'(?:[^']|'')*'/g, ' ')
    .replace(/--[^\n]*/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ');
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

module.exports = { sqliExtraTables, adminSecret, shopShell, challengeTarget, withChallengeTarget, stripSqlNoise };

// Seed the extra tables (and the limit-offset target row) once every helper
// above is initialized.
sqliExtraTables();
