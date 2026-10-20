'use strict';
// Mass assignment: PATCH /api/me writes every client-supplied key into the users row.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');
const { setRoleOverride, effectiveRole } = require('../../../lib/account-state');

const router = express.Router();

// GET /api/me -> your profile, so you can see what the API thinks you are.
router.get('/me', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ ok: false, error: 'Not logged in. Use GET /api/login/alice first.' });
  const me = getDb().prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(user.id);
  // A role this session granted itself through mass assignment applies to
  // this session only (see the PATCH handler); everyone else sees the
  // account's real role.
  if (me) me.role = effectiveRole(req, me.id, me.role);
  res.json({ ok: true, user: me });
});

// PATCH /api/me -> v1 mass assignment. Every key in the JSON body is written
// straight into the users row of the logged-in user.
router.patch('/me', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ ok: false, error: 'Not logged in. Use GET /api/login/alice first.' });

  const body = req.body || {};
  const keys = Object.keys(body);
  if (keys.length === 0) return res.status(400).json({ ok: false, error: 'Empty JSON body.' });

  const db = getDb();
  const before = db.prepare('SELECT id, role FROM users WHERE id = ?').get(user.id);
  // VULN: mass assignment, no allowlist. Client-controlled keys (even "role"
  // or "id") become columns in the UPDATE, so privilege escalation is trivial.
  const setClause = keys.map((k) => `"${k}" = ?`).join(', ');
  const values = keys.map((k) => body[k]);
  db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, user.id);

  // Multi-student isolation (P1-1): the privilege change the exploit earned
  // must not leak into the shared users table, or alice would silently stay
  // admin for every other student and nullify the six IDOR challenges that
  // gate on role. The escalation above runs for real (it is the lesson),
  // then the shared row is restored and the new role is kept as a
  // per-session override, visible only to the session that earned it.
  const updated = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(user.id);
  let flag = null;
  const wantsPromotion = keys.some((k) => String(k).toLowerCase() === 'role');
  if (wantsPromotion && before && updated && updated.role !== before.role) {
    // NOTE: SQLite returns the INTEGER PRIMARY KEY alias ("id") for a
    // rowid select, so before.id is the row locator here.
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(before.role, before.id);
    setRoleOverride(req, user.id, updated.role);
    updated.role = before.role;
  }
  const shown = updated
    ? { id: updated.id, username: updated.username, email: updated.email,
        role: effectiveRole(req, updated.id, updated.role) }
    : null;
  if (shown && shown.role === 'admin') {
    flag = award(req, 'api', 'mass-assignment');
  }
  res.json({ ok: true, user: shown, flag });
});

module.exports = {
  vuln: {
    id: 'mass-assignment',
    name: 'Mass Assignment',
    difficulty: 'Medium',
    hint: 'PATCH /api/me builds its SQL SET clause from Object.keys(req.body). Nothing stops you from adding fields the form never showed you; think about which column in the users table decides what you are allowed to do.',
    hints: [
      "Log in as alice with Burp's Proxy on, then browse to /api/me and send that request to Repeater (Ctrl+R) to read your profile columns.",
      "PATCH /me builds its SQL SET clause from Object.keys(req.body). There is no allowlist, so every key in the JSON body becomes a column in the UPDATE, even fields the form never showed you.",
      "In Repeater, add one extra key to the PATCH body that raises your privilege level, then send it. GET /me shows you which column decides your role."
    ],
    tools: 'BZ, C',
    how: 'Log in as alice, send a GET /api/me to Repeater to read your columns, then replay the PATCH /api/me in Repeater with one extra JSON key that raises your privilege and collect the flag.',
    link: '/api#mass-assignment',
    start: 'Route your browser through Burp Proxy, visit /api/login/alice to log in, then browse to /api/me and send that request to Repeater (Ctrl+R) to see your profile columns.',
  },
  router,
};
