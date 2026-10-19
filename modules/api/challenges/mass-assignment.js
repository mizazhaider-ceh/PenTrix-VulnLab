'use strict';
// Mass assignment: PATCH /api/me writes every client-supplied key into the users row.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');

const router = express.Router();

// GET /api/me -> your profile, so you can see what the API thinks you are.
router.get('/me', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ ok: false, error: 'Not logged in. Use GET /api/login/alice first.' });
  const me = getDb().prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(user.id);
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
  // VULN: mass assignment, no allowlist. Client-controlled keys (even "role"
  // or "id") become columns in the UPDATE, so privilege escalation is trivial.
  const setClause = keys.map((k) => `"${k}" = ?`).join(', ');
  const values = keys.map((k) => body[k]);
  db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, user.id);

  const updated = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(user.id);
  let flag = null;
  if (updated && updated.role === 'admin') {
    flag = award(req, 'api', 'mass-assignment');
  }
  res.json({ ok: true, user: updated, flag });
});

module.exports = {
  vuln: {
    id: 'mass-assignment',
    name: 'Mass Assignment',
    difficulty: 'Medium',
    hint: 'PATCH /api/me builds its SQL SET clause from Object.keys(req.body). Nothing stops you from adding fields the form never showed you, like "role".',
    hints: ["The PATCH /me endpoint updates your profile. What happens if you send fields the form never showed you?", "There is no allowlist: every key in the JSON body becomes a column in the UPDATE.", "Send a PATCH with a JSON body containing an extra privilege-related field."],
    tools: 'C',
    how: 'Log in as alice, then send a JSON body with an extra field that escalates your privilege.',
    link: '/api#mass-assignment',
    start: 'curl -s -b jar -c jar http://localhost:3000/api/login/alice\ncurl -s -b jar http://localhost:3000/api/me',
  },
  router,
};
