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
    hint: 'PATCH /api/me builds its SQL SET clause from Object.keys(req.body). Nothing stops you from adding fields the form never showed you; think about which column in the users table decides what you are allowed to do.',
    hints: [
      "Log in as alice with Burp's Proxy on, then browse to /api/me and send that request to Repeater (Ctrl+R) to read your profile columns.",
      "PATCH /me builds its SQL SET clause from Object.keys(req.body). There is no allowlist, so every key in the JSON body becomes a column in the UPDATE, even fields the form never showed you.",
      "In Repeater, add one extra key to the PATCH body that raises your privilege level, then send it. GET /me shows you which column decides your role."
    ],
    tools: 'BZ, C',
    how: 'Log in as alice, send a GET /api/me to Repeater to read your columns, then replay the PATCH /api/me in Repeater with one extra JSON key that raises your privilege and collect the flag.',
    link: '/api#mass-assignment',
    start: 'Route your browser through Burp Proxy, visit http://localhost:3000/api/login/alice to log in, then browse to http://localhost:3000/api/me and send that request to Repeater (Ctrl+R) to see your profile columns.',
  },
  router,
};
