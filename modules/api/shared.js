'use strict';
// Module-scoped helpers shared by the API challenges. No routes, no vuln.
const { getDb } = require('../../lib/db');

// 401 JSON for routes that need a logged-in user; returns the session user or null.
function requireLogin(req, res) {
  const user = req.session.user;
  if (!user) {
    res.status(401).json({ ok: false, error: 'Not logged in. Use GET /api/login/alice first.' });
    return null;
  }
  return user;
}

function userTable() {
  return getDb().prepare('SELECT * FROM users').all();
}

function userRow(id) {
  return getDb().prepare('SELECT id, username, email, role, secret FROM users WHERE id = ?').get(id);
}

module.exports = { requireLogin, userTable, userRow };
