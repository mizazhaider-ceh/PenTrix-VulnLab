'use strict';
// Login Bypass: the login query is built by string interpolation, so a quote
// breakout can rewrite the WHERE clause and skip the password check entirely.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { shopShell } = require('../shared');

const router = express.Router();

router.get('/login', (req, res) => {
  res.send(page('Login Bypass', shopShell('Sign in', `
    <h1>Sign in</h1>
    ${brief('Login Bypass', 'Log in below. The query behind this form is vulnerable to SQL injection.')}
    <form class="clay-card" method="POST" action="/sqli/login">
      <div class="card-top"><b>Member sign in</b></div>
      <div class="clay-field">
        <label for="username">Username</label>
        <input class="clay-input" id="username" name="username" autocomplete="off" />
      </div>
      <div class="clay-field">
        <label for="password">Password</label>
        <input class="clay-input" id="password" name="password" type="password" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Log in</button>
    </form>
  `)));
});

router.post('/login', (req, res) => {
  const u = req.body.username || '';
  const p = req.body.password || '';
  const db = getDb();
  // VULN: user input interpolated directly into the SQL string (no parameterization).
  const sql = `SELECT * FROM users WHERE username='${u}' AND password='${p}'`;
  let row = null;
  try {
    const rows = db.prepare(sql).all();
    row = rows[0] || null;
  } catch (e) {
    // broken query, treat as failed login
  }
  // BUGFIX: award only when the match came from breaking the query, not from
  // supplying the real admin credentials. Without the `u !== row.username`
  // check, anyone who happens to know (or finds in source) the seeded admin
  // password could log in normally and still earn the flag with no injection
  // at all; a quote-breakout payload never equals the row's real username.
  if (row && (row.username === 'admin' || row.role === 'admin') && u !== row.username) {
    const flag = award(req, 'sqli', 'login-bypass');
    return res.send(page('Login Bypass', shopShell('Signed in', `
      <h1>Signed in</h1>
      <p>Logged in as <strong>${esc(row.username)}</strong> (role: ${esc(row.role)}).</p>
      ${flagBox(flag)}
      ${fixPanel('sqli', 'login-bypass')}
    `)));
  }
  res.send(page('Login Bypass', shopShell('Sign in', `
    <h1>Sign in</h1>
    <div class="warn"><p><strong>Invalid username or password.</strong></p></div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/login">Try again</a></p>
  `)));
});

module.exports = {
  vuln: {
    id: 'login-bypass',
    name: 'Login Bypass',
    difficulty: 'Easy',
    hint: 'The login query is built by string interpolation. Make the WHERE clause always true and comment out the password check.',
    hints: ["The login form asks for a username and password. What does the database query look like, and where does your input end up in it?", "The query is built by gluing your input into a SQL string. If your username contains a quote, you can break out of the string and rewrite the WHERE clause.", "Make the WHERE clause always true and comment out the password check: try ' OR '1'='1' --  as the username."],
    tools: "B, C",
    how: "Log in as admin with the classic ' OR '1'='1 payload.",
    link: '/sqli/login',
    start: 'curl -X POST http://localhost:3000/sqli/login -d "username=admin&password=wrong"',
  },
  router,
};
