'use strict';
// Login Bypass: the login query is built by string interpolation, so a quote
// breakout can rewrite the WHERE clause and skip the password check entirely.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
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
      ${fixCta('sqli', 'login-bypass')}
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
    hints: ["Fill in the login form, then intercept the POST /sqli/login request in Burp Proxy and send it to Repeater. The database query behind this form is built by gluing your input into a SQL string. Where does your input end up in it?", "In Repeater, experiment with the username parameter. If your username contains a quote, you can break out of the SQL string and rewrite the WHERE clause yourself.", "In Repeater, edit the username so the WHERE clause evaluates to true for every row and the password check is neutralized with a SQL comment. If the query returns a row, the app logs you in."],
    tools: "BZ, B, C",
    how: "Break out of the quoted username field so the WHERE clause is always true and the password comparison is commented out. The app logs you in as the first matching row (admin) and awards the flag.",
    link: '/sqli/login',
    start: 'In Burp Proxy, intercept the POST /sqli/login request, then send it to Repeater.',
  },
  router,
};
