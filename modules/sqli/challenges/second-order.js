'use strict';
// Second-Order SQL Injection: registration stores the display name safely,
// but the profile page later interpolates that stored value into a new query.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, fixCta } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { shopShell } = require('../shared');

const router = express.Router();

router.get('/register', (req, res) => {
  res.send(page('Member Registration', shopShell('Join', `
    <h1>Member registration</h1>
    ${brief('Member Registration', 'Create a member account. Your display name is stored with a prepared statement, so nothing dangerous can happen at this step. The danger comes later, when the stored value is reused.')}
    <form class="clay-card" method="POST" action="/sqli/register">
      <div class="card-top"><b>Create an account</b></div>
      <div class="clay-field">
        <label for="username">Username</label>
        <input class="clay-input" id="username" name="username" required />
      </div>
      <div class="clay-field">
        <label for="display_name">Display name</label>
        <input class="clay-input" id="display_name" name="display_name" required />
      </div>
      <div class="clay-field">
        <label for="password">Password</label>
        <input class="clay-input" id="password" name="password" type="password" required />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Register</button>
    </form>
    <div class="note"><p>After registering, view your profile at <code>/sqli/profile?u=YOUR_USERNAME</code>.</p></div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>
  `)));
});

router.post('/register', (req, res) => {
  const username = String(req.body.username || '').trim().slice(0, 40);
  const displayName = String(req.body.display_name || '').trim().slice(0, 80);
  const password = String(req.body.password || '').slice(0, 80);
  if (!username || !displayName || !password) {
    return res.status(400).send(page('Member Registration', shopShell('Join', `
      <h1>Member registration</h1>
      <div class="warn"><p>All fields are required.</p></div>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/register">Back</a></p>
    `)));
  }
  const db = getDb();
  try {
    // Parameterized: the payload is stored verbatim and sleeps quietly.
    db.prepare('INSERT INTO sqli_members (username, display_name, password) VALUES (?,?,?)')
      .run(username, displayName, password);
  } catch (e) {
    return res.status(400).send(page('Member Registration', shopShell('Join', `
      <h1>Member registration</h1>
      <div class="warn"><p><strong>Could not register:</strong> ${esc(e.message)}</p></div>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli/register">Back</a></p>
    `)));
  }
  res.send(page('Member Registration', shopShell('Welcome', `
    <h1>Welcome, ${esc(username)}</h1>
    <p>Registered as <strong>${esc(username)}</strong>.</p>
    <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/sqli/profile?u=${encodeURIComponent(username)}">View your profile</a></p>
  `)));
});

// Step 2: the profile page interpolates the STORED display name into a new query.
router.get('/profile', (req, res) => {
  const u = String(req.query.u || '');
  const db = getDb();
  const member = u ? db.prepare('SELECT * FROM sqli_members WHERE username = ?').get(u) : null;
  let body = `
    <h1>Member profile</h1>
    ${brief('Member Profile', "Look up a member. The app then finds the matching user account using the member's stored display name.")}
    <form class="clay-card" method="GET" action="/sqli/profile">
      <div class="card-top"><b>Look up a member</b></div>
      <div class="clay-field">
        <label for="u">Username</label>
        <input class="clay-input" id="u" name="u" value="${esc(u)}" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">View profile</button>
    </form>
  `;
  let flagHtml = '';
  if (!member) {
    body += u ? '<div class="warn"><p><strong>No such member.</strong> Register first.</p></div>' : '<p>Enter a member username above.</p>';
  } else {
    // VULN: second-order injection. display_name was stored safely, but it is
    // interpolated into a brand-new query here, where the payload wakes up.
    const sql = `SELECT * FROM users WHERE username='${member.display_name}'`;
    let account = null;
    let error = null;
    try {
      account = db.prepare(sql).get();
    } catch (e) {
      error = e.message;
    }
    body += `<div class="card"><div class="card-top"><b>Member: ${esc(member.username)}</b></div><p>Display name: ${esc(member.display_name)}</p></div>`;
    if (error) {
      body += `<div class="warn"><p><strong>Database error:</strong> ${esc(error)}</p></div>`;
    } else if (account) {
      body += `<div class="tbl-scroll"><table class="tbl">
        <caption class="sr-only">Linked user account</caption>
        <thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead>
        <tbody>
          <tr><th scope="row">Username</th><td>${esc(account.username)}</td></tr>
          <tr><th scope="row">Role</th><td>${esc(account.role)}</td></tr>
          <tr><th scope="row">Email</th><td>${esc(account.email)}</td></tr>
          <tr><th scope="row">Secret</th><td>${esc(account.secret)}</td></tr>
        </tbody>
      </table></div>`;
      // The stored payload genuinely executed when the lookup lands on the
      // admin account for a member who is not admin. The stored display name
      // must contain a quote: without one the value cannot break out of the
      // string literal, so registering display_name='admin' with no injection
      // at all must not award the flag.
      if (account.username === 'admin' && member.username !== 'admin' && member.display_name.includes("'")) {
        flagHtml = flagBox(award(req, 'sqli', 'second-order'));
        flagHtml += fixPanel('sqli', 'second-order');
        flagHtml += fixCta('sqli', 'second-order');
      }
    } else {
      body += '<p>No user account matches this display name.</p>';
    }
  }
  res.send(page('Member Profile (Second-Order SQLi)', shopShell('Members', body + flagHtml + `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/sqli">Back</a></p>`)));
});

module.exports = {
  vuln: {
    id: 'second-order',
    name: 'Second-Order SQL Injection',
    difficulty: 'Hard',
    est: 'about 20 to 40 minutes',
    hint: 'Registration stores your display name safely, but the profile page interpolates that stored value into a brand-new query later. A payload that is harmless at rest becomes SQL when it is reused.',
    hints: ["Register an account through Burp's Proxy, then look at Proxy history: you will see the POST to /sqli/register followed by a GET to /sqli/profile. The injection lands in the first request and fires in the second.", "The profile page reuses your stored display name in a brand-new query. Send the register POST to Repeater and shape the display_name value so it sleeps harmlessly in storage but turns into SQL when the profile lookup reuses it.", "Register a new account with a display name that breaks out of the string literal, then request your profile: the stored value detonates in the second query and lands the lookup on the admin account."],
    tools: "BZ, B",
    how: 'Register with a display name containing a quote-breakout, then view your profile to trigger the stored injection and land on the admin account.',
    link: '/sqli/register',
    start: "Browse to /sqli/register in the Burp browser with the Proxy running, register an account, then find both requests (the POST to /sqli/register and the GET to /sqli/profile) in Proxy history.",
  },
  router,
};
