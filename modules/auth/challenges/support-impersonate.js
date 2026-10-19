'use strict';
// Support Ticket Impersonation: sequential ticket numbers log the caller in as the ticket owner with no staff check.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, emptyState } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { getDb } = require('../../../lib/db');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'support-impersonate',
  name: 'Support Ticket Impersonation',
  difficulty: 'Medium',
  hint: 'Tickets are sequential, and one of them belongs to admin. The support endpoint never checks that you are staff.',
  hints: ["Open someone else's ticket: which Burp step turns the ticket number into a variable you can walk?", "The ticket number is in the query string, and the page says tickets are sequential around the recent range. Send the request to Repeater and step through the numbers one by one.", "For the full sweep, send the request to Intruder, put the payload marker on the ticket value, load a numbers payload over the recent range, and look for the response that signs you in as someone important."],
  tools: 'BZ, B',
  how: 'Walk the sequential ticket numbers at /auth/support/login in Burp Repeater or Intruder until a response lands an admin session.',
  link: '/auth/support',
  start: 'Open http://localhost:3000/auth/support through the Burp proxy browser, submit a ticket number once, then send that request to Repeater.',
};

function ensureSupportTickets() {
  const db = getDb();
  db.exec(`CREATE TABLE IF NOT EXISTS auth_support_tickets (
    ticket INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    subject TEXT NOT NULL
  )`);
  const count = db.prepare('SELECT COUNT(*) AS c FROM auth_support_tickets').get().c;
  if (count === 0) {
    const idOf = (n) => db.prepare('SELECT id FROM users WHERE username = ?').get(n).id;
    const ins = db.prepare('INSERT INTO auth_support_tickets (ticket, user_id, subject) VALUES (?,?,?)');
    ins.run(1001, idOf('alice'), 'Password reset help');
    ins.run(1002, idOf('bob'), 'Locked out of account');
    ins.run(1003, idOf('alice'), 'Billing question');
    ins.run(1004, idOf('bob'), 'API access request');
    ins.run(1005, idOf('admin'), 'Urgent: admin account recovery');
  }
}
ensureSupportTickets();

function ticketForm(value) {
  return `<form method="GET" action="/auth/support/login">
    ${shared.field({ id: 'ticket', name: 'ticket', label: 'Ticket number', value })}
    ${shared.submitButton('Open customer session')}
  </form>`;
}

router.get('/support', (req, res) => {
  res.send(
    page(
      'Support desk',
      brief(
        'Support staff portal',
        `Northwind support agents paste a <b>ticket number</b> to jump straight
         into the customer's session. Recent tickets sit in the 1001-1005
         range. Land a session that matters.`
      ) +
        shared.portal('Support desk', `
  ${ticketForm('1001')}`, 'Northwind Support Desk') +
        hintLadder(vuln) +
        shared.navLinks([])
    )
  );
});

router.get('/support/login', (req, res) => {
  const n = parseInt(req.query.ticket, 10);
  const row = Number.isNaN(n)
    ? null
    : getDb()
        .prepare(
          `SELECT t.ticket, t.subject, u.username, u.role
           FROM auth_support_tickets t JOIN users u ON u.id = t.user_id
           WHERE t.ticket = ?`
        )
        .get(n);

  if (!row) {
    return res.send(
      page(
        'Unknown ticket',
        shared.portal('Support desk', `<h2>Unknown ticket</h2>
  <p class="clay-err" role="alert">No ticket <b>${esc(req.query.ticket || '')}</b> exists.</p>
  ${ticketForm(String(req.query.ticket || '1001').slice(0, 20))}`, 'Northwind Support Desk') +
          shared.navLinks([['/auth/support', 'Back to the support desk']])
      )
    );
  }

  // VULN: predictable sequential ticket ids plus zero authorization on the
  // support endpoint means anyone can impersonate any customer, even admin.
  req.session.authUser = row.username;
  let extra = '';
  if (row.role === 'admin') {
    extra = flagBox(award(req, 'auth', 'support-impersonate')) + fixPanel('auth', 'support-impersonate');
  }
  res.send(
    page(
      'Support session',
      shared.portal('Customer session', `<h2>Acting as ${esc(row.username)}</h2>
  <p>Ticket <b>${n}</b> (${esc(row.subject)}) accepted. You are now signed in as
  <b>${esc(row.username)}</b> (role <b>${esc(row.role)}</b>).</p>`, 'Northwind Support Desk') +
        extra +
        shared.navLinks([['/auth/settings', 'Open account settings'], ['/auth/support', 'Another ticket']])
    )
  );
});

// Account settings page for the active session identity; the target of the
// "Open account settings" link shown after a support session is opened.
router.get('/settings', (req, res) => {
  const me = shared.authSessionUser(req);
  const u = me ? shared.findUser(me) : null;
  if (!u) {
    return res.send(
      page(
        'Account settings',
        emptyState(
          'No active session',
          '<p>Open a customer session from the support desk to see their account settings.</p>',
          '<p><a class="clay-btn clay-btn-primary" href="/auth/support">Support desk</a></p>'
        ) + shared.navLinks([])
      )
    );
  }
  res.send(
    page(
      'Account settings',
      shared.portal('Account settings', `<h2>Signed in as ${esc(u.username)}</h2>
  <div class="tbl-scroll"><table class="tbl">
    <caption class="sr-only">Account details</caption>
    <thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead>
    <tbody>
      <tr><th scope="row">Username</th><td>${esc(u.username)}</td></tr>
      <tr><th scope="row">Email</th><td>${esc(u.email)}</td></tr>
      <tr><th scope="row">Role</th><td>${esc(u.role)}</td></tr>
    </tbody>
  </table></div>`) +
        shared.navLinks([['/auth/change-password', 'Change password'], ['/auth/support', 'Support desk']])
    )
  );
});

module.exports = { vuln, router };
