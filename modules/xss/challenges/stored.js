'use strict';
// Stored XSS: guestbook entries are saved verbatim and rendered unencoded.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, emptyState, errorPage, claimBox, fixCta } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');

const router = express.Router();

router.get('/guestbook', (req, res) => {
  const db = getDb();
  // The shared comments table is seeded with one benign comment already.
  const rows = db.prepare('SELECT author, body, created_at FROM comments ORDER BY id DESC').all();
  // VULN: stored comment author and body are rendered raw, no output encoding.
  const items = rows.map((r) => `
    <article class="card">
      <p><b>${r.author}</b> <span class="muted">${esc(r.created_at)}</span></p>
      <p>${r.body}</p>
    </article>`).join('\n');
  res.send(page('Guestbook · Maple Street Cafe', `
    <h2>Maple Street Cafe</h2>
    ${xssNonceTag(req, 'stored')}
    ${siteFrame('Maple Street Cafe', ['Menu', 'Guestbook', 'Visit us'], `
      <p>Tell us how your visit went. Entries appear on this page for every visitor.</p>
      <form method="POST" action="/xss/guestbook">
        <div class="clay-field">
          <label for="author">Your name</label>
          <input class="clay-input" type="text" id="author" name="author" placeholder="Jordan" maxlength="80" required>
        </div>
        <div class="clay-field">
          <label for="body">Your message</label>
          <textarea class="clay-input" id="body" name="body" rows="4" placeholder="The flat white was excellent." maxlength="2000" required></textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Sign guestbook</button>
      </form>`)}
    <h3>Messages</h3>
    ${items || emptyState('No messages yet', '<p>Be the first to sign the guestbook.</p>')}
    ${claimBox({ vulnId: 'stored', payload: esc(`<script>${beacon('stored')}</script>`), statusUrl: '/xss/claim-status?v=stored' })}
    ${fixCta('xss', 'stored')}
    ${backLinks('stored')}
  `));
});

router.post('/guestbook', (req, res) => {
  const author = String(req.body.author || '').slice(0, 80);
  const body = String(req.body.body || '').slice(0, 2000);
  if (!author.trim() || !body.trim()) {
    return res.status(400).send(page('Guestbook · Maple Street Cafe', errorPage(400, 'Name and message are required',
      '<p>Both fields must be filled in to sign the guestbook.</p><p><a href="/xss/guestbook">Back to the guestbook</a></p>')));
  }
  const db = getDb();
  // Prepared statement keeps this about XSS only; input is stored verbatim.
  db.prepare('INSERT INTO comments (author, body) VALUES (?, ?)').run(author, body);
  res.redirect('/xss/guestbook');
});

module.exports = {
  vuln: {
    id: 'stored',
    name: 'Stored XSS',
    difficulty: 'Easy',
    hint: 'Comments are saved and shown to every visitor unescaped. Your payload persists and fires on every page view.',
    hints: [
      'Comments are saved and shown to every visitor. Where does your comment end up in the HTML?',
      'Send the sign-guestbook POST to Burp Repeater. The comment is stored verbatim and rendered raw, so your payload persists in the database and fires for every page view.',
      'Plant a beacon comment via Repeater that calls /xss/collect (parameters c, v=stored and n=window.__px), then reload the guestbook in your proxied browser so your own browser executes it and fires the beacon.',
    ],
    tools: 'BZ, B',
    how: 'In Burp Repeater, POST the exfiltration payload as a guestbook comment, then reload the guestbook in your proxied browser so the stored payload fires.',
    link: '/xss/guestbook',
    start: 'Start Burp Proxy, browse to /xss/guestbook in your proxied browser, and read the Messages list. Then send the sign-guestbook POST to Repeater: the body field is stored verbatim and rendered raw for every visitor.',
  },
  router,
};
