'use strict';
// Comment Deletion IDOR: deletion is keyed by comment id only, authorship is never checked.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { deny, ensureComments, requireUser, shopPage } = require('../shared');

const router = express.Router();

router.get('/comments', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  ensureComments();
  const comments = getDb().prepare('SELECT id, author, body FROM comments ORDER BY id').all();
  const rows = comments.map((c) => {
    const action = c.author === u.username
      ? `<form method="POST" action="/idor/comments/delete">
           <input type="hidden" name="id" value="${Number(c.id)}">
           <button type="submit" class="clay-btn clay-btn-secondary clay-btn-sm">Delete</button>
         </form>`
      : '<span class="dim">Not yours</span>';
    return `<tr><td>${Number(c.id)}</td><td>${esc(c.author)}</td><td>${esc(c.body)}</td><td>${action}</td></tr>`;
  }).join('');
  res.send(shopPage(u, 'Community comments', `
    <div class="tbl-scroll"><table class="tbl">
      <caption>Latest comments</caption>
      <thead><tr><th scope="col">ID</th><th scope="col">Author</th><th scope="col">Comment</th><th scope="col">Action</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    ${hintLadder(module.exports.vuln)}
  `));
});

router.post('/comments/delete', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const id = parseInt(req.body.id, 10);
  const c = getDb().prepare('SELECT id, author FROM comments WHERE id = ?').get(id);
  if (!c) {
    return deny(res, 404, 'Not found',
      '<p class="muted">No comment with that id.</p><p><a href="/idor/comments">Back to comments</a></p>');
  }
  // VULN: deletion is keyed by comment id only; authorship is never checked.
  getDb().prepare('DELETE FROM comments WHERE id = ?').run(id);
  let flagHtml = '';
  // Award: a non-admin member deleting a comment written by someone else.
  if (c.author !== u.username && u.role !== 'admin') {
    flagHtml = flagBox(award(req, 'idor', 'idor-comment-delete')) + fixPanel('idor', 'idor-comment-delete');
  }
  res.send(shopPage(u, 'Comment deleted', `
    <div class="note"><p>Comment <b>#${Number(c.id)}</b> by <b>${esc(c.author)}</b> was deleted.</p></div>
    ${flagHtml}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/idor/comments">Back to comments</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'idor-comment-delete',
    name: 'Comment Deletion IDOR',
    difficulty: 'Easy',
    hint: 'The delete button on /idor/comments sends only the comment id. Log in as bob and delete a comment written by someone else.',
    hints: [
      'The delete button sends a comment id. Does the server check that you wrote the comment?',
      'You only get a delete button for your own comments. Click it once with Burp intercepting, then send that POST to Repeater and try a different id.',
      'Log in as bob, note the id of a comment written by someone else in the comments table, then use Repeater to send the delete request for that id.',
    ],
    tools: 'BZ, B',
    how: 'Delete another user\'s comment by submitting its id to the delete endpoint from Repeater.',
    link: '/idor#idor-comment-delete',
    start: 'Point your browser at Burp\'s proxy, then visit http://localhost:3000/idor/login/bob to log in and open /idor/comments.',
  },
  router,
};
