'use strict';
// Guessable Security Question: the "secret" answer (mother's maiden name) is printed in each user's public profile.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, errorPage } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { getDb } = require('../../../lib/db');
const { setPasswordOverride } = require('../../../lib/account-state');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'security-question',
  name: 'Guessable Security Question',
  difficulty: 'Easy',
  hint: 'The reset asks for the mother\'s maiden name, and alice printed hers in her public bio. Read the bio, answer the question, reset her password.',
  hints: [
    "The security question asks for something 'only you know', but the bio is public. Browse /auth/bio/alice through Burp Proxy and read it.",
    'Security questions are just weak passwords when the answer is printed on a public page.',
    "Send the reset POST to Burp's Repeater, fill in the public answer, and set a new password.",
  ],
  tools: 'BZ, B',
  how: 'Read alice\'s public bio for the maiden name, then answer the security question at /auth/question-reset to reset her password. Proxy and Repeater carry the whole chain.',
  link: '/auth/question-reset',
  start: 'With Burp Proxy on your browser, open /auth/question-reset and read alice\'s public bio at /auth/bio/alice.',
};

const MAIDEN_NAMES = { alice: 'Smith', bob: 'Jones', admin: 'Blackwood' };
const PUBLIC_BIOS = {
  alice:
    "Alice loves CTFs and sticker packs. A fun fact she tells everyone at meetups: her mother's maiden name is Smith.",
  bob:
    'Bob collects USB rubber duckies (training ones only). His go-to party story involves his mother\'s maiden name: Jones.',
  admin:
    'The admin keeps this lab running. Ancient forum posts mention the family name Blackwood more than once.',
};

router.get('/bio/:username', (req, res) => {
  const name = String(req.params.username || '').toLowerCase();
  const u = shared.findUser(name);
  if (!u || !PUBLIC_BIOS[name]) {
    return res.status(404).send(
      page(
        'No such profile',
        errorPage(404, 'No public profile', `<p>Northwind has no public profile for <b>${esc(name)}</b>.</p>
<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/auth/question-reset">Password reset</a></p>`)
      )
    );
  }
  res.send(
    page(
      `${u.username}'s profile`,
      shared.portal('Community profile', `<h2>${esc(u.username)}</h2>
  <p>${esc(PUBLIC_BIOS[name])}</p>
  <div class="tbl-scroll"><table class="tbl">
    <caption class="sr-only">Other community profiles</caption>
    <thead><tr><th scope="col">Member</th><th scope="col">Profile</th></tr></thead>
    <tbody>
      <tr><th scope="row">alice</th><td><a href="/auth/bio/alice">View profile</a></td></tr>
      <tr><th scope="row">bob</th><td><a href="/auth/bio/bob">View profile</a></td></tr>
      <tr><th scope="row">admin</th><td><a href="/auth/bio/admin">View profile</a></td></tr>
    </tbody>
  </table></div>`) +
        shared.navLinks([['/auth/question-reset', 'Reset via security question']])
    )
  );
});

router.get('/question-reset', (req, res) => {
  res.send(
    page(
      'Reset via security question',
      brief(
        'Reset alice\'s password',
        `Forgot your password? Northwind lets you reset it by answering the
         security question: <b>what is your mother's maiden name?</b>
         Members share plenty about themselves on their
         <a href="/auth/bio/alice">community profiles</a>.`
      ) +
        shared.portal('Account recovery', `
  <form method="POST" action="/auth/question-reset">
    ${shared.field({ id: 'username', name: 'username', label: 'Username', value: 'alice' })}
    ${shared.field({ id: 'answer', name: 'answer', label: 'Mother\'s maiden name' })}
    ${shared.field({ id: 'newPassword', name: 'newPassword', label: 'New password', type: 'password', attrs: 'autocomplete="new-password"' })}
    ${shared.submitButton('Reset password')}
  </form>`) +
        hintLadder(vuln) +
        shared.navLinks([['/auth/bio/alice', 'Community profiles']])
    )
  );
});

router.post('/question-reset', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const answer = String(req.body.answer || '').trim();
  const newPassword = String(req.body.newPassword || '');
  const u = shared.findUser(username);

  // VULN: the "secret" answer is public knowledge (printed in the user's bio),
  // so the security question is not authentication at all.
  if (
    !u ||
    !newPassword ||
    (MAIDEN_NAMES[username] || '').toLowerCase() !== answer.toLowerCase()
  ) {
    return res.send(
      page(
        'Reset failed',
        shared.portal('Account recovery', `<h2>Reset failed</h2>
  <p class="clay-err" role="alert">Wrong answer to the security question.</p>`) +
          shared.navLinks([['/auth/question-reset', 'Try again']])
      )
    );
  }

  // Multi-student isolation (P1-1): the new password lives in this session
  // only; the shared users table keeps the seeded value.
  setPasswordOverride(req, u.username, newPassword);
  const extra = flagBox(award(req, 'auth', 'security-question')) + fixPanel('auth', 'security-question');
  res.send(
    page(
      'Password changed',
      shared.portal('Account recovery', `<h2>Password changed</h2>
  <p>The password for <b>${esc(u.username)}</b> was reset with the security question answer.</p>`) +
        extra +
        shared.navLinks([['/auth/login', 'Sign in']])
    )
  );
});

module.exports = { vuln, router };
