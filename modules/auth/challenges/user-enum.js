'use strict';
// Username Enumeration: the login answers "user not found" and "wrong password" differently, confirming which accounts exist.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'user-enum',
  name: 'Username Enumeration',
  difficulty: 'Easy',
  hint: 'The login says "user not found" for bad usernames but "wrong password" for real ones. Probe names like alice, bob, admin, or anything else, then submit the confirmed username on the submit page.',
  hints: ["Try logging in with a wrong username vs a wrong password. Does the error message change?", "Different errors for 'bad username' vs 'bad password' reveal which usernames exist. That's an oracle.", "Enumerate usernames by comparing error messages, then submit a valid one."],
  tools: 'B, C',
  how: 'Enumerate a valid username through the different error messages and submit it.',
  link: '/auth/enum-login',
  start: 'curl -c jar -b jar -d "username=nosuchuser&password=x" http://localhost:3000/auth/enum-login',
};

function loginView(req, opts) {
  const o = opts || {};
  return page(
    'Sign in',
    brief(
      'Which accounts exist?',
      `Northwind staff sign in here. Find out which usernames are real by
       probing the form, then report a username you have confirmed on the
       <a href="/auth/enum-submit">submit page</a>.`
    ) +
      shared.portal('Staff sign in', `
  ${shared.errorLine(o.error)}
  <form method="POST" action="/auth/enum-login">
    ${shared.field({ id: 'username', name: 'username', label: 'Username', attrs: 'autocomplete="username"' })}
    ${shared.field({ id: 'password', name: 'password', label: 'Password', type: 'password', attrs: 'autocomplete="current-password"' })}
    ${shared.submitButton('Sign in')}
  </form>`) +
      hintLadder(vuln) +
      shared.navLinks([['/auth/enum-submit', 'Submit a found username']])
  );
}

router.get('/enum-login', (req, res) => {
  res.send(loginView(req));
});

router.post('/enum-login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = shared.findUser(username);

  // VULN: the error message reveals whether the username exists, so an
  // attacker can enumerate valid accounts one probe at a time.
  if (!user) {
    return res.send(loginView(req, { error: `User <b>${esc(username)}</b> not found.` }));
  }
  if (user.password !== password) {
    req.session.enumFound = req.session.enumFound || [];
    if (!req.session.enumFound.includes(user.username)) {
      req.session.enumFound.push(user.username);
    }
    return res.send(loginView(req, { error: `Wrong password for user <b>${esc(user.username)}</b>.` }));
  }
  req.session.authUser = user.username;
  return res.send(
    page(
      'Welcome',
      shared.portal('Dashboard', `<h2>Welcome back, ${esc(user.username)}!</h2>
  <p>You are signed in for the other auth labs.</p>`) +
        shared.navLinks([])
    )
  );
});

router.get('/enum-submit', (req, res) => {
  res.send(
    page(
      'Submit enumerated username',
      brief(
        'Prove the enumeration',
        `Enter a username you confirmed exists through the
         <a href="/auth/enum-login">sign-in form</a>, using only what its
         responses told you.`
      ) +
        shared.portal('Report a username', `
  <form method="POST" action="/auth/enum-submit">
    ${shared.field({ id: 'username', name: 'username', label: 'Enumerated username' })}
    ${shared.submitButton('Submit')}
  </form>`) +
        hintLadder(vuln) +
        shared.navLinks([['/auth/enum-login', 'Back to the sign-in form']])
    )
  );
});

router.post('/enum-submit', (req, res) => {
  const username = String(req.body.username || '').trim();
  const found =
    (req.session.enumFound || []).includes(username) && shared.findUser(username);
  let extra = '';
  if (found) extra = flagBox(award(req, 'auth', 'user-enum')) + fixPanel('auth', 'user-enum');
  res.send(
    page(
      'Enumeration result',
      shared.portal('Enumeration result', `<h2>Enumeration result</h2>
  ${found
    ? `<p>Username <b>${esc(username)}</b> confirmed through the sign-in responses.</p>`
    : `<p class="clay-err" role="alert">Not confirmed: <b>${esc(username)}</b> was not found through the sign-in form in this session.</p>`}`) +
        extra +
        shared.navLinks([['/auth/enum-login', 'Back to the sign-in form'], ['/auth/enum-submit', 'Submit another']])
    )
  );
});

module.exports = { vuln, router };
