'use strict';
// Username Enumeration: the login answers "user not found" and "wrong password" differently, confirming which accounts exist.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');
const { passwordMatches } = require('../../../lib/account-state');

const router = express.Router();

const vuln = {
  id: 'user-enum',
  name: 'Username Enumeration',
  difficulty: 'Easy',
  hint: 'The login answers differently for unknown usernames than it does for real ones with a bad password. Probe names like alice, bob, admin, or anything else, then submit the confirmed username on the submit page.',
  hints: ["Log in once with a made-up username, then once with a real-sounding one and a bad password. Compare the two responses in Burp: what changed between them?", "That difference is an oracle for which accounts exist: one answer for names that do not, another for names that do. Send the login POST to Intruder and set a sniper payload position on the username field.", "In Intruder, mark only the username parameter with the payload marker, load a short candidate wordlist, and add a Grep-Match rule for the exact phrase you observed in your own probe of a real account (copy it from your probe response, not from any hint: the hint ladder renders on this very page, so any phrase written here would match every response and hide the oracle). Submit one you confirmed, in the same browser session."],
  tools: 'BZ, B',
  est: 'about 10 minutes',
  how: 'Sniper through candidate usernames at /auth/enum-login in Burp Intruder, spot the valid ones by their different response (Grep-Match on the phrase from your own probe), then submit a confirmed username in the same session.',
  link: '/auth/enum-login',
  start: 'Open /auth/enum-login through the Burp proxy browser, submit the form once with a guess, then send that POST to Intruder.',
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
  if (!passwordMatches(req, user, password)) {
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
