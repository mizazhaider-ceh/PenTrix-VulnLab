'use strict';
// No Rate Limiting (Brute-Force Login): POST /auth/login never throttles, locks out or challenges failed attempts.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'brute-force',
  name: 'No Rate Limiting (Brute-Force Login)',
  difficulty: 'Medium',
  hint: 'There is no rate limiting, no lockout, and no CAPTCHA. Alice\'s password is very weak. If a few tries don\'t work, script it: the counter resets only on success, and the flag lands when you finally log in as alice after at least 5 failed attempts in the same session.',
  hints: ["The login has no rate limit, no lockout, no CAPTCHA. What does that mean for password guessing?", "Without throttling, you can try thousands of passwords. Alice's password is weak and guessable.", "Script the login attempts (or guess manually). The flag lands when you log in as alice after 5+ failed attempts in one session."],
  tools: 'B, P',
  how: 'Brute-force / guess alice\'s weak password; the flag is awarded once you log in as alice after 5+ failed attempts in one session.',
  link: '/auth/login',
  start: 'curl -i -c jar -b jar -d "username=alice&password=letmein" http://localhost:3000/auth/login',
};

function loginView(req, opts) {
  const o = opts || {};
  const attempts = req.session.authAttempts || 0;
  const signedIn = shared.authSessionUser(req);
  return page(
    'Sign in',
    brief(
      'Take over alice\'s account',
      `Alice is a Northwind customer who picked a short, memorable password.
       Sign in as <b>alice</b> to prove the account is yours. The lab tracks
       failed sign-ins per browser session, so keep your cookie between requests.`
    ) +
      shared.portal('Sign in', `
  ${shared.errorLine(o.error)}
  <form method="POST" action="/auth/login">
    ${shared.field({ id: 'username', name: 'username', label: 'Username', value: o.username !== undefined ? o.username : 'alice', attrs: 'autocomplete="username"' })}
    ${shared.field({ id: 'password', name: 'password', label: 'Password', type: 'password', attrs: 'autocomplete="current-password"' })}
    ${shared.submitButton('Sign in')}
  </form>
  <p class="dim">Failed sign-ins this session: <b>${attempts}</b>${signedIn ? ` (currently signed in as <b>${esc(signedIn)}</b>)` : ''}</p>`) +
      hintLadder(vuln) +
      shared.navLinks([])
  );
}

router.get('/login', (req, res) => {
  res.send(loginView(req));
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = shared.findUser(username);
  const attempts = req.session.authAttempts || 0;

  if (user && user.password === password) {
    // VULN: no rate limiting or account lockout, and the server happily
    // reports how many failed attempts preceded a success.
    let extra = '';
    if (username === 'alice' && attempts >= 5) {
      extra = flagBox(award(req, 'auth', 'brute-force')) + fixPanel('auth', 'brute-force');
    }
    req.session.authAttempts = 0; // counter resets on success
    req.session.authUser = username; // login identity used by the other auth labs
    return res.send(
      page(
        'Welcome',
        shared.portal('Dashboard', `<h2>Welcome back, ${esc(user.username)}!</h2>
  <p>Role: <b>${esc(user.role)}</b>. You signed in after <b>${attempts}</b> failed
  attempt(s) this session.</p>`) +
          extra +
          shared.navLinks([['/auth/login', 'Back to sign in']])
      )
    );
  }

  req.session.authAttempts = attempts + 1;
  return res.send(loginView(req, { error: 'Invalid username or password.', username }));
});

module.exports = { vuln, router };
