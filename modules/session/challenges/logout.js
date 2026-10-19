'use strict';
// Logout Does Not Destroy the Session: logout only flips a flag, so the old
// session id still opens the admin page after "logging out".
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, toolsPill } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

// Per-lab session store: sid -> { user, role, loggedOut }. Never shared across labs.
const logoutStore = new Map();

const vuln = {
  id: 'logout',
  name: 'Logout Does Not Destroy the Session',
  difficulty: 'Easy',
  hint: 'Logging out should kill the server-side session. Here it only shows you a goodbye page. Replay the old cookie in Repeater.',
  hints: [
    'With Burp Proxy running, log in as admin and log out in your browser. Which Cookie header did the browser send?',
    "Send the logout request to Repeater, note the lab_sid value, then log out. The logout flips a flag but never deletes the session server-side.",
    'In Repeater, replay the GET /session/logoutdemo/secret request with the old lab_sid cookie you captured before logging out.',
  ],
  tools: 'BZ, B',
  how: 'Log in as admin, capture the lab_sid cookie through Burp Proxy, log out, then replay the secret admin request in Burp Repeater with the same cookie.',
  link: '/session#logout',
  start: 'Open Burp Proxy and browse to http://localhost:3000/session/logoutdemo in your proxied browser. Log in as admin, then visit the logout page and watch which Cookie header the browser keeps sending.',
};

// Clay-styled 403 page (same denials as the module helper, full clay).
function deniedPage(msg) {
  return page('Denied', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">!</span><b>Acme Portal</b><span class="dim">Access denied</span></div>
      <h2>Access denied</h2>
      <p class="clay-err" role="alert">${esc(msg)}</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session">Back to the Session module</a></p>
    </section>`);
}

// Clay login card used by the challenge pages in this file.
function loginCard(action, crumb) {
  return `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">${esc(crumb)}</span></div>
      <form method="POST" action="${esc(action)}">
        <div class="clay-field">
          <label for="username">Username</label>
          <input class="clay-input" id="username" name="username" type="text" placeholder="username (try admin)" required />
        </div>
        <div class="clay-field">
          <label for="password">Password</label>
          <input class="clay-input" id="password" name="password" type="password" placeholder="password (try admin123)" required />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Log in</button>
      </form>
    </section>`;
}

function backLink() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session">Back to the Session module</a></p>`;
}

// GET /session/logoutdemo -> login page for the broken-logout lab.
router.get('/logoutdemo', (req, res) => {
  res.send(page('Login (logout)', `
    ${brief('Broken logout lab', `
      <p>Log in as <code>admin</code> / <code>admin123</code>, then log out, then try
      to use the old session anyway.</p>`)}
    ${loginCard('/session/logoutdemo/login', 'Sign in')}
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}
    ${backLink()}
  `));
});

// POST /session/logoutdemo/login -> issue a fresh server-side session.
router.post('/logoutdemo/login', (req, res) => {
  const user = shared.checkCreds(req.body.username, req.body.password);
  if (!user) return res.status(403).send(deniedPage('Bad username or password.'));
  const sid = shared.genSid();
  logoutStore.set(sid, { user: user.username, role: user.role, loggedOut: false });
  shared.setSid(res, sid);
  res.redirect('/session/logoutdemo/home');
});

// GET /session/logoutdemo/home -> session home, only for live sessions.
router.get('/logoutdemo/home', (req, res) => {
  const s = logoutStore.get(shared.sidOf(req));
  if (!s || s.loggedOut) return res.status(403).send(deniedPage('No active session. Log in first.'));
  res.send(page('Home (logout)', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Home</span></div>
      <h2>Welcome, ${esc(s.user)}</h2>
      <p>
        <a class="clay-btn clay-btn-primary clay-btn-sm" href="/session/logoutdemo/secret">Secret admin page</a>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session/logoutdemo/logout">Log out</a>
      </p>
    </section>
    ${backLink()}
  `));
});

// GET /session/logoutdemo/logout -> "logs out" without killing the session.
router.get('/logoutdemo/logout', (req, res) => {
  const s = logoutStore.get(shared.sidOf(req));
  // VULN: logout only flips a flag; the server-side session (and its cookie)
  // stays valid, so the "dead" session can still be replayed.
  if (s) s.loggedOut = true;
  res.send(page('Logged out', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Signed out</span></div>
      <h2>Logged out</h2>
      <p>You have been logged out. Your session cookie is now worthless... or is it?
      Try the <a href="/session/logoutdemo/secret">secret admin page</a> with the same cookie.</p>
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/session/logoutdemo/secret">Secret admin page</a></p>
    </section>
    ${backLink()}
  `));
});

// GET /session/logoutdemo/secret -> admin page, still reachable after logout.
router.get('/logoutdemo/secret', (req, res) => {
  const s = logoutStore.get(shared.sidOf(req));
  if (!s || s.role !== 'admin') return res.status(403).send(deniedPage('Admins only.'));
  if (!s.loggedOut) {
    return res.send(page('Secret admin page', `
      <section class="clay-card">
        <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Secret admin page</span></div>
        <h2>Secret admin page</h2>
        <p>You are viewing this with a live session. Log out first, then come back
        with the same cookie to prove the session survived.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session/logoutdemo/home">Back</a></p>
      </section>
      ${backLink()}`));
  }
  const flag = award(req, 'session', 'logout');
  return res.send(page('Secret admin page', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Secret admin page</span></div>
      <h2>Secret admin page</h2>
      <div class="warn"><p><b>Logout bypass confirmed.</b> You logged out, but the
      server kept your session alive, and the old cookie still opens the admin page.</p></div>
      ${flagBox(flag)}
      ${fixPanel('session', 'logout')}
    </section>
    ${backLink()}`));
});

module.exports = { vuln, router };
