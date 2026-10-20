'use strict';
// Absolute continue URL: GET/POST /hostheader/login builds the post-login
// destination (and the 302 Location) as an absolute URL from the Host header.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');
const { esc, page, flagBox, fixPanel, brief, hintLadder, payloadBlock } = require('../../../lib/page');
// Module-level helper (lives in modules/hostheader/shared.js, placed by the
// module finisher; not copied here): isLocalHost(host) is true for
// localhost / 127.0.0.1 / ::1 and empty hosts only.
// Module-level middleware (placed in the finisher's index.js):
// express.urlencoded({ extended: false }) so POST /login sees req.body.
const { isLocalHost } = require('../shared');

const router = express.Router();

const APP = 'Nimbus Member Portal';

function shell(crumb, bodyHtml) {
  return `<section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">N</span><b>${esc(APP)}</b><span class="dim">${esc(crumb)}</span></div>
    ${bodyHtml}
  </section>`;
}

function navRow(links) {
  const all = (links || []).concat([['/hostheader', 'Module index']]);
  return `<p>${all.map(([href, label]) =>
    `<a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(href)}">${esc(label)}</a>`).join(' ')}</p>`;
}

function loginForm(cont) {
  return `<form method="POST" action="/hostheader/login">
    <div class="clay-field">
      <label for="username">Username</label>
      <input class="clay-input" id="username" name="username" type="text" required autocomplete="username" />
    </div>
    <div class="clay-field">
      <label for="password">Password</label>
      <input class="clay-input" id="password" name="password" type="password" required autocomplete="current-password" />
    </div>
    <input type="hidden" name="continue" value="${esc(cont)}" />
    <button type="submit" class="clay-btn clay-btn-primary">Log in</button>
  </form>`;
}

// GET /hostheader/login -> sign-in page showing the absolute continue URL.
router.get('/login', (req, res) => {
  const host = req.headers.host || '';
  const cont = String(req.query.continue || '/hostheader/dashboard');
  // VULN: the post-login "continue" destination is rendered as an absolute URL
  // built from the Host header.
  const absolute = 'http://' + host + cont;
  res.send(page('Sign in', `
    ${shell('Sign in', `
      <h2>Welcome back</h2>
      ${brief('Where you are heading', `After you sign in you continue to the
        page below. The portal builds this link from the request host:`)}
      ${payloadBlock('Continue URL', absolute)}
      ${loginForm(cont)}
      <p class="dim"><b>Demo accounts:</b> alice / alice123, bob / bob123.
      Tip: poison the <code>Host</code> header on the login request in
      Repeater, log in, and read the 302 <code>Location</code> header in the
      response to see where it points.</p>
    `)}
    ${hintLadder(vuln)}
    ${navRow([])}
  `));
});

// POST /hostheader/login -> credential check, then a 302 built from Host.
router.post('/login', (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  const cont = String(req.body.continue || '/hostheader/dashboard');
  const user = getDb()
    .prepare('SELECT * FROM users WHERE username = ? AND password = ?')
    .get(username, password);
  if (!user) {
    return res.status(401).send(page('Sign in', `
      ${shell('Sign in', `
        <h2>Sign in failed</h2>
        <p class="clay-err" role="alert">Bad credentials.</p>
      `)}
      ${navRow([['/hostheader/login', 'Try again']])}
    `));
  }
  const host = req.headers.host || '';
  // VULN: the post-login redirect is an absolute URL built from the Host header.
  const target = 'http://' + host + (cont.startsWith('/') ? cont : '/' + cont);
  let flagHtml = '';
  if (!isLocalHost(host)) {
    const flag = award(req, 'hostheader', 'host-abs-url');
    flagHtml = `<hr /><p>Login succeeded, and the 302 below points at the
      attacker-controlled host from the poisoned header.</p>${flagBox(flag)}${fixPanel('hostheader', 'host-abs-url')}`;
  }
  res.status(302).set('Location', target).send(page('Signed in', `
    ${shell('Signed in', `
      <h2>Welcome, ${esc(user.username)}</h2>
      <p>Continuing to <a href="${esc(target)}">${esc(target)}</a> ...</p>
      ${flagHtml}
    `)}
    ${navRow([])}
  `));
});

const vuln = {
  id: 'host-abs-url',
  name: 'Absolute Continue URL',
  difficulty: 'Easy',
    est: '5-10 minutes',
  hint: 'The login page renders an absolute continue URL built from Host, and the post-login 302 uses it too.',
  hints: [
    "In Repeater, POST /hostheader/login and change only the Host header before sending.",
    "The 302 Location is built from your Host header with no allowlist. Claim a host you control and watch where the post-login redirect points.",
    "The key insight: the app never checks your Host against any allowlist, so the 302 destination becomes whatever host you name.",
  ],
  tools: 'BZ, B',
  how: 'The login page builds its continue address from a header you control, and the post-login redirect believes it. Whose domain ends up in that address is up to you.',
  link: '/hostheader#host-abs-url',
  start: 'Open Burp, proxy the login page in your browser, send the sign-in request to Repeater, edit the Host header, and log in as alice / alice123.',
};

module.exports = { vuln, router };
