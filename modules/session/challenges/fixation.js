'use strict';
// Session Fixation: the pre-login session id is kept after login instead of
// being regenerated, so an attacker-chosen sid becomes an authenticated session.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, toolsPill } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

// Per-lab session store: sid -> { user, role }. Never shared across labs.
const fixationStore = new Map();

const vuln = {
  id: 'fixation',
  name: 'Session Fixation',
  difficulty: 'Medium',
  hint: "The server keeps whatever session id you arrived with, even across login. Set the victim's cookie to a value you chose, then let them log in.",
  hints: [
    'Log in, then check your session id. Did it change from before login?',
    "The pre-login sid is kept after login. Fixate a victim's sid, wait for their login, then use it.",
    "Get a sid, don't log in. Have the 'victim' (or yourself in another browser) log in with that sid. The sid is now authed.",
  ],
  tools: 'B, DT',
  how: 'Fix the lab_sid cookie to a known value, log in as admin, and confirm the sid did not change.',
  link: '/session#fixation',
  start: 'curl -s -c jar -b jar http://localhost:3000/session/fixation/preset\ncurl -s -b jar -c jar -d "username=admin&password=admin123" http://localhost:3000/session/fixation/login',
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

// GET /session/fixation -> attack console: fix the sid, then log in.
router.get('/fixation', (req, res) => {
  const current = shared.sidOf(req);
  res.send(page('Login (fixation)', `
    ${brief('Session fixation lab', `
      <p>A normal login page, plus an attack console. Your goal: end up holding a
      session id the server believes belongs to <b>admin</b>, using a session id
      you chose before anyone logged in.</p>`)}
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">1</span><b>Attacker step 1</b><span class="dim">fix the session id</span></div>
      <p><a class="clay-btn clay-btn-primary" href="/session/fixation/preset">Set my session cookie to sid=attacker123</a></p>
      <p class="note">Current <code>lab_sid</code> cookie value: <code>${esc(current || '(none)')}</code></p>
    </section>
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">2</span><b>Attacker step 2</b><span class="dim">the victim logs in</span></div>
      <p>Now the victim (or you, in another browser) logs in with that fixed cookie set.</p>
      ${loginCard('/session/fixation/login', 'Victim sign in')}
    </section>
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}
    ${backLink()}
  `));
});

// GET /session/fixation/preset -> fixate the sid, then back to the console.
router.get('/fixation/preset', (req, res) => {
  shared.setSid(res, 'attacker123');
  res.redirect('/session/fixation');
});

// POST /session/fixation/login -> login that keeps the pre-login sid.
router.post('/fixation/login', (req, res) => {
  const user = shared.checkCreds(req.body.username, req.body.password);
  if (!user) return res.status(403).send(deniedPage('Bad username or password.'));
  const preset = shared.sidOf(req);
  // VULN: the pre-login session id is kept after login instead of being
  // regenerated, so an attacker-chosen sid becomes an authenticated session.
  const sid = preset || shared.genSid();
  fixationStore.set(sid, { user: user.username, role: user.role });
  shared.setSid(res, sid);
  let body = `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Signed in</span></div>
      <h2>Welcome, ${esc(user.username)}</h2>
      <p>You are logged in. Your session id: <code>${esc(sid)}</code></p>
    </section>`;
  if (preset && user.role === 'admin') {
    const flag = award(req, 'session', 'fixation');
    body += `
      <div class="warn"><p><b>Session fixation confirmed.</b> You arrived with a
      session id chosen before login (<code>${esc(preset)}</code>), and the server
      kept it after you authenticated as admin. An attacker who set that cookie in
      your browser now shares your session.</p></div>
      ${flagBox(flag)}${fixPanel('session', 'fixation')}`;
  } else if (!preset) {
    body += `<p class="note">You logged in without a pre-set session id, so a fresh
    one was issued. Fix the session id first (step 1), then log in again.</p>`;
  }
  body += backLink();
  res.send(page('Login (fixation)', body));
});

module.exports = { vuln, router };
