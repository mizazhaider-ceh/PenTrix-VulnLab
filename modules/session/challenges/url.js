'use strict';
// Session ID in the URL: sids travel in the query string, so the corporate
// logging proxy captures the admin's sid and anyone with log access can replay it.
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

// Per-lab session store and proxy log (never shared with the other labs).
const urlStore = new Map();
const proxyLog = [];
function logProxy(url) {
  proxyLog.push(url);
  if (proxyLog.length > 50) proxyLog.shift();
}

const vuln = {
  id: 'url',
  name: 'Session ID in the URL',
  difficulty: 'Easy',
  est: 'about 5 to 10 minutes',
  hint: 'Session ids in URLs get logged, bookmarked, and shared. The corporate proxy log records every URL, including the admin\'s.',
  hints: [
    'The sid is in the URL. Where do URLs end up? Open the proxy log page through Burp.',
    'Proxy logs, browser history, referer headers. The sid leaks.',
    "Copy the leaked home?sid= URL from the proxy log into Repeater and send it.",
  ],
  tools: 'BZ, B, DT',
  how: 'Find the admin\'s sid in the proxy log and replay their home URL with it in Burp Repeater.',
  link: '/session#url',
  start: 'Point your browser at Burp, visit /session/urldemo, then open the proxy log link shown on that page.',
};

// Clay-styled 403 page (same denials as the module helper, full clay).
function deniedPage(msg) {
  return page('Denied', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">!</span><b>Acme Portal</b><span class="dim">Access denied</span></div>
      <h2>Access denied</h2>
      <p class="clay-err" role="alert">${esc(msg)}</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session/urldemo">Back to the login</a></p>
    </section>`);
}

function backLink() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session">Back to the Session module</a></p>`;
}

// Clay login card for the shareable-links portal.
function loginCard() {
  return `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Log in</span></div>
      <h2>Log in</h2>
      <form method="POST" action="/session/urldemo/login">
        <div class="clay-field">
          <label for="url-username">Username</label>
          <input class="clay-input" id="url-username" name="username" type="text" placeholder="username (try admin)" required />
        </div>
        <div class="clay-field">
          <label for="url-password">Password</label>
          <input class="clay-input" id="url-password" name="password" type="password" placeholder="password (try admin123)" required />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Log in</button>
      </form>
    </section>`;
}

// GET /session/urldemo -> login page; the admin "visits" through this service too.
router.get('/urldemo', (req, res) => {
  // The admin "visits" through this service regularly; the proxy sees everything.
  if (!urlStore.has('__admin_seeded__')) {
    const adminSid = shared.genSid();
    urlStore.set('__admin_seeded__', true);
    urlStore.set(adminSid, { user: 'admin', role: 'admin', bot: true });
    logProxy('GET /session/urldemo/home?sid=' + adminSid);
  }
  logProxy('GET /session/urldemo');
  res.send(page('Login (sid in URL)', `
    ${loginCard()}
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Proxy log</span></div>
      <h2>Corporate proxy log</h2>
      <p>This service puts your session id in the URL after login
      (<code>/session/urldemo/home?sid=...</code>) so links stay "shareable".
      All traffic passes through a logging proxy. The admin uses this service too.</p>
      <p><a class="clay-btn clay-btn-secondary" href="/session/urldemo/proxy-log">View the proxy log</a></p>
    </section>
    ${backLink()}
  `));
});

// POST /session/urldemo/login -> session id issued and placed in the URL.
router.post('/urldemo/login', (req, res) => {
  const user = shared.checkCreds(req, req.body.username, req.body.password);
  if (!user) return res.status(403).send(deniedPage('Bad username or password.'));
  const sid = shared.genSid();
  urlStore.set(sid, { user: user.username, role: user.role, bot: false });
  logProxy('POST /session/urldemo/login');
  res.redirect('/session/urldemo/home?sid=' + sid);
});

// GET /session/urldemo/home -> session id is read from the query string (VULN).
router.get('/urldemo/home', (req, res) => {
  const sid = String(req.query.sid || '');
  logProxy(req.originalUrl);
  const s = urlStore.get(sid);
  if (!s) return res.status(403).send(deniedPage('Unknown or missing sid.'));
  let body = `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Home</span></div>
      <h2>Welcome, ${esc(s.user)}</h2>
      <p>Your sid travels in the URL bar.</p>`;
  if (s.role === 'admin' && s.bot) {
    const flag = award(req, 'session', 'url');
    body += `
      <div class="warn"><p><b>Session stolen from the proxy log.</b> The admin's
      sid leaked through a logged URL, and you replayed it.</p></div>
      ${flagBox(flag)}${fixPanel('session', 'url')}`;
  }
  body += `</section>${backLink()}`;
  res.send(page('Home (sid in URL)', body));
});

// GET /session/urldemo/proxy-log -> every full URL the proxy recorded (VULN).
router.get('/urldemo/proxy-log', (req, res) => {
  // VULN: session ids in URLs end up in logs, where anyone with log access can
  // steal them, including the admin's.
  const rows = proxyLog.map((u) => `<li><code>${esc(u)}</code></li>`).join('') || '<li><i>empty</i></li>';
  res.send(page('Proxy log', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Proxy log</span></div>
      <h2>Proxy log</h2>
      <p>Full request URLs, as recorded by the corporate proxy. Look for a session
      id that is not yours.</p>
      <ul>${rows}</ul>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session/urldemo">Back to the login</a></p>
    </section>
  `));
});

module.exports = { vuln, router };
