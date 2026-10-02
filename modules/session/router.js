// PenTrix VulnLab module: Session Management (session)
// Six session-layer flaws: fixation (pre-login sid kept), logout that never kills
// the server-side session, sequential predictable session ids, sid in the URL
// leaking through a proxy log, sessions that never expire, and session ids
// leaking through a verbose debug log. Each lab keeps its own session store;
// the cookie name lab_sid is shared so techniques transfer between labs.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const COOKIE = 'lab_sid';
const TEN_YEARS_MS = 10 * 365 * 24 * 3600 * 1000;

function genSid() {
  return crypto.randomBytes(16).toString('hex');
}
function setSid(res, sid) {
  // VULN (deliberate, lab-wide): the session cookie is readable by JavaScript,
  // mirroring the app's httpOnly:false posture for cookie-theft demos.
  res.cookie(COOKIE, sid, { httpOnly: false, path: '/' });
}
function sidOf(req) {
  return req.cookies ? req.cookies[COOKIE] : undefined;
}
function checkCreds(username, password) {
  const db = getDb();
  return db.prepare('SELECT username, role FROM users WHERE username = ? AND password = ?')
    .get(String(username || ''), String(password || ''));
}
function loginForm(action) {
  return `
    <form method="POST" action="${esc(action)}">
      <input type="text" name="username" placeholder="username (try admin)" required />
      <input type="password" name="password" placeholder="password (try admin123)" required />
      <button type="submit">Log in</button>
    </form>`;
}
function denied(msg) {
  return page('Denied', `
    <h2>Access denied</h2>
    <div class="warn"><p>${msg}</p></div>
    <p><a href="/session">Back to the Session module</a></p>`);
}

// Per-lab session stores (never shared across labs).
const fixationStore = new Map();    // sid -> { user, role }
const logoutStore = new Map();      // sid -> { user, role, loggedOut }
const predictableStore = new Map(); // sid -> { user, role }
let nextSeq = 1000;                 // VULN lab 3: sequential session ids
const urlStore = new Map();         // sid -> { user, role, bot }
const proxyLog = [];
const legacyStore = new Map();      // sid -> { user, role, createdAt }
const leakStore = new Map();        // sid -> { user, role }
const debugLog = [];

// Seed the long-lived and simulated sessions once at boot.
const LEGACY_SID = '7f3a9c1e4b2d48f0a6e5c3b9d1f7a2e4';
legacyStore.set(LEGACY_SID, { user: 'admin', role: 'admin', createdAt: Date.now() - TEN_YEARS_MS + 30 * 24 * 3600 * 1000 });
const LEAK_ADMIN_SID = genSid();
leakStore.set(LEAK_ADMIN_SID, { user: 'admin', role: 'admin' });
debugLog.push('[INFO] session service starting, verbose mode ON');
debugLog.push('[DEBUG] admin session started sid=' + LEAK_ADMIN_SID + ' user=admin ip=10.0.0.8');
debugLog.push('[DEBUG] GET /dashboard 200 sid=' + genSid().slice(0, 12) + '... user=alice');
debugLog.push('[DEBUG] GET /dashboard 200 sid=' + genSid().slice(0, 12) + '... user=bob');

function logProxy(url) {
  proxyLog.push(url);
  if (proxyLog.length > 50) proxyLog.shift();
}

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const links = {
    'fixation': '/session/fixation',
    'logout': '/session/logoutdemo',
    'predictable': '/session/predictable',
    'url': '/session/urldemo',
    'never-expires': '/session/neverexpires',
    'log-leak': '/session/logleak',
  };
  const rows = module.exports.vulns.map((v) => {
    const done = captured(req, 'session', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="${links[v.id]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  const briefHtml = `
    <p><b>What is session management?</b> After you log in, the server hands your
    browser a session id (usually a cookie). Every later request carries that id,
    and the server trusts it as proof of who you are.</p>
    <p><b>The goal in this module:</b> break that trust. Each challenge gives you a
    login and a flawed session mechanism; your job is to end up holding a session
    the server believes belongs to <b>admin</b>. Use a cookie jar
    (<code>curl -c jar -b jar</code>) so your session ids persist between requests.</p>
    <p>All labs use the cookie name <code>lab_sid</code>, but each lab keeps its
    own session store.</p>`;

  res.send(page('Session Management', `
    ${brief('Module briefing', briefHtml)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

// ------------------------------------------------------- v1: session fixation
router.get('/fixation', (req, res) => {
  const current = sidOf(req);
  res.send(page('Login (fixation)', `
    <h2>Login</h2>
    <p>A normal login page. Log in as <code>admin</code> / <code>admin123</code>.</p>
    <h3>Attacker step 1: fix the session id</h3>
    <p><a class="btn" href="/session/fixation/preset">Set my session cookie to sid=attacker123</a></p>
    <p class="note">Current <code>lab_sid</code> cookie value:
    <code>${esc(current || '(none)')}</code></p>
    <h3>Attacker step 2: the victim logs in</h3>
    ${loginForm('/session/fixation/login')}
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.get('/fixation/preset', (req, res) => {
  setSid(res, 'attacker123');
  res.redirect('/session/fixation');
});

router.post('/fixation/login', (req, res) => {
  const user = checkCreds(req.body.username, req.body.password);
  if (!user) return res.status(403).send(denied('Bad username or password.'));
  const preset = sidOf(req);
  // VULN: the pre-login session id is kept after login instead of being
  // regenerated, so an attacker-chosen sid becomes an authenticated session.
  const sid = preset || genSid();
  fixationStore.set(sid, { user: user.username, role: user.role });
  setSid(res, sid);
  let body = `
    <h2>Welcome, ${esc(user.username)}</h2>
    <p>You are logged in. Your session id: <code>${esc(sid)}</code></p>`;
  if (preset && user.role === 'admin') {
    const flag = award(req, 'session', 'fixation');
    body += `
      <div class="warn"><p><b>Session fixation confirmed.</b> You arrived with a
      session id chosen before login (<code>${esc(preset)}</code>), and the server
      kept it after you authenticated as admin. An attacker who set that cookie in
      your browser now shares your session.</p></div>
      ${flagBox(flag)}`;
  } else if (!preset) {
    body += `<p class="note">You logged in without a pre-set session id, so a fresh
    one was issued. Fix the session id first (step 1), then log in again.</p>`;
  }
  body += `<p><a href="/session">Back to the Session module</a></p>`;
  res.send(page('Login (fixation)', body));
});

// ---------------------------------- v2: logout does not kill the session
router.get('/logoutdemo', (req, res) => {
  res.send(page('Login (logout)', `
    <h2>Login</h2>
    <p>Log in as <code>admin</code> / <code>admin123</code>, then log out, then try
    to use the old session anyway.</p>
    ${loginForm('/session/logoutdemo/login')}
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.post('/logoutdemo/login', (req, res) => {
  const user = checkCreds(req.body.username, req.body.password);
  if (!user) return res.status(403).send(denied('Bad username or password.'));
  const sid = genSid();
  logoutStore.set(sid, { user: user.username, role: user.role, loggedOut: false });
  setSid(res, sid);
  res.redirect('/session/logoutdemo/home');
});

router.get('/logoutdemo/home', (req, res) => {
  const s = logoutStore.get(sidOf(req));
  if (!s || s.loggedOut) return res.status(403).send(denied('No active session. Log in first.'));
  res.send(page('Home (logout)', `
    <h2>Welcome, ${esc(s.user)}</h2>
    <ul>
      <li><a href="/session/logoutdemo/secret">Secret admin page</a></li>
      <li><a href="/session/logoutdemo/logout">Log out</a></li>
    </ul>
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.get('/logoutdemo/logout', (req, res) => {
  const s = logoutStore.get(sidOf(req));
  // VULN: logout only flips a flag; the server-side session (and its cookie)
  // stays valid, so the "dead" session can still be replayed.
  if (s) s.loggedOut = true;
  res.send(page('Logged out', `
    <h2>Logged out</h2>
    <p>You have been logged out. Your session cookie is now worthless... or is it?
    Try the <a href="/session/logoutdemo/secret">secret admin page</a> with the same cookie.</p>
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.get('/logoutdemo/secret', (req, res) => {
  const s = logoutStore.get(sidOf(req));
  if (!s || s.role !== 'admin') return res.status(403).send(denied('Admins only.'));
  if (!s.loggedOut) {
    return res.send(page('Secret admin page', `
      <h2>Secret admin page</h2>
      <p>You are viewing this with a live session. Log out first, then come back
      with the same cookie to prove the session survived.</p>
      <p><a href="/session/logoutdemo/home">Back</a></p>`));
  }
  const flag = award(req, 'session', 'logout');
  return res.send(page('Secret admin page', `
    <h2>Secret admin page</h2>
    <div class="warn"><p><b>Logout bypass confirmed.</b> You logged out, but the
    server kept your session alive, and the old cookie still opens the admin page.</p></div>
    ${flagBox(flag)}
    <p><a href="/session">Back to the Session module</a></p>`));
});

// -------------------------------------------- v3: predictable session ids
router.get('/predictable', (req, res) => {
  let yours = sidOf(req);
  let adminSid;
  if (!yours || !predictableStore.has(yours)) {
    // VULN: session ids are sequential integers, so the next one is guessable.
    yours = String(nextSeq);
    adminSid = String(nextSeq + 1);
    nextSeq += 2;
    predictableStore.set(yours, { user: 'guest', role: 'user' });
    predictableStore.set(adminSid, { user: 'admin', role: 'admin' });
    setSid(res, yours);
  } else {
    const n = parseInt(yours, 10);
    adminSid = String(n + 1);
    if (!predictableStore.has(adminSid)) {
      predictableStore.set(adminSid, { user: 'admin', role: 'admin' });
    }
  }
  res.send(page('Session ids (predictable)', `
    <h2>Welcome, guest</h2>
    <p>This service hands out session ids as sequential integers.</p>
    <ul>
      <li>Your session id: <code>${esc(yours)}</code></li>
      <li>The admin logged in right after you. Their session id: <code>${esc(adminSid)}</code></li>
    </ul>
    <p>Swap your <code>lab_sid</code> cookie for the admin's value and open the
    <a href="/session/predictable/admin">admin panel</a>.</p>
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.get('/predictable/admin', (req, res) => {
  const s = predictableStore.get(sidOf(req));
  if (!s || s.role !== 'admin') {
    return res.status(403).send(denied('Admins only. Your current session id is not the admin\'s.'));
  }
  const flag = award(req, 'session', 'predictable');
  res.send(page('Admin panel (predictable)', `
    <h2>Welcome, admin</h2>
    <p>You guessed the admin's sequential session id and hijacked the session.</p>
    ${flagBox(flag)}
    <p><a href="/session">Back to the Session module</a></p>`));
});

// ------------------------------------------------------ v4: sid in the URL
router.get('/urldemo', (req, res) => {
  // The admin "visits" through this service regularly; the proxy sees everything.
  if (!urlStore.has('__admin_seeded__')) {
    const adminSid = genSid();
    urlStore.set('__admin_seeded__', true);
    urlStore.set(adminSid, { user: 'admin', role: 'admin', bot: true });
    logProxy('GET /session/urldemo/home?sid=' + adminSid);
  }
  logProxy('GET /session/urldemo');
  res.send(page('Login (sid in URL)', `
    <h2>Login</h2>
    <p>This service puts your session id in the URL after login
    (<code>/session/urldemo/home?sid=...</code>) so links stay "shareable".</p>
    ${loginForm('/session/urldemo/login')}
    <h3>Corporate proxy log</h3>
    <p>All traffic passes through a logging proxy. The admin uses this service too.
    <a href="/session/urldemo/proxy-log">View the proxy log</a>.</p>
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.post('/urldemo/login', (req, res) => {
  const user = checkCreds(req.body.username, req.body.password);
  if (!user) return res.status(403).send(denied('Bad username or password.'));
  const sid = genSid();
  urlStore.set(sid, { user: user.username, role: user.role, bot: false });
  logProxy('POST /session/urldemo/login');
  res.redirect('/session/urldemo/home?sid=' + sid);
});

router.get('/urldemo/home', (req, res) => {
  const sid = String(req.query.sid || '');
  logProxy(req.originalUrl);
  const s = urlStore.get(sid);
  if (!s) return res.status(403).send(denied('Unknown or missing sid.'));
  let body = `<h2>Welcome, ${esc(s.user)}</h2><p>Your sid travels in the URL bar.</p>`;
  if (s.role === 'admin' && s.bot) {
    const flag = award(req, 'session', 'url');
    body += `
      <div class="warn"><p><b>Session stolen from the proxy log.</b> The admin's
      sid leaked through a logged URL, and you replayed it.</p></div>
      ${flagBox(flag)}`;
  }
  body += `<p><a href="/session">Back to the Session module</a></p>`;
  res.send(page('Home (sid in URL)', body));
});

router.get('/urldemo/proxy-log', (req, res) => {
  // VULN: session ids in URLs end up in logs, where anyone with log access can
  // steal them, including the admin's.
  const rows = proxyLog.map((u) => `<li><code>${esc(u)}</code></li>`).join('') || '<li><i>empty</i></li>';
  res.send(page('Proxy log', `
    <h2>Proxy log</h2>
    <p>Full request URLs, as recorded by the corporate proxy. Look for a session
    id that is not yours.</p>
    <ul>${rows}</ul>
    <p><a href="/session/urldemo">Back to the login</a></p>
  `));
});

// ----------------------------------------------- v5: sessions never expire
router.get('/neverexpires', (req, res) => {
  res.send(page('Sessions (never expire)', `
    <h2>Session lifetimes</h2>
    <p>Sessions here live for <b>10 years</b>. The operations team keeps an archive
    of old sessions "for nostalgia". One of them belongs to an admin.</p>
    <p><a href="/session/legacy-archive">Browse the session archive</a></p>
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.get('/legacy-archive', (req, res) => {
  res.send(page('Session archive', `
    <h2>Session archive</h2>
    <table class="tbl">
      <tr><th>Session id</th><th>Owner</th><th>Created</th></tr>
      <tr><td><code>${esc(LEGACY_SID)}</code></td><td>admin</td><td>2016 (10 years ago)</td></tr>
    </table>
    <p>Set your <code>lab_sid</code> cookie to the archived value and open the
    <a href="/session/legacy-admin">legacy admin panel</a>.</p>
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.get('/legacy-admin', (req, res) => {
  const s = legacyStore.get(sidOf(req));
  if (!s || s.role !== 'admin') {
    return res.status(403).send(denied('Admins only. The archived session id is shown in the session archive.'));
  }
  const ageMs = Date.now() - s.createdAt;
  // VULN: a 10-year session lifetime means a decade-old stolen session still works.
  if (ageMs < TEN_YEARS_MS) {
    const flag = award(req, 'session', 'never-expires');
    return res.send(page('Legacy admin panel', `
      <h2>Welcome back, admin</h2>
      <p>Session age: about <b>${Math.floor(ageMs / (365 * 24 * 3600 * 1000))} years</b>.
      Still accepted, because sessions live for 10 years.</p>
      ${flagBox(flag)}
      <p><a href="/session">Back to the Session module</a></p>`));
  }
  res.status(403).send(denied('Session expired.'));
});

// ------------------------------------------------ v6: session id in debug log
router.get('/logleak', (req, res) => {
  res.send(page('Debug logs (session leak)', `
    <h2>Verbose logging</h2>
    <p>The ops team runs this service with <b>verbose debug logging</b>. The log
    viewer below prints everything, including session ids.</p>
    <p><a href="/session/debug-log">Open the debug log</a>, find the admin's
    session id, set it as your <code>lab_sid</code> cookie, and open the
    <a href="/session/leak-admin">admin panel</a>.</p>
    <p><a href="/session">Back to the Session module</a></p>
  `));
});

router.get('/debug-log', (req, res) => {
  // VULN: session ids are written to a verbose debug log that leaks them to
  // anyone who can read it.
  const rows = debugLog.map((l) => `<li><code>${esc(l)}</code></li>`).join('');
  res.send(page('Debug log', `
    <h2>Debug log</h2>
    <ul>${rows}</ul>
    <p><a href="/session/logleak">Back</a></p>
  `));
});

router.get('/leak-admin', (req, res) => {
  const s = leakStore.get(sidOf(req));
  if (!s || s.role !== 'admin') {
    return res.status(403).send(denied('Admins only. The admin\'s session id is sitting in the debug log.'));
  }
  const flag = award(req, 'session', 'log-leak');
  res.send(page('Admin panel (log leak)', `
    <h2>Welcome, admin</h2>
    <p>You lifted the admin's session id out of the debug log and replayed it.</p>
    ${flagBox(flag)}
    <p><a href="/session">Back to the Session module</a></p>`));
});

module.exports = {
  id: 'session',
  name: 'Session Management',
  tagline: 'Fixate, predict, steal, and replay sessions: six ways login state breaks.',
  description: 'Authentication does not end at the login form. These six labs attack the session layer itself: fixation, broken logout, predictable ids, ids in URLs and logs, and sessions that never die.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'fixation',
      name: 'Session Fixation',
      difficulty: 'Medium',
      hint: 'The server keeps whatever session id you arrived with, even across login. Set the victim\'s cookie to a value you chose, then let them log in.',
      how: 'Fix the lab_sid cookie to a known value, log in as admin, and confirm the sid did not change.',
    },
    {
      id: 'logout',
      name: 'Logout Does Not Destroy the Session',
      difficulty: 'Easy',
      hint: 'Logging out should kill the server-side session. Here it only shows you a goodbye page. Replay the old cookie.',
      how: 'Log in as admin, visit the logout link, then revisit the secret admin page with the same cookie.',
    },
    {
      id: 'predictable',
      name: 'Predictable Session IDs',
      difficulty: 'Medium',
      hint: 'Session ids are sequential integers. The demo page shows your id and the admin\'s id right next to each other. Do the math.',
      how: 'Read the admin\'s session id off the demo page, set it as your lab_sid cookie, and open the admin panel.',
    },
    {
      id: 'url',
      name: 'Session ID in the URL',
      difficulty: 'Easy',
      hint: 'Session ids in URLs get logged, bookmarked, and shared. The corporate proxy log records every URL, including the admin\'s.',
      how: 'Find the admin\'s sid in the proxy log and open their home URL with it.',
    },
    {
      id: 'never-expires',
      name: 'Sessions Never Expire',
      difficulty: 'Easy',
      hint: 'Sessions live for 10 years here. The archive keeps a decade-old admin session, and it still works.',
      how: 'Copy the archived admin session id, set it as your lab_sid cookie, and open the legacy admin panel.',
    },
    {
      id: 'log-leak',
      name: 'Session ID in Debug Log',
      difficulty: 'Easy',
      hint: 'Verbose debug logs print session ids. The log viewer is one click away, and the admin\'s sid is in there.',
      how: 'Read the admin\'s sid from the debug log, replay it as your cookie, and open the admin panel.',
    },
  ],
  router,
};
