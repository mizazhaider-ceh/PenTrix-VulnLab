'use strict';
// Session ID in Debug Log: verbose debug logging writes the admin's session
// id into a log viewer that anyone can read.
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'log-leak',
  name: 'Session ID in Debug Log',
  difficulty: 'Easy',
  est: 'about 5 to 10 minutes',
  hint: 'Verbose debug logs print session ids. Browse the log viewer through Burp Proxy: the admin sid is in there.',
  hints: ["The debug log writes session ids. Read it through Burp Proxy and find the admin session line.", "Spot the admin sid in the log viewer, then send the admin panel request to Repeater.", "In Repeater, replay the admin panel request with the admin sid set as your lab_sid cookie."],
  tools: 'BZ, B',
  how: 'Read the admin sid from the debug log, replay it as your lab_sid cookie in Repeater, and open the admin panel.',
  link: '/session#log-leak',
  start: 'With Burp Proxy on, open the verbose logging page (/session/logleak), follow the link to the debug log viewer, and read the admin session line.',
};

// Lab-scoped session store and verbose debug log, seeded once at load
// (mirrors the router.js boot seed).
const leakStore = new Map();
const debugLog = [];
const LEAK_ADMIN_SID = shared.genSid();
leakStore.set(LEAK_ADMIN_SID, { user: 'admin', role: 'admin' });
debugLog.push('[INFO] session service starting, verbose mode ON');
debugLog.push('[DEBUG] admin session started sid=' + LEAK_ADMIN_SID + ' user=admin ip=10.0.0.8');
debugLog.push('[DEBUG] GET /dashboard 200 sid=' + shared.genSid().slice(0, 12) + '... user=alice');
debugLog.push('[DEBUG] GET /dashboard 200 sid=' + shared.genSid().slice(0, 12) + '... user=bob');

function backLink() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session">Back to the Session module</a></p>`;
}

// GET /session/logleak -> explains the verbose logging and links the viewer.
router.get('/logleak', (req, res) => {
  res.send(page('Debug logs (session leak)', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">⌗</span><b>Acme Ops</b><span class="dim">Logging</span></div>
      <h2>Verbose logging</h2>
      <p>The ops team runs this service with <b>verbose debug logging</b>. The log
      viewer below prints everything, including session ids.</p>
      <p><a class="clay-btn clay-btn-primary" href="/session/debug-log">Open the debug log</a></p>
      <p>Find the admin's session id, set it as your <code>lab_sid</code> cookie,
      and open the <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session/leak-admin">admin panel</a>.</p>
    </section>
    ${backLink()}
  `));
});

// GET /session/debug-log -> the verbose log, including the admin's sid.
router.get('/debug-log', (req, res) => {
  // VULN: session ids are written to a verbose debug log that leaks them to
  // anyone who can read it.
  const rows = debugLog.map((l) => `<li><code>${esc(l)}</code></li>`).join('');
  res.send(page('Debug log', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">⌗</span><b>Acme Ops</b><span class="dim">Debug log</span></div>
      <h2>Debug log</h2>
      <ul>${rows}</ul>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session/logleak">Back</a></p>
    </section>
    ${backLink()}
  `));
});

// GET /session/leak-admin -> awards the flag when the cookie holds the
// admin's leaked session id.
router.get('/leak-admin', (req, res) => {
  const s = leakStore.get(shared.sidOf(req));
  if (!s || s.role !== 'admin') {
    return res.status(403).send(shared.denied('Admins only. The admin\'s session id is sitting in the debug log.'));
  }
  const flag = award(req, 'session', 'log-leak');
  res.send(page('Admin panel (log leak)', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">⌗</span><b>Acme Ops</b><span class="dim">Admin panel</span></div>
      <h2>Welcome, admin</h2>
      <p>You lifted the admin's session id out of the debug log and replayed it.</p>
      ${flagBox(flag)}
      ${fixPanel('session', 'log-leak')}
    </section>
    ${backLink()}`));
});

module.exports = { vuln, router };
