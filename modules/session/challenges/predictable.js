'use strict';
// Predictable Session IDs: the service hands out session ids as sequential
// integers, so the admin's id is trivially computable from your own.
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

// Per-lab session store: sid -> { user, role }. Never shared across labs.
const predictableStore = new Map();
let nextSeq = 1000; // VULN lab 3: sequential session ids

const vuln = {
  id: 'predictable',
  name: 'Predictable Session IDs',
  difficulty: 'Medium',
  hint: "Session ids are sequential integers, handed out in sign-in order. The demo page shows only your own id, but it tells you the admin signed in right after you. Do the math.",
  hints: [
    "Session ids here are sequential integers, handed out in sign-in order. Open the demo page through Burp Proxy and note your own sid. The page also tells you the admin signed in right after you: what does that let you compute?",
    "Predictable ids: the admin's sid is not printed anywhere, because it does not need to be. If ids go up by one per sign-in and the admin signed in immediately after you, their sid is a number you already know plus one.",
    "In Burp, send the admin panel request to Repeater, replace the lab_sid cookie with the computed sid, and re-send. A Proxy Match and Replace rule on the lab_sid cookie (Tool Setup Guide, section 10) does the same job for full browsing. Intruder with a small numeric range around your sid also works.",
  ],
  tools: 'BZ, B, DT',
  est: 'about 10 minutes',
  how: 'Work out the admin sid from yours (ids are sequential and the admin signed in right after you), set it as your lab_sid cookie in Burp (Repeater, or a Match and Replace rule), and open the admin panel.',
  link: '/session#predictable',
  start: 'Point your browser at Burp, visit /session/predictable, and note your own session id. The admin signed in right after you; work out theirs.',
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

function backLink() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/session">Back to the Session module</a></p>`;
}

// GET /session/predictable -> guest session. The admin's sid is deliberately
// NOT printed: ids are sequential and the copy tells you the admin signed in
// right after you, so the analysis (yours plus one) is the challenge (P3-7).
router.get('/predictable', (req, res) => {
  let yours = shared.sidOf(req);
  let adminSid;
  if (!yours || !predictableStore.has(yours)) {
    // VULN: session ids are sequential integers, so the next one is guessable.
    yours = String(nextSeq);
    adminSid = String(nextSeq + 1);
    nextSeq += 2;
    predictableStore.set(yours, { user: 'guest', role: 'user' });
    predictableStore.set(adminSid, { user: 'admin', role: 'admin' });
    shared.setSid(res, yours);
  } else {
    const n = parseInt(yours, 10);
    adminSid = String(n + 1);
    if (!predictableStore.has(adminSid)) {
      predictableStore.set(adminSid, { user: 'admin', role: 'admin' });
    }
  }
  res.send(page('Guest portal (predictable sids)', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Guest session</span></div>
      <h2>Guest session</h2>
      <p>Welcome to the guest portal. Sessions here are handed out as sequential integers, in sign-in order.</p>
      <p>Your session id: <code>${esc(yours)}</code></p>
      <p>The admin signed in right after you did. Their session id is not shown anywhere: work it out.</p>
      <p>Swap your <code>lab_sid</code> cookie for the value you computed, then open the admin panel.</p>
      <p><a class="clay-btn clay-btn-primary" href="/session/predictable/admin">Open the admin panel</a></p>
    </section>
    ${backLink()}
  `));
});

// GET /session/predictable/admin -> flag when the cookie is the admin's sid.
router.get('/predictable/admin', (req, res) => {
  const s = predictableStore.get(shared.sidOf(req));
  if (!s || s.role !== 'admin') {
    return res.status(403).send(deniedPage('Admins only. Your current session id is not the admin\'s.'));
  }
  const flag = award(req, 'session', 'predictable');
  res.send(page('Admin panel (predictable)', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Acme Portal</b><span class="dim">Admin panel</span></div>
      <h2>Admin panel</h2>
      <div class="warn"><p><b>Session hijacked.</b> You worked out the admin's sequential session id and the server accepted it as proof you are the admin.</p></div>
      ${flagBox(flag)}
      ${fixPanel('session', 'predictable')}
    </section>
    ${backLink()}
  `));
});

module.exports = { vuln, router };
