'use strict';
// Host Header Injection: labs around one trust mistake, building links, cache
// entries, and server-side request URLs out of the Host header (and its proxy
// variants X-Forwarded-Host and X-Host-Override) without validation. The
// challenge files hold each flaw; this file is only the module wiring:
// module-level helper routes, the index page, and the registry metadata.
const express = require('express');
const { brief, esc, flagBox, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, fixSection, consoleMap , capturedPill } = require('../../lib/page');
const { award } = require('../../lib/flags');
const { tokenDb, isLocalHost } = require('./shared');

const challenges = [
  require('./challenges/host-reset-poison'),
  require('./challenges/host-cache-poison'),
  require('./challenges/host-ssrf'),
  require('./challenges/host-xforwarded'),
  require('./challenges/host-abs-url'),
];

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// Challenge page slug per vuln id (used by the index page links).
const PAGE_FOR = {
  'host-reset-poison': 'forgot',
  'host-cache-poison': 'app',
  'host-ssrf': 'status',
  'host-xforwarded': 'forgot-xfwd',
  'host-abs-url': 'login',
};

const BRIEF_HTML = `
<p><b>What is host header injection?</b> Many apps build absolute links, emails,
and even server-side request URLs from the <code>Host</code> header, trusting a
value the client fully controls. Behind proxies, the equivalent headers are
<code>X-Forwarded-Host</code> and vendor variants like
<code>X-Host-Override</code>.</p>
<p><b>The labs below:</b> poison a password-reset email so the victim's token
goes to your collector, poison a path-keyed cache, drive a server-side fetch at
a loopback-only internal agent, and bend an absolute login URL to your domain.</p>
<p><b>How to attack:</b> <code>curl -H "Host: evil.com" ...</code> The in-lab
attacker collector is <code>/hostheader/evil-collect?token=...</code>. A flag is
awarded only when the poisoned value genuinely flows through the vulnerable
code path.</p>`;

// GET /hostheader -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('hostheader', ordered, consoleMap('/hostheader/', PAGE_FOR));
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="/hostheader/${PAGE_FOR[v.id]}">${esc(v.name)}</a> ${difficultyPill(v.difficulty)} ${capturedPill(req, 'hostheader', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  res.send(page('Host Header Injection', `
    ${brief('Host Header Injection', BRIEF_HTML)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Five flaws hide in the way this portal trusts the <code>Host</code>
    header and its proxy variants. Each challenge card has a hint ladder:
    level 1 nudges, level 2 teaches the technique, level 3 shows the payload
    shape.</p>
    ${cards}
  ${fixSection('hostheader', challenges)}
`));
});

// GET /hostheader/reset -> the real reset endpoint the emailed link points at
// (one-time token). Shared by both password-reset challenges.
router.get('/reset', (req, res) => {
  const token = String(req.query.token || '');
  const row = token
    ? tokenDb().prepare('SELECT * FROM hostheader_tokens WHERE token = ?').get(token)
    : undefined;
  if (!row) {
    return res.status(400).send(page('Reset password', `
      <div class="clay-card">
        <p>Invalid or expired token.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader/forgot">Request a new link</a></p>
      </div>
    `));
  }
  tokenDb().prepare('DELETE FROM hostheader_tokens WHERE token = ?').run(token);
  res.send(page('Reset password', `
    <div class="clay-card">
      <h2>Password reset</h2>
      <p>Password for <b>${esc(row.email)}</b> has been reset
      (demo: nothing actually changed).</p>
      <p class="note dim">This is where the victim lands after clicking the link
      in the email. If the link pointed at the attacker's domain, the token went
      to the collector instead.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader">Back to the module</a></p>
    </div>
  `));
});

// GET /hostheader/evil-collect -> attacker collector for the reset-token
// challenges. Awards only for tokens issued under a poisoned host.
router.get('/evil-collect', (req, res) => {
  const token = String(req.query.token || '');
  const row = token
    ? tokenDb().prepare('SELECT * FROM hostheader_tokens WHERE token = ?').get(token)
    : undefined;
  if (row && !isLocalHost(row.issued_host)) {
    const flag = award(req, 'hostheader', row.vuln);
    return res.send(page('Attacker collector', `
      <div class="clay-card">
        <h2>Token captured</h2>
        <p>A password-reset token for <b>${esc(row.email)}</b> was just harvested.
        It was issued while the app believed its own host was
        <code>${esc(row.issued_host)}</code>, so the reset email pointed the
        victim at the attacker's domain.</p>
        <pre><code>${esc(token)}</code></pre>
        ${flagBox(flag)}
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader">Back to the module</a></p>
      </div>
    `));
  }
  res.send(page('Attacker collector', `
    <div class="clay-card">
      <h2>Evil collector</h2>
      <p>This page belongs to the attacker. It awards the flag when a reset
      token that was issued under a <b>poisoned</b> host arrives here as
      <code>?token=...</code>.</p>
      ${row
        ? '<p class="note dim">That token was issued for the legitimate host, so no flag: poison the Host header (or X-Forwarded-Host / X-Host-Override on their own pages) when requesting the reset email, then bring the token here.</p>'
        : '<p>No token received yet.</p>'}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader">Back to the module</a></p>
    </div>
  `));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'hostheader',
  name: 'Host Header Injection',
  tagline: 'Poison the Host header and watch links, caches, and server-side fetches obey it.',
  description: 'Six host-header injection labs: password-reset poisoning through Host, X-Forwarded-Host, and X-Host-Override with an attacker token collector, cache poisoning via path-only cache keys, server-side request forgery that reaches a loopback-only internal agent, and an absolute login continue URL built from the Host header.',
  difficulty: 'Intermediate',
  track: 'Auth and Sessions',
  prerequisites: ['auth'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
