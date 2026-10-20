'use strict';
// API Security Flaws: intentionally vulnerable JSON API training targets.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, consoleBtn, fixSection , capturedPill } = require('../../lib/page');

const challenges = [
  require('./challenges/mass-assignment'),
  require('./challenges/exposure'),
  require('./challenges/rate-limit'),
  require('./challenges/ratelimit-xff'),
  require('./challenges/api-version-bypass'),
];

const router = express.Router();

// GET /api/login/alice -> quick-login as alice (id 2) for lab convenience.
// Module-level demo login, not a challenge: it exists so students can start
// authenticated flows without a password form.
router.get('/login/alice', (req, res) => {
  req.session.user = { id: 2, username: 'alice', role: 'user' };
  res.json({ ok: true, loggedInAs: 'alice', id: 2 });
});

// GET /api -> module index page (developer docs for the fictional Acme API).
router.get('/', (req, res) => {
  const who = req.session.user ? esc(req.session.user.username) : 'nobody';
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('api', ordered, {
      'mass-assignment': '/api/me',
      exposure: '/api/users/view',
      'rate-limit': { href: '', cmd: "curl -i -X POST \"http://<your-lab-address>/api/login\" -H \"Content-Type: application/json\" -d '{\"username\":\"alice\",\"password\":\"<password>\"}'" },
      'ratelimit-xff': { href: '', cmd: "curl -i -X POST \"http://<your-lab-address>/api/v1/login\" -H \"Content-Type: application/json\" -H \"X-Forwarded-For: 10.0.0.9\" -d '{\"username\":\"alice\",\"password\":\"<password>\"}'" },
      'api-version-bypass': '/api/v2/users/2',
    });
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'api', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      ${consoleBtn('Open challenge', consoles[i])}
    </article>`).join('');

  res.send(page('Acme API Docs', `
    ${brief('API Security Flaws', `
      A tiny JSON API for a fictional startup. The endpoints below are the
      public surface; your job is to find where the API trusts the client too
      much. You are currently logged in as <b>${who}</b>.
      Flags for the JSON endpoints arrive in the response body (<code>"flag"</code>)
      or the <code>X-Pentrix-Flag</code> response header (read the full response
      in Burp Repeater, headers included).`)}
    ${trackBanner(module.exports)}

    <h2>Endpoints</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">Acme API endpoints</caption>
      <thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Description</th></tr></thead>
      <tbody>
        <tr><td>GET</td><td><code>/api/login/:user</code></td><td>Log in as a user (demo only)</td></tr>
        <tr><td>POST</td><td><code>/api/login</code></td><td>Log in with username and password (JSON)</td></tr>
        <tr><td>GET</td><td><code>/api/me</code></td><td>Your profile</td></tr>
        <tr><td>PATCH</td><td><code>/api/me</code></td><td>Update your profile (JSON)</td></tr>
        <tr><td>GET</td><td><code>/api/users</code></td><td>List users</td></tr>
        <tr><td>POST</td><td><code>/api/v1/login</code></td><td>Log in (v1, rate limited)</td></tr>
        <tr><td>GET</td><td><code>/api/v1/users/:id</code></td><td>Get user by id (v1)</td></tr>
        <tr><td>GET</td><td><code>/api/v2/users/:id</code></td><td>Get user by id (v2)</td></tr>
      </tbody>
    </table></div>

    <h2>Quick login</h2>
    <p>
      <a class="clay-btn clay-btn-primary clay-btn-sm" href="/api/login/alice">Log in as alice</a>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/api/users/view">View user list (browser)</a>
    </p>

    <h2>Challenges</h2>
    <p>Five flaws hide in the endpoints above. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  ${fixSection('api', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'api',
  name: 'API Security Flaws',
  tagline: 'Mass assignment, data exposure, and brute force on a JSON API.',
  description: 'A small JSON API with five classic flaws: a profile endpoint that merges every client-supplied field, a user-list endpoint that leaks full database rows, a login endpoint with no rate limiting, a rate limit bypassed via X-Forwarded-For, and a v2 endpoint that forgot its authorization check. All flags are awarded server-side on real exploitation.',
  difficulty: 'Intermediate',
  track: 'Advanced',
  prerequisites: ['Auth and Sessions track', 'Injection track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
