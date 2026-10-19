'use strict';
// Wildcard on Sensitive Data: the team directory API answers
// Access-Control-Allow-Origin: * while returning every user's email address,
// so any website can read the whole directory cross-origin.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, hintBox, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'cors-wildcard-data',
  name: 'Wildcard on Sensitive Data',
  difficulty: 'Easy',
  hint: 'Access-Control-Allow-Origin: * on an endpoint that returns every user\'s email address.',
  hints: ["The API sends ACAO: * with user emails. What does * mean? Open GET /cors/api/users in Repeater and read the raw response headers.", "Any website can read it. No credentials needed, just fetch. Replay the request in Repeater: the wildcard rides on every response.", "The data endpoint answers any origin, so your page only needs to ask for it and read the response body. No special setup is needed on the attacker's side."],
  tools: "BZ, B",
  how: 'Burp Repeater: GET /cors/api/users and read the Access-Control-Allow-Origin: * header riding on a response that returns every user\'s email address; any origin can read it cross-origin, no credentials needed; or prove via /cors/prove?vuln=cors-wildcard-data&origin=https://evil.com',
  link: '/cors#cors-wildcard-data',
  start: 'Burp: browse the team directory page, find GET /cors/api/users in Proxy history, send it to Repeater, and inspect the CORS response headers.',
};

// GET /cors/api/users -> team directory data. Wildcard origin on sensitive
// data, behavior identical to the module router.
router.get('/api/users', (req, res) => {
  // VULN: wildcard origin on an endpoint returning sensitive data. Any website
  // can read every user's email address.
  res.set('Access-Control-Allow-Origin', '*');
  const users = getDb()
    .prepare('SELECT username, email FROM users ORDER BY username')
    .all();
  res.json({ users });
});

// GET /cors/wildcard -> the fictional internal app: Pentrix Team, a company
// directory. Full claymorphism, real-app feel.
router.get('/wildcard', (req, res) => {
  res.send(page('Wildcard on Sensitive Data', `
    <div class="hero">
      <h1>Pentrix Team</h1>
      <p class="lead">Find anyone in the company. The directory loads live from the team API.</p>
      <div class="stats">
        <div class="stat"><b>Live</b><span>directory data</span></div>
        <div class="stat"><b>JSON</b><span>served by /cors/api/users</span></div>
      </div>
    </div>
    ${hintBox(vuln.hint)}
    <div class="clay-card">
      <h2>Directory</h2>
      <p>Every teammate, pulled straight from the API.</p>
      <button class="clay-btn clay-btn-primary" id="load-team" type="button">Load team</button>
      <div id="team-out" aria-live="polite"><p>Press the button to load the directory.</p></div>
    </div>
    <div class="clay-card">
      <h2>API and origin checker</h2>
      <p>Raw endpoint: <a href="/cors/api/users"><code>/cors/api/users</code></a></p>
      ${payloadBlock('Burp Repeater', 'GET /cors/api/users HTTP/1.1\nHost: localhost:3000\n\n')}
      <p>The checker sends a real request to the endpoint with the Origin you
      type and shows the exact response headers, the same check a browser
      performs before allowing a cross-origin read.</p>
      <form method="GET" action="/cors/prove">
        <input type="hidden" name="vuln" value="cors-wildcard-data" />
        <div class="clay-field">
          <label for="origin-wildcard">Origin header to test</label>
          <input class="clay-input" type="text" id="origin-wildcard" name="origin" value="https://evil.com" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Send the request</button>
      </form>
      <p><a href="/cors/prove?vuln=cors-wildcard-data">Choose your own Origin</a></p>
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/cors">Back to the module</a></p>
    <script>
      const escHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
      document.getElementById('load-team').addEventListener('click', async () => {
        const out = document.getElementById('team-out');
        out.innerHTML = '<p>Loading...</p>';
        try {
          const r = await fetch('/cors/api/users');
          const data = await r.json();
          out.innerHTML = '<div class="tbl-scroll"><table class="tbl">' +
            '<caption class="sr-only">Team directory</caption>' +
            '<thead><tr><th scope="col">Username</th><th scope="col">Email</th></tr></thead><tbody>' +
            data.users.map((u) => '<tr><td>' + escHtml(u.username) + '</td><td>' + escHtml(u.email) + '</td></tr>').join('') +
            '</tbody></table></div>';
        } catch (e) {
          out.innerHTML = '<p>Request failed.</p>';
        }
      });
    </script>
  `));
});

module.exports = {
  vuln,
  router,
};
