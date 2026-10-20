'use strict';
// Exposed Admin Token Header: the session API answers
// Access-Control-Allow-Origin: * and lists X-Admin-Token in
// Access-Control-Expose-Headers, so any website the victim visits can read
// the admin token straight out of the response headers with JavaScript.
const express = require('express');
const crypto = require('crypto');
const { page, hintBox, payloadBlock } = require('../../../lib/page');

const router = express.Router();

// Random per boot, only ever revealed through the vulnerable endpoint.
const ADMIN_TOKEN = crypto.randomBytes(16).toString('hex');

const vuln = {
  id: 'cors-expose-headers',
  name: 'Exposed Admin Token Header',
  difficulty: 'Easy',
  est: '5-10 minutes',
  hint: 'The response carries a sensitive token header. Whether a script on another origin may read it depends on a second response header: find both in Repeater.',
  hints: ["Replay /cors/api/token in Burp Repeater and read the response headers. Can a script on another origin read those headers?", "Only if a header is named in Access-Control-Expose-Headers. Check whether the response names one.", "The browser trusts that whitelist, so a page on an attacker origin can read the whitelisted header with fetch. Run the proof through /cors/prove and take the flag."],
  tools: "BZ, B",
  how: 'A sensitive response header rides on this endpoint. The real question is whether cross-origin scripts are allowed to read it.',
  link: '/cors#cors-expose-headers',
  start: 'Open /cors/expose through the Burp proxy browser, click "Check session status" to capture the session API request, then send it to Repeater and replay it with an attacker Origin to read the response headers.',
};

// GET /cors/api/token -> admin session status. A sensitive response header is
// exposed cross-origin, behavior identical to the module router.
router.get('/api/token', (req, res) => {
  // VULN: a sensitive response header is exposed cross-origin, so any site the
  // victim visits can read it with JavaScript.
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Expose-Headers', 'X-Admin-Token');
  res.set('X-Admin-Token', ADMIN_TOKEN);
  res.json({ ok: true, message: 'session valid' });
});

// GET /cors/expose -> the fictional internal app: Pentrix Admin Console, a
// session health check for administrators. Full claymorphism, real-app feel.
router.get('/expose', (req, res) => {
  res.send(page('Exposed Admin Token Header', `
    <div class="hero">
      <h1>Pentrix Admin Console</h1>
      <p class="lead">Session health check for administrators. Confirm your session is still valid before opening the console.</p>
      <div class="stats">
        <div class="stat"><b>Live</b><span>session status</span></div>
        <div class="stat"><b>JSON</b><span>served by /cors/api/token</span></div>
      </div>
    </div>
    ${hintBox(vuln.hint)}
    <div class="clay-card">
      <h2>Session status</h2>
      <p>Ask the session API whether your admin session is valid.</p>
      <button class="clay-btn clay-btn-primary" id="check-session" type="button">Check session status</button>
      <pre id="session-out" aria-live="polite">Press the button to check your session.</pre>
    </div>
    <div class="clay-card">
      <h2>API and origin checker</h2>
      <p>Raw endpoint: <a href="/cors/api/token"><code>/cors/api/token</code></a></p>
      ${payloadBlock('Burp Repeater', 'GET /cors/api/token HTTP/1.1\nHost: <your-lab-address>\n\n')}
      <p>The checker sends a real request to the endpoint with the Origin you
      type and shows the exact response headers, the same check a browser
      performs before allowing a cross-origin read.</p>
      <form method="GET" action="/cors/prove">
        <input type="hidden" name="vuln" value="cors-expose-headers" />
        <div class="clay-field">
          <label for="origin-expose">Origin header to test</label>
          <input class="clay-input" type="text" id="origin-expose" name="origin" value="https://evil.com" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Send the request</button>
      </form>
      <p><a href="/cors/prove?vuln=cors-expose-headers">Choose your own Origin</a></p>
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/cors">Back to the module</a></p>
    <script>
      document.getElementById('check-session').addEventListener('click', async () => {
        const out = document.getElementById('session-out');
        out.textContent = 'Checking...';
        try {
          const r = await fetch('/cors/api/token');
          out.textContent = JSON.stringify(await r.json(), null, 2);
        } catch (e) {
          out.textContent = 'Request failed: ' + e;
        }
      });
    </script>
  `));
});

module.exports = {
  vuln,
  router,
};
