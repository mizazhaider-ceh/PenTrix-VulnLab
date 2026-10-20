'use strict';
// Subdomain Suffix Check: the partner API trusts any Origin whose hostname
// ends with ".trusted.pentrix.lab", with no allowlist of real subdomains
// behind it, so an attacker-controlled subdomain is treated as trusted.
const express = require('express');
const { page, hintBox, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'cors-subdomain',
  name: 'Subdomain Suffix Check',
  difficulty: 'Medium',
  hint: 'The check is hostname.endsWith(".trusted.pentrix.lab") with no allowlist of real subdomains behind it.',
  hints: ["The check is hostname.endsWith('.trusted.pentrix.lab'). No allowlist of real subdomains sits behind it. In Repeater, add an Origin header to GET /cors/api/partner and watch the ACAO response header.", "Any subdomain of trusted.pentrix.lab passes the suffix check, including ones you control. In Repeater, swap in a subdomain label of your own choosing and resend.", "The suffix check cannot tell your invented subdomain apart from a real one, so the endpoint echoes your origin back with Access-Control-Allow-Credentials: true, and the flag box appears."],
  tools: "BZ, B",
  est: 'about 10 minutes',
  how: 'Partner access is granted by a suffix check on the hostname. A suffix is not an allowlist: whose subdomains can you invent?',
  link: '/cors#cors-subdomain',
  start: 'Burp: send GET /cors/api/partner to Repeater, add an Origin header, and try a subdomain label of your own invention under the trusted suffix. The prove check accepts any invented label, not one specific word.',
};

// GET /cors/api/partner -> partner discount data. The CORS check is a
// suffix-only subdomain check, behavior identical to the module router.
router.get('/api/partner', (req, res) => {
  const origin = req.headers.origin || '';
  let host = '';
  try { host = new URL(origin).hostname; } catch (e) { host = ''; }
  // VULN: suffix-only subdomain check with no allowlist. Any subdomain of
  // trusted.pentrix.lab passes, including attacker-controlled ones.
  if (host.endsWith('.trusted.pentrix.lab')) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ partner: true, discount: '20%' });
});

// GET /cors/subdomain -> the fictional internal app: Pentrix Partners, a
// partner discount portal for trusted subdomains. Full claymorphism,
// real-app feel.
router.get('/subdomain', (req, res) => {
  res.send(page('Subdomain Suffix Check', `
    <div class="hero">
      <h1>Pentrix Partners</h1>
      <p class="lead">Partner discount portal. Trusted partners browse from their own subdomain and get 20% off.</p>
      <div class="stats">
        <div class="stat"><b>20%</b><span>partner discount</span></div>
        <div class="stat"><b>Live</b><span>data from /cors/api/partner</span></div>
      </div>
    </div>
    ${hintBox(vuln.hint)}
    <div class="clay-card">
      <h2>Partner status check</h2>
      <p>The portal calls the partner API to confirm your discount tier.</p>
      <button class="clay-btn clay-btn-primary" id="check-partner" type="button">Check my partner status</button>
      <pre id="partner-out" aria-live="polite">Press the button to check your status.</pre>
    </div>
    <div class="clay-card">
      <h2>API and origin checker</h2>
      <p>Raw endpoint: <a href="/cors/api/partner"><code>/cors/api/partner</code></a></p>
      ${payloadBlock('Burp Repeater', 'GET /cors/api/partner HTTP/1.1\nHost: <your-lab-address>\nOrigin: https://evil.trusted.pentrix.lab\n\n')}
      <p>The checker sends a real request to the endpoint with the Origin you
      type and shows the exact response headers, the same check a browser
      performs before allowing a cross-origin read.</p>
      <form method="GET" action="/cors/prove">
        <input type="hidden" name="vuln" value="cors-subdomain" />
        <div class="clay-field">
          <label for="origin-subdomain">Origin header to test</label>
          <input class="clay-input" type="text" id="origin-subdomain" name="origin" value="https://evil.trusted.pentrix.lab" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Send the request</button>
      </form>
      <p><a href="/cors/prove?vuln=cors-subdomain">Choose your own Origin</a></p>
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/cors">Back to the module</a></p>
    <script>
      document.getElementById('check-partner').addEventListener('click', async () => {
        const out = document.getElementById('partner-out');
        out.textContent = 'Checking...';
        try {
          const r = await fetch('/cors/api/partner');
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
