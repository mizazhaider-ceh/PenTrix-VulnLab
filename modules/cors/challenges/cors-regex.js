'use strict';
// Regex Allowlist Bypass: the metrics API trusts any https:// origin merely
// containing "pentrix.lab" because the allowlist regex has no subdomain
// boundary and no end anchor, so https://pentrix.lab.evil.com passes.
const express = require('express');
const { page, hintBox, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'cors-regex',
  name: 'Regex Allowlist Bypass',
  difficulty: 'Medium',
  hint: 'The regex is ^https://.*pentrix\\.lab with no subdomain boundary and no end anchor. It matches strings, not domain boundaries.',
  hints: ["The allowlist is the regex ^https://.*pentrix\\.lab. In Burp Repeater, request /cors/api/data with an Origin header and watch which origins come back echoed.", "No subdomain boundary and no end anchor: the check matches strings, not domain boundaries. Stay in Repeater and edit the Origin header by hand for each candidate; a handful of edits beats setting up Intruder Sniper for this one.", "An origin that merely contains the expected string instead of sitting under it passes. The endpoint echoes whatever you send, and the reflected winner earns the flag."],
  tools: "BZ, B",
  est: 'about 10 minutes',
  how: 'The allowlist is a pattern, not a boundary. Find an origin that satisfies the pattern while actually belonging to someone else.',
  link: '/cors#cors-regex',
  start: 'Burp: send GET /cors/api/data to Repeater and edit the Origin header by hand for each candidate. Some origins should fail the pattern; one should pass it for the wrong reason.',
};

// GET /cors/api/data -> weekly security metrics. The CORS check is a naive
// regex allowlist, behavior identical to the module router.
router.get('/api/data', (req, res) => {
  const origin = req.headers.origin || '';
  // VULN: naive regex allowlist with no subdomain boundary and no end anchor.
  // The developer forgot the dot before "pentrix" and the "$" at the end, so any
  // https:// origin merely containing "pentrix.lab" passes, including
  // https://pentrix.lab.evil.com.
  if (/^https:\/\/.*pentrix\.lab/.test(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ report: 'weekly security metrics', internal: true });
});

// GET /cors/regex -> the fictional internal app: Pentrix Metrics, a security
// metrics dashboard for pentrix.lab staff. Full claymorphism, real-app feel.
router.get('/regex', (req, res) => {
  res.send(page('Regex Allowlist Bypass', `
    <div class="hero">
      <h1>Pentrix Metrics</h1>
      <p class="lead">Internal security metrics dashboard. Access is restricted to pentrix.lab origins.</p>
      <div class="stats">
        <div class="stat"><b>Weekly</b><span>security metrics</span></div>
        <div class="stat"><b>Internal</b><span>scope: staff only</span></div>
        <div class="stat"><b>JSON</b><span>served by /cors/api/data</span></div>
      </div>
    </div>
    ${hintBox(vuln.hint)}
    <div class="clay-card">
      <h2>Latest report</h2>
      <p>Pulls the live JSON report from the metrics API.</p>
      <button class="clay-btn clay-btn-primary" id="load-report" type="button">Load latest report</button>
      <pre id="report-out" aria-live="polite">Press the button to load the report.</pre>
    </div>
    <div class="clay-card">
      <h2>API and origin checker</h2>
      <p>Raw endpoint: <a href="/cors/api/data"><code>/cors/api/data</code></a></p>
      ${payloadBlock('Burp Repeater', 'GET /cors/api/data HTTP/1.1\nHost: <your-lab-address>\nOrigin: https://pentrix.lab.evil.com\n\n')}
      <p>The checker sends a real request to the endpoint with the Origin you
      type and shows the exact response headers, the same check a browser
      performs before allowing a cross-origin read.</p>
      <form method="GET" action="/cors/prove">
        <input type="hidden" name="vuln" value="cors-regex" />
        <div class="clay-field">
          <label for="origin-regex">Origin header to test</label>
          <input class="clay-input" type="text" id="origin-regex" name="origin" value="https://pentrix.lab.evil.com" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Send the request</button>
      </form>
      <p><a href="/cors/prove?vuln=cors-regex">Choose your own Origin</a></p>
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/cors">Back to the module</a></p>
    <script>
      document.getElementById('load-report').addEventListener('click', async () => {
        const out = document.getElementById('report-out');
        out.textContent = 'Loading...';
        try {
          const r = await fetch('/cors/api/data');
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
