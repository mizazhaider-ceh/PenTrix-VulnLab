'use strict';
// SSRF via Host Header: GET /hostheader/status builds its server-side fetch
// target from the Host header. With Host: 127.0.0.1:13919 the server fetches
// the loopback-only internal monitoring agent and returns its secrets.
const express = require('express');
const crypto = require('crypto');
const http = require('http');
const { award } = require('../../../lib/flags');
const { esc, page, flagBox, fixPanel, brief, hintLadder, payloadBlock } = require('../../../lib/page');

const router = express.Router();

const APP = 'Nimbus Ops Monitor';

function shell(crumb, bodyHtml) {
  return `<section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">N</span><b>${esc(APP)}</b><span class="dim">${esc(crumb)}</span></div>
    ${bodyHtml}
  </section>`;
}

function navRow(links) {
  const all = (links || []).concat([['/hostheader', 'Module index']]);
  return `<p>${all.map(([href, label]) =>
    `<a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(href)}">${esc(label)}</a>`).join(' ')}</p>`;
}

// Internal monitoring agent. It binds 127.0.0.1 only, so in the lab story it is
// reachable solely by the server itself, never directly from the internet.
// (Moved here from the module router: it belongs to this challenge alone. The
// finisher must not keep a second copy in the module router or index.js, or
// the port bind will collide.)
let internalPort = null;
let internalUp = false;
// Per-boot seal: the real agent signs every response with this header. It is
// generated fresh each boot and never shown on any page, so the award can
// require it as proof the response really came from the internal agent and
// not from a stand-in server that merely returns the marker text.
const AGENT_SEAL = crypto.randomBytes(16).toString('hex');
const internalAgent = http.createServer((req, res) => {
  if (req.url === '/hostheader/internal/metrics') {
    res.setHeader('X-Internal-Agent-Seal', AGENT_SEAL);
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({
      service: 'pentrix-internal-monitor',
      exposure: 'loopback only - not reachable from the internet',
      db_password: 'DbP@ss-Internal-9921',
      admin_api_key: 'ak-internal-7f3a9c2e',
    }, null, 2));
  }
  res.statusCode = 404;
  res.end('not found');
});
internalAgent.on('error', (err) => {
  console.error('[hostheader] internal agent could not start:', err.message);
});
// Per-instance ephemeral port: the agent must be bindable on every lab
// instance (classroom pools run many instances on one host), so it takes a
// free loopback port at boot. The /status page shows the real address, and
// the award still requires the per-boot seal, so a stand-in on any other
// port cannot win.
internalAgent.listen(0, '127.0.0.1', () => {
  internalPort = internalAgent.address().port;
  internalUp = true;
});

// GET /hostheader/internal/metrics -> the same path on the public app returns
// only boring public metrics.
router.get('/internal/metrics', (req, res) => {
  res.json({ service: 'pentrix-web', status: 'ok', version: '1.0-lab' });
});

// GET /hostheader/status -> server-side health check whose target is built
// from the Host header.
router.get('/status', async (req, res) => {
  const host = req.headers.host || '';
  // VULN: the server-side health check builds its target URL from the Host header.
  const target = 'http://' + host + '/hostheader/internal/metrics';
  let body = '';
  let errMsg = '';
  let seal = null;
  try {
    const r = await fetch(target, { signal: AbortSignal.timeout(4000) });
    seal = r.headers.get('x-internal-agent-seal');
    body = await r.text();
  } catch (e) {
    errMsg = String((e && e.message) || e);
  }
  let flagHtml = '';
  // The marker text in the body is not proof: any stand-in server can return
  // it. Award only when the response also carries the internal agent's
  // per-boot seal header, which only the real agent sets.
  if (body.includes('ak-internal-') && seal === AGENT_SEAL) {
    const flag = award(req, 'hostheader', 'host-ssrf');
    flagHtml = `<hr /><p><b>Exfiltrated:</b> the server fetched an internal-only
      URL on your behalf and handed you its secrets.</p>${flagBox(flag)}${fixPanel('hostheader', 'host-ssrf')}`;
  }
  res.send(page('Service health check', `
    ${shell('Monitoring', `
      <h2>Service health check</h2>
      ${brief('What this page does', `The monitor fetches the app's own metrics
        page to check health. The fetch target is built from the
        <code>Host</code> header of your request:`)}
      ${payloadBlock('Server-side fetch target', 'GET ' + target)}
      ${errMsg
        ? `<p class="clay-err" role="alert">Fetch failed: ${esc(errMsg)}</p>`
        : `<div class="payload"><div class="payload-head"><span>Upstream response</span></div><pre class="payload-body"><code>${esc(body.slice(0, 2000))}</code></pre></div>`}
      <p class="note dim">An internal monitoring agent listens on
      <code>127.0.0.1:${internalPort || '(starting)'}</code> (loopback only)
      ${internalUp ? '(agent is up)' : '(agent failed to start - see server log)'}. Can you make the
      server's fetch reach it?</p>
      ${flagHtml}
    `)}
    ${hintLadder(vuln)}
    ${navRow([])}
  `));
});

const vuln = {
  id: 'host-ssrf',
  name: 'SSRF via Host Header',
  difficulty: 'Medium',
  hint: 'The health check fetches http://<Host>/hostheader/internal/metrics server-side. A loopback-only agent holds secrets, and the status page shows its loopback address.',
  hints: ["The health check builds a URL from the Host header. Send the request to Repeater in Burp and check which URL the page says the server will fetch.", "The fetch target is http://<Host>/hostheader/internal/metrics, and the page names the loopback-only agent's address. In Repeater, edit the Host header so the server's fetch reaches that agent instead of the public site.", "Think about whose network the fetch runs from: the server's. Set the Host header in Repeater so the server-side fetch targets the internal agent. The key insight: an address your browser could never reach becomes reachable when the server fetches it."],
  tools: 'BZ, C',
  how: 'In Burp Repeater, send GET /hostheader/status with the Host header set to the loopback-only internal agent address shown on the status page, so the server fetches the internal agent for you.',
  link: '/hostheader#host-ssrf',
  start: 'Open /hostheader/status in the browser with Burp Proxy on, send the request to Repeater, then edit the Host header in Repeater and re-send until the upstream response shows the internal agent secrets.',
};

module.exports = { vuln, router };
