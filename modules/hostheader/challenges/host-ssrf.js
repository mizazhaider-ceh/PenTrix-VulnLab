'use strict';
// SSRF via Host Header: GET /hostheader/status builds its server-side fetch
// target from the Host header. With Host: 127.0.0.1:13919 the server fetches
// the loopback-only internal monitoring agent and returns its secrets.
const express = require('express');
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
const INTERNAL_PORT = 13919;
let internalUp = false;
const internalAgent = http.createServer((req, res) => {
  if (req.url === '/hostheader/internal/metrics') {
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
internalAgent.listen(INTERNAL_PORT, '127.0.0.1', () => { internalUp = true; });

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
  try {
    const r = await fetch(target, { signal: AbortSignal.timeout(4000) });
    body = await r.text();
  } catch (e) {
    errMsg = String((e && e.message) || e);
  }
  let flagHtml = '';
  if (body.includes('ak-internal-')) {
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
      <code>127.0.0.1:${INTERNAL_PORT}</code> (loopback only)
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
  hint: 'The health check fetches http://<Host>/hostheader/internal/metrics server-side. A loopback-only agent on 127.0.0.1:13919 holds secrets.',
  hints: ["The health check builds a URL from the Host header. What URL?", "The fetch target is http://<Host>/hostheader/internal/metrics, and the page tells you where the loopback-only agent listens. Make the server's fetch reach that agent by choosing Host accordingly.", "Point the Host header at the loopback address and port the internal agent listens on, so the server-side fetch reaches it. The key insight: the fetch runs from the server's network position, so an address your browser could never reach becomes reachable when the server fetches it."],
  tools: 'C',
  how: 'GET /hostheader/status with Host: 127.0.0.1:13919 so the server fetches the internal agent for you.',
  link: '/hostheader#host-ssrf',
  start: 'curl -s http://localhost:3000/hostheader/status\ncurl -s -H "Host: 127.0.0.1:13919" http://localhost:3000/hostheader/status',
};

module.exports = { vuln, router };
