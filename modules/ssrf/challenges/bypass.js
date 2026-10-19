'use strict';
// Blocklist bypass SSRF: GET /ssrf/fetch2 fetches any user-supplied URL
// server-side, with only a naive substring blocklist in the way.
const express = require('express');
const http = require('http');
const https = require('https');
const { appShell, esc, flagBox, fixPanel, hintLadder, page, toolsPill } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const SECRET_MARKER = 'SSRF-INTERNAL-9921';
const FETCH_TIMEOUT_MS = 5000;

const vuln = {
  id: 'bypass',
  name: 'Blocklist bypass',
  difficulty: 'Hard',
  hint: 'The blocklist is a naive substring check. Loopback has more than one spelling.',
  hints: ["The fetcher blocks '127.0.0.1' as a substring. But an IP address is just a number. How else can you write 127.0.0.1?", "The blocklist is a naive string check on the raw URL text. The URL parser, however, also accepts loopback written as a single decimal number, with hex octets, or with leading-zero octal octets, and normalizes each of those forms back to 127.0.0.1.", "Rebuild the internal fetch URL using one of the alternate loopback spellings. The string check will wave it through while the URL parser still delivers the request to loopback."],
  tools: "C",
  how: 'Fetch the internal secret via /ssrf/fetch2 using http://2130706433:PORT/... or http://0.0.0.0:PORT/....',
  link: '/ssrf#bypass',
  start: 'curl -s "http://localhost:3000/ssrf/fetch2?url=http://example.com/"',
};

// Fetch a URL server-side with a hard timeout. Resolves with the raw body
// string, or rejects with an Error describing what went wrong.
function fetchBody(targetUrl) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (e) {
      return reject(new Error('Invalid URL'));
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return reject(new Error('Only http(s) URLs are supported'));
    }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.get(parsed, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Fetch timed out after 5s'));
    });
    req.setTimeout(FETCH_TIMEOUT_MS);
    req.on('error', reject);
  });
}

// Renders the fetch-result page inside the FetchBox Pro app shell. On
// success, shows the raw body escaped for display and awards the flag only
// when the internal secret marker was reached WITHOUT a blocked host string.
function resultPage(title, req, url, body, err, modId, vulnId, opts = {}) {
  let inner = `<h2>${esc(title)}</h2>`;
  inner += `<p class="dim">Fetched: <code>${esc(url)}</code></p>`;
  if (err) {
    inner += `<div class="error">Fetch failed: <code>${esc(err.message)}</code></div>`;
  } else {
    inner += `<h3>Response body</h3><pre class="resp">${esc(body)}</pre>`;
    if (body.includes(SECRET_MARKER)) {
      // Real success: the attacker reached the internal secret endpoint.
      if (opts.requireBypass) {
        const usedBlockedHost = url.includes('127.0.0.1') || url.includes('localhost');
        if (!usedBlockedHost) {
          inner += flagBox(award(req, modId, vulnId));
          inner += fixPanel(modId, vulnId);
        } else {
          inner += `<p class="dim">Marker found, but the URL used a blocked host string, so this does not count as a bypass.</p>`;
        }
      } else if (opts.requireRedirect && !(opts.redirects > 0)) {
        inner += `<p class="dim">Marker found, but no redirect was followed, so the redirect technique was not demonstrated.</p>`;
      } else {
        inner += flagBox(award(req, modId, vulnId));
        inner += fixPanel(modId, vulnId);
      }
    }
  }
  const form = `<div class="card">
    <h2>Fetch a link (protected edition)</h2>
    <p class="dim">Same fast server-side fetching, now with our new host blocklist keeping internal addresses out of reach.</p>
    <form action="/ssrf/fetch2" method="get">
      <label class="dim" for="url">URL to fetch</label>
      <input class="clay-input" id="url" name="url" type="text" size="60" placeholder="http://example.com/" value="${esc(url === '(none)' ? '' : url)}">
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
  </div>`;
  const bodyHtml = appShell('FetchBox Pro', form + `<div class="card">${inner}</div>
    ${hintLadder(vuln)}
    ${toolsPill(vuln.tools)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>`, { mark: '🔗', nav: ['Preview', 'History', 'API'] });
  return page(title, bodyHtml);
}

// ---- v2: naive blocklist fetcher ---------------------------------------

const BLOCKED = ['127.0.0.1', 'localhost'];

router.get('/fetch2', async (req, res) => {
  const url = String(req.query.url || '');

  // VULN: blocklist is a naive substring check; alternate loopback
  // representations such as 2130706433 or 0.0.0.0 slip through and the
  // server still fetches them.
  if (BLOCKED.some((s) => url.includes(s))) {
    const bodyHtml = appShell('FetchBox Pro', `<div class="card">
      <h2>SSRF Fetch 2 (blocklisted)</h2>
      <p class="dim">Fetched: <code>${esc(url)}</code></p>
      <div class="error">Blocked: URL contains a forbidden host.</div>
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>`, { mark: '🔗', nav: ['Preview', 'History', 'API'] });
    return res.status(403).send(page('SSRF Fetch 2', bodyHtml));
  }
  if (!url) {
    return res.send(resultPage('SSRF Fetch 2', req, '(none)', '', new Error('Provide a ?url= parameter'), 'ssrf', 'bypass', { requireBypass: true }));
  }
  try {
    const body = await fetchBody(url);
    res.send(resultPage('SSRF Fetch 2', req, url, body, null, 'ssrf', 'bypass', { requireBypass: true }));
  } catch (e) {
    res.send(resultPage('SSRF Fetch 2', req, url, '', e, 'ssrf', 'bypass', { requireBypass: true }));
  }
});

module.exports = { vuln, router };
