'use strict';
// Basic SSRF: GET /ssrf/fetch fetches any user-supplied URL server-side.
const express = require('express');
const http = require('http');
const https = require('https');
const { appShell, esc, flagBox, fixPanel, hintLadder, page, toolsPill } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const SECRET_MARKER = 'SSRF-INTERNAL-9921';
const FETCH_TIMEOUT_MS = 5000;

const vuln = {
  id: 'basic',
  name: 'Basic SSRF',
  difficulty: 'Medium',
  hint: 'The server fetches whatever URL you give it. What does 127.0.0.1 mean from the server\'s point of view?',
  hints: ["The app fetches a URL you provide and shows you the result. What can the server reach that you can't?", "The server is inside the network. Give it an internal URL (127.0.0.1) and it will fetch it for you.", "Think from the server's point of view: the internal secret lives on its own loopback interface. Feed the fetcher a loopback URL aimed at the internal secret path, and the server-side request will return the internal marker."],
  tools: "B, C",
  how: 'Point the fetcher at http://127.0.0.1:PORT/ssrf/internal/secret.',
  link: '/ssrf#basic',
  start: 'curl -s "http://localhost:3000/ssrf/fetch?url=http://example.com/"',
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

// Renders the fetch-result page inside the FetchBox app shell. On success,
// shows the raw body escaped for display and awards the flag when the
// internal secret marker is present.
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
    <h2>Fetch a link</h2>
    <p class="dim">Paste any URL. FetchBox fetches it server-side and shows you exactly what the server receives.</p>
    <form action="/ssrf/fetch" method="get">
      <label class="dim" for="url">URL to fetch</label>
      <input class="clay-input" id="url" name="url" type="text" size="60" placeholder="http://example.com/" value="${esc(url === '(none)' ? '' : url)}">
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
  </div>`;
  const bodyHtml = appShell('FetchBox', form + `<div class="card">${inner}</div>
    ${hintLadder(vuln)}
    ${toolsPill(vuln.tools)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>`, { mark: '🔗', nav: ['Preview', 'History', 'API'] });
  return page(title, bodyHtml);
}

// ---- v1: wide-open fetcher ---------------------------------------------

router.get('/fetch', async (req, res) => {
  const url = String(req.query.url || '');

  // VULN: user-supplied URL is fetched server-side with no validation at all.
  if (!url) {
    return res.send(resultPage('SSRF Fetch', req, '(none)', '', new Error('Provide a ?url= parameter'), 'ssrf', 'basic'));
  }
  try {
    const body = await fetchBody(url);
    res.send(resultPage('SSRF Fetch', req, url, body, null, 'ssrf', 'basic'));
  } catch (e) {
    res.send(resultPage('SSRF Fetch', req, url, '', e, 'ssrf', 'basic'));
  }
});

module.exports = { vuln, router };
