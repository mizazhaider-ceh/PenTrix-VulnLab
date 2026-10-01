// PenTrix VulnLab module: Server-Side Request Forgery (SSRF)
// An intentionally vulnerable URL fetcher. The server blindly fetches any
// URL the user supplies, letting an attacker reach internal-only endpoints.

const express = require('express');
const http = require('http');
const https = require('https');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();

const SECRET_MARKER = 'SSRF-INTERNAL-9921';
const FETCH_TIMEOUT_MS = 5000;

function port() {
  return process.env.PORT || 3000;
}

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

// Renders the fetch-result page. On success, shows the raw body escaped for
// display and awards the flag when the internal secret marker is present.
function resultPage(title, req, url, body, err, modId, vulnId, opts = {}) {
  let html = `<h2>${esc(title)}</h2>`;
  html += `<p class="dim">Fetched: <code>${esc(url)}</code></p>`;
  if (err) {
    html += `<div class="error">Fetch failed: <code>${esc(err.message)}</code></div>`;
  } else {
    html += `<h3>Response body</h3><pre class="resp">${esc(body)}</pre>`;
    if (body.includes(SECRET_MARKER)) {
      // Real success: the attacker reached the internal secret endpoint.
      if (opts.requireBypass) {
        const usedBlockedHost = url.includes('127.0.0.1') || url.includes('localhost');
        if (!usedBlockedHost) {
          html += flagBox(award(req, modId, vulnId));
        } else {
          html += `<p class="dim">Marker found, but the URL used a blocked host string, so this does not count as a bypass.</p>`;
        }
      } else {
        html += flagBox(award(req, modId, vulnId));
      }
    }
  }
  html += `<p><a href="/ssrf">&larr; Back to the SSRF module</a></p>`;
  return page(title, html);
}

// ---- Internal-only endpoints (would be unreachable from outside in a real
// deployment; SSRF lets the attacker reach them through the server itself) ----

router.get('/internal/status', (req, res) => {
  res.type('text').send('internal ok');
});

router.get('/internal/secret', (req, res) => {
  res.type('text').send(`internal secret marker: ${SECRET_MARKER}`);
});

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

// ---- v2: naive blocklist fetcher ---------------------------------------

const BLOCKED = ['127.0.0.1', 'localhost'];

router.get('/fetch2', async (req, res) => {
  const url = String(req.query.url || '');
  
  // VULN: blocklist is a naive substring check; alternate loopback
  // representations such as 2130706433 or 0.0.0.0 slip through and the
  // server still fetches them.
  if (BLOCKED.some((s) => url.includes(s))) {
    const html = page(
      'SSRF Fetch 2',
      `<h2>SSRF Fetch 2 (blocklisted)</h2>
       <p class="dim">Fetched: <code>${esc(url)}</code></p>
       <div class="error">Blocked: URL contains a forbidden host.</div>
       <p><a href="/ssrf">&larr; Back to the SSRF module</a></p>`
    );
    return res.status(403).send(html);
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

// ---- Module index -------------------------------------------------------

router.get('/', (req, res) => {
  const p = port();
  const internalSecret = `http://127.0.0.1:${p}/ssrf/internal/secret`;
  const bypassA = `http://2130706433:${p}/ssrf/internal/secret`;
  const bypassB = `http://0.0.0.0:${p}/ssrf/internal/secret`;
  const body = `
  ${brief('Server-Side Request Forgery', `
    This module exposes a small service that fetches a URL <b>on the server side</b>
    and shows you the response. The server has two internal-only endpoints
    (<code>/ssrf/internal/status</code> and <code>/ssrf/internal/secret</code>)
    that are meant for the server itself, not for you. Your goal is to trick the
    fetcher into reaching them and leaking the secret marker.`)}
  <h2>Vulnerabilities</h2>
  <table class="vulns">
    <tr><th>ID</th><th>Name</th><th>Difficulty</th><th>What to do</th><th>Hint</th></tr>
    <tr>
      <td><code>basic</code></td><td>Basic SSRF</td><td>Medium</td>
      <td>Get the fetcher to read the internal secret endpoint.</td>
      <td>${hintBox('The server fetches whatever URL you give it. What does "127.0.0.1" mean from the server\'s point of view? Try <code>' + esc(internalSecret) + '</code>.')}</td>
    </tr>
    <tr>
      <td><code>bypass</code></td><td>Blocklist bypass</td><td>Hard</td>
      <td>Reach the internal secret through <code>/ssrf/fetch2</code> without using the blocked strings.</td>
      <td>${hintBox('The blocklist just looks for substrings. Loopback has more than one spelling: <code>2130706433</code> is the decimal form of 127.0.0.1, and Node also accepts <code>0.0.0.0</code>.')}</td>
    </tr>
  </table>

  <h2>Challenge 1: open fetcher</h2>
  <form action="/ssrf/fetch" method="get">
    <label for="url1">URL to fetch:</label>
    <input id="url1" name="url" size="60" placeholder="http://example.com/">
    <button type="submit">Fetch</button>
  </form>

  <h2>Challenge 2: blocklisted fetcher</h2>
  <form action="/ssrf/fetch2" method="get">
    <label for="url2">URL to fetch:</label>
    <input id="url2" name="url" size="60" placeholder="http://example.com/">
    <button type="submit">Fetch</button>
  </form>

  <h2>Quick links</h2>
  <ul>
    <li><a href="/ssrf/internal/status">Internal status endpoint</a> (see what it returns)</li>
    <li><a href="/ssrf/fetch?url=${encodeURIComponent(internalSecret)}">Fetch the internal secret via the open fetcher</a></li>
    <li><a href="/ssrf/fetch2?url=${encodeURIComponent(bypassA)}">Bypass attempt: decimal loopback</a></li>
    <li><a href="/ssrf/fetch2?url=${encodeURIComponent(bypassB)}">Bypass attempt: 0.0.0.0</a></li>
  </ul>`;
  res.send(page('Server-Side Request Forgery', body));
});

module.exports = {
  id: 'ssrf',
  name: 'Server-Side Request Forgery',
  tagline: 'Make the server fetch URLs for you, then turn it against its own internals.',
  description: 'The app fetches user-supplied URLs server-side. Pivot through it to reach internal-only endpoints and bypass a naive blocklist.',
  difficulty: 'Intermediate',
  vulns: [
    {
      id: 'basic',
      name: 'Basic SSRF',
      difficulty: 'Medium',
      hint: 'The server fetches whatever URL you give it. What does 127.0.0.1 mean from the server\'s point of view?',
      how: 'Point the fetcher at http://127.0.0.1:PORT/ssrf/internal/secret.',
    },
    {
      id: 'bypass',
      name: 'Blocklist bypass',
      difficulty: 'Hard',
      hint: 'The blocklist is a naive substring check. Loopback has more than one spelling.',
      how: 'Fetch the internal secret via /ssrf/fetch2 using http://2130706433:PORT/... or http://0.0.0.0:PORT/....',
    },
  ],
  router,
};
