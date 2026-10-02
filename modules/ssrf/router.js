// PenTrix VulnLab module: Server-Side Request Forgery (SSRF)
// An intentionally vulnerable URL fetcher. The server blindly fetches any
// URL the user supplies, letting an attacker reach internal-only endpoints.

const express = require('express');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

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
      } else if (opts.requireRedirect && !(opts.redirects > 0)) {
        html += `<p class="dim">Marker found, but no redirect was followed, so the redirect technique was not demonstrated.</p>`;
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

// ---- v3: redirect-following fetcher ------------------------------------

// Fetch a URL, following up to 5 redirects. Resolves with
// { body, redirects } where redirects counts followed 3xx responses.
function fetchBodyFollow(targetUrl, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    const step = (current, count) => {
      let parsed;
      try {
        parsed = new URL(current);
      } catch (e) {
        return reject(new Error('Invalid URL'));
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return reject(new Error('Only http(s) URLs are supported'));
      }
      const mod = parsed.protocol === 'https:' ? https : http;
      const req = mod.get(parsed, (res) => {
        const loc = res.headers.location;
        if (res.statusCode >= 300 && res.statusCode < 400 && loc && count < maxRedirects) {
          res.resume(); // discard the redirect body
          let next;
          try {
            next = new URL(loc, current).toString();
          } catch (e) {
            return reject(new Error('Bad redirect location'));
          }
          return step(next, count + 1);
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ body: Buffer.concat(chunks).toString('utf8'), redirects: count }));
        res.on('error', reject);
      });
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Fetch timed out after 5s'));
      });
      req.setTimeout(FETCH_TIMEOUT_MS);
      req.on('error', reject);
    };
    step(targetUrl, 0);
  });
}

// Open redirect used by the redirect lab. The destination is fully
// attacker-controlled, including internal hosts.
router.get('/jump', (req, res) => {
  const to = String(req.query.to || '/ssrf/internal/status');
  // VULN: open redirect — any destination is allowed.
  res.redirect(302, to);
});

const REDIRECT_BLOCKED = ['127.0.0.1'];

router.get('/fetch3', async (req, res) => {
  const url = String(req.query.url || '');

  // VULN: the blocklist is checked against the initial URL only, and only
  // against its parsed hostname. Redirect targets are followed without any
  // re-validation, so bouncing through the open redirect at /ssrf/jump
  // smuggles the request to a blocked host.
  let initialHost = '';
  try { initialHost = new URL(url).hostname; } catch (e) { /* invalid URL; reported below */ }
  if (REDIRECT_BLOCKED.includes(initialHost)) {
    return res.status(403).send(page(
      'SSRF Fetch 3',
      `<h2>SSRF Fetch 3 (redirect follower)</h2>
       <p class="dim">Fetched: <code>${esc(url)}</code></p>
       <div class="error">Blocked: URL contains a forbidden host.</div>
       <p><a href="/ssrf">&larr; Back to the SSRF module</a></p>`
    ));
  }
  const done = (body, err, redirects) => res.send(
    resultPage('SSRF Fetch 3', req, url || '(none)', body, err, 'ssrf', 'ssrf-redirect',
      { requireRedirect: true, redirects })
  );
  if (!url) return done('', new Error('Provide a ?url= parameter'), 0);
  try {
    const { body, redirects } = await fetchBodyFollow(url);
    done(body, null, redirects);
  } catch (e) {
    done('', e, 0);
  }
});

// ---- v4: single-technique bypass fetchers ------------------------------
// Each endpoint below validates the URL with a different naive check and
// awards its own flag when the internal secret marker comes back, which
// proves the check was bypassed.

function blockedPage(title, url, msg) {
  return page(title, `<h2>${esc(title)}</h2>
    <p class="dim">Fetched: <code>${esc(url)}</code></p>
    <div class="error">${esc(msg)}</div>
    <p><a href="/ssrf">&larr; Back to the SSRF module</a></p>`);
}

async function guardedFetch(req, res, cfg) {
  const url = String(req.query.url || '');
  const problem = cfg.check(url);
  if (problem) return res.status(403).send(blockedPage(cfg.title, url, problem));
  if (!url) {
    return res.send(resultPage(cfg.title, req, '(none)', '', new Error('Provide a ?url= parameter'), 'ssrf', cfg.vulnId));
  }
  try {
    const body = await cfg.fetch(url);
    res.send(resultPage(cfg.title, req, url, body, null, 'ssrf', cfg.vulnId));
  } catch (e) {
    res.send(resultPage(cfg.title, req, url, '', e, 'ssrf', cfg.vulnId));
  }
}

const rawHostBlock = (url) =>
  BLOCKED.some((s) => url.includes(s)) ? 'Blocked: URL contains a forbidden host.' : null;

// VULN (hex/octal/single-int): the blocklist is a naive substring test on
// the raw URL string. The WHATWG URL parser normalizes alternate loopback
// spellings (0x7f.0.0.1, 0177.0.0.1, 2130706433) to 127.0.0.1, so they slip
// past the string check while the request still goes to loopback.
router.get('/hex-ip', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Hex IP', vulnId: 'ssrf-hex-ip', check: rawHostBlock, fetch: fetchBody,
}));

router.get('/octal-ip', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Octal IP', vulnId: 'ssrf-octal-ip', check: rawHostBlock, fetch: fetchBody,
}));

router.get('/single-int', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Integer IP', vulnId: 'ssrf-single-int', check: rawHostBlock, fetch: fetchBody,
}));

router.get('/zero-ip', (req, res) => guardedFetch(req, res, {
  title: 'SSRF 0.0.0.0', vulnId: 'ssrf-zero-ip', check: rawHostBlock,
  fetch: async (url) => {
    const u = new URL(url);
    // 0.0.0.0 passes the string blocklist; many HTTP stacks treat it as
    // "this host", so the lab rewrites it to loopback the way those stacks do.
    if (u.hostname === '0.0.0.0') u.hostname = '127.0.0.1';
    return fetchBody(u.toString());
  },
}));

router.get('/userinfo', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Userinfo', vulnId: 'ssrf-userinfo',
  // VULN: the "allowlist" inspects the raw URL string for a trusted domain
  // instead of parsing the real hostname, so userinfo smuggling
  // (http://pentrix.lab@127.0.0.1/) passes while the request goes to 127.0.0.1.
  check: (url) => (url.includes('pentrix.lab') ? null : 'Blocked: only pentrix.lab URLs may be fetched.'),
  fetch: fetchBody,
}));

// ---- v5: simulated cloud metadata ---------------------------------------

function metadataDoc() {
  return JSON.stringify({
    code: 'Success',
    lastUpdated: '2026-10-02T11:34:00Z',
    type: 'AWS-HMAC',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + SECRET_MARKER,
    token: 'AgoEXAMPLE4f5z9TokenSimulated==',
    expiration: '2026-10-02T17:34:00Z',
  }, null, 2);
}

router.get('/fetch-meta', async (req, res) => {
  const url = String(req.query.url || '');
  const title = 'SSRF Cloud Metadata';
  if (!url) {
    return res.send(resultPage(title, req, '(none)', '', new Error('Provide a ?url= parameter'), 'ssrf', 'ssrf-metadata'));
  }
  try {
    const parsed = new URL(url);
    // VULN: the fetcher happily requests the cloud link-local metadata
    // address; this lab simulates that metadata service in-process and it
    // returns instance credentials containing the secret marker.
    const body = parsed.hostname === '169.254.169.254' ? metadataDoc() : await fetchBody(url);
    res.send(resultPage(title, req, url, body, null, 'ssrf', 'ssrf-metadata'));
  } catch (e) {
    res.send(resultPage(title, req, url, '', e, 'ssrf', 'ssrf-metadata'));
  }
});

// ---- v6: file:// scheme --------------------------------------------------

router.get('/fetch-file', async (req, res) => {
  const url = String(req.query.url || '');
  const title = 'SSRF File Scheme';
  if (!url) {
    return res.send(resultPage(title, req, '(none)', '', new Error('Provide a ?url= parameter'), 'ssrf', 'ssrf-file'));
  }
  try {
    const parsed = new URL(url);
    let body;
    if (parsed.protocol === 'file:') {
      // VULN: the file:// scheme is allowed, turning the URL fetcher into a
      // local file reader with the server's filesystem privileges.
      body = fs.readFileSync(decodeURIComponent(parsed.pathname), 'utf8');
    } else {
      body = await fetchBody(url);
    }
    let html = `<h2>${esc(title)}</h2>`;
    html += `<p class="dim">Fetched: <code>${esc(url)}</code></p>`;
    html += `<h3>Response body</h3><pre class="resp">${esc(body)}</pre>`;
    if (body.includes('root:')) {
      html += flagBox(award(req, 'ssrf', 'ssrf-file'));
    } else {
      html += `<p class="dim">No local file content detected yet. Try <code>file:///etc/passwd</code>.</p>`;
    }
    html += `<p><a href="/ssrf">&larr; Back to the SSRF module</a></p>`;
    res.send(page(title, html));
  } catch (e) {
    res.send(resultPage(title, req, url, '', e, 'ssrf', 'ssrf-file'));
  }
});

// ---- Module index -------------------------------------------------------

router.get('/', (req, res) => {
  const p = port();
  const internalSecret = `http://127.0.0.1:${p}/ssrf/internal/secret`;
  const bypassA = `http://2130706433:${p}/ssrf/internal/secret`;
  const bypassB = `http://0.0.0.0:${p}/ssrf/internal/secret`;
  const redirectVia = `http://localhost:${p}/ssrf/jump?to=${encodeURIComponent(`http://127.0.0.1:${p}/ssrf/internal/secret`)}`;
  const userinfoVia = `http://pentrix.lab@127.0.0.1:${p}/ssrf/internal/secret`;
  const hexVia = `http://0x7f.0.0.1:${p}/ssrf/internal/secret`;
  const octalVia = `http://0177.0.0.1:${p}/ssrf/internal/secret`;
  const zeroVia = `http://0.0.0.0:${p}/ssrf/internal/secret`;
  const singleVia = `http://2130706433:${p}/ssrf/internal/secret`;
  const metaVia = `http://169.254.169.254/latest/meta-data/iam/security-credentials/`;
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
    <tr>
      <td><code>ssrf-redirect</code></td><td>Open-redirect SSRF</td><td>Medium</td>
      <td>Get <code>/ssrf/fetch3</code> to leak the internal secret by bouncing through the open redirect at <code>/ssrf/jump</code>.</td>
      <td>${hintBox('The blocklist only sees the first URL. Fetch the jump endpoint with <code>?to=</code> pointing at the internal secret: the fetcher follows the 302 without re-checking.')}</td>
    </tr>
    <tr>
      <td><code>ssrf-userinfo</code></td><td>Userinfo bypass</td><td>Easy</td>
      <td>Pass the <code>pentrix.lab</code> allowlist on <code>/ssrf/userinfo</code> while the request actually goes to loopback.</td>
      <td>${hintBox('The check looks for the trusted string anywhere in the URL. Put it before an <code>@</code>: <code>http://pentrix.lab@127.0.0.1:' + p + '/ssrf/internal/secret</code>.')}</td>
    </tr>
    <tr>
      <td><code>ssrf-hex-ip</code></td><td>Hex IP bypass</td><td>Medium</td>
      <td>Reach the internal secret through <code>/ssrf/hex-ip</code> using a hex-encoded loopback address.</td>
      <td>${hintBox('The blocklist compares raw strings, but the URL parser normalizes hex: try <code>http://0x7f.0.0.1:' + p + '/ssrf/internal/secret</code>.')}</td>
    </tr>
    <tr>
      <td><code>ssrf-octal-ip</code></td><td>Octal IP bypass</td><td>Medium</td>
      <td>Reach the internal secret through <code>/ssrf/octal-ip</code> using an octal-encoded loopback address.</td>
      <td>${hintBox('Leading zeros mean octal to the URL parser: try <code>http://0177.0.0.1:' + p + '/ssrf/internal/secret</code>.')}</td>
    </tr>
    <tr>
      <td><code>ssrf-zero-ip</code></td><td>0.0.0.0 bypass</td><td>Easy</td>
      <td>Reach the internal secret through <code>/ssrf/zero-ip</code> using <code>0.0.0.0</code> as the host.</td>
      <td>${hintBox('The blocklist never mentions <code>0.0.0.0</code>, and this fetcher treats it as "this host". Try <code>http://0.0.0.0:' + p + '/ssrf/internal/secret</code>.')}</td>
    </tr>
    <tr>
      <td><code>ssrf-single-int</code></td><td>Integer IP bypass</td><td>Medium</td>
      <td>Reach the internal secret through <code>/ssrf/single-int</code> using the single-decimal-integer form of 127.0.0.1.</td>
      <td>${hintBox('127.0.0.1 is 2130706433 as one decimal number. Try <code>http://2130706433:' + p + '/ssrf/internal/secret</code>.')}</td>
    </tr>
    <tr>
      <td><code>ssrf-metadata</code></td><td>Cloud metadata SSRF</td><td>Medium</td>
      <td>Use <code>/ssrf/fetch-meta</code> to read the simulated cloud instance metadata service and leak its credentials.</td>
      <td>${hintBox('Cloud VMs expose credentials at the link-local address <code>169.254.169.254</code>. Try <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code>.')}</td>
    </tr>
    <tr>
      <td><code>ssrf-file</code></td><td>file:// scheme SSRF</td><td>Medium</td>
      <td>Use <code>/ssrf/fetch-file</code> to read a local file through the fetcher.</td>
      <td>${hintBox('This fetcher allows more than http(s). Try <code>file:///etc/passwd</code>.')}</td>
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

  <h2>Challenge 3: redirect follower</h2>
  <p class="dim">This fetcher follows redirects, but the blocklist is only checked against the first URL. The open redirect at <code>/ssrf/jump?to=</code> goes anywhere you tell it to.</p>
  <form action="/ssrf/fetch3" method="get">
    <label for="url3">URL to fetch:</label>
    <input id="url3" name="url" size="60" placeholder="http://example.com/">
    <button type="submit">Fetch</button>
  </form>

  <h2>Challenge 4: one technique per fetcher</h2>
  <p class="dim">Each fetcher below has a different naive validation. Same goal every time: make it return the internal secret marker.</p>
  <form action="/ssrf/userinfo" method="get">
    <label for="url4a">Allowlisted fetcher (wants <code>pentrix.lab</code>):</label>
    <input id="url4a" name="url" size="60" placeholder="http://pentrix.lab/">
    <button type="submit">Fetch</button>
  </form>
  <form action="/ssrf/hex-ip" method="get">
    <label for="url4b">Hex IP fetcher:</label>
    <input id="url4b" name="url" size="60" placeholder="http://0x7f.0.0.1:PORT/ssrf/internal/secret">
    <button type="submit">Fetch</button>
  </form>
  <form action="/ssrf/octal-ip" method="get">
    <label for="url4c">Octal IP fetcher:</label>
    <input id="url4c" name="url" size="60" placeholder="http://0177.0.0.1:PORT/ssrf/internal/secret">
    <button type="submit">Fetch</button>
  </form>
  <form action="/ssrf/zero-ip" method="get">
    <label for="url4d">0.0.0.0 fetcher:</label>
    <input id="url4d" name="url" size="60" placeholder="http://0.0.0.0:PORT/ssrf/internal/secret">
    <button type="submit">Fetch</button>
  </form>
  <form action="/ssrf/single-int" method="get">
    <label for="url4e">Integer IP fetcher:</label>
    <input id="url4e" name="url" size="60" placeholder="http://2130706433:PORT/ssrf/internal/secret">
    <button type="submit">Fetch</button>
  </form>

  <h2>Challenge 5: cloud metadata</h2>
  <p class="dim">This lab simulates a cloud instance metadata service at the link-local address. Ask for its credentials.</p>
  <form action="/ssrf/fetch-meta" method="get">
    <label for="url5">URL to fetch:</label>
    <input id="url5" name="url" size="60" placeholder="http://169.254.169.254/latest/meta-data/">
    <button type="submit">Fetch</button>
  </form>

  <h2>Challenge 6: file scheme</h2>
  <p class="dim">This fetcher accepts an extra URL scheme. Point it at the local filesystem.</p>
  <form action="/ssrf/fetch-file" method="get">
    <label for="url6">URL to fetch:</label>
    <input id="url6" name="url" size="60" placeholder="file:///etc/passwd">
    <button type="submit">Fetch</button>
  </form>

  <h2>Quick links</h2>
  <ul>
    <li><a href="/ssrf/internal/status">Internal status endpoint</a> (see what it returns)</li>
    <li><a href="/ssrf/fetch?url=${encodeURIComponent(internalSecret)}">Fetch the internal secret via the open fetcher</a></li>
    <li><a href="/ssrf/fetch2?url=${encodeURIComponent(bypassA)}">Bypass attempt: decimal loopback</a></li>
    <li><a href="/ssrf/fetch2?url=${encodeURIComponent(bypassB)}">Bypass attempt: 0.0.0.0</a></li>
    <li><a href="/ssrf/fetch3?url=${encodeURIComponent(redirectVia)}">Redirect lab: bounce through /ssrf/jump to the internal secret</a></li>
    <li><a href="/ssrf/userinfo?url=${encodeURIComponent(userinfoVia)}">Userinfo trick vs the pentrix.lab allowlist</a></li>
    <li><a href="/ssrf/hex-ip?url=${encodeURIComponent(hexVia)}">Hex IP bypass</a></li>
    <li><a href="/ssrf/octal-ip?url=${encodeURIComponent(octalVia)}">Octal IP bypass</a></li>
    <li><a href="/ssrf/zero-ip?url=${encodeURIComponent(zeroVia)}">0.0.0.0 bypass</a></li>
    <li><a href="/ssrf/single-int?url=${encodeURIComponent(singleVia)}">Integer IP bypass</a></li>
    <li><a href="/ssrf/fetch-meta?url=${encodeURIComponent(metaVia)}">Cloud metadata credentials</a></li>
    <li><a href="/ssrf/fetch-file?url=${encodeURIComponent('file:///etc/passwd')}">file:///etc/passwd</a></li>
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
    {
      id: 'ssrf-redirect',
      name: 'Open-redirect SSRF',
      difficulty: 'Medium',
      hint: 'The blocklist only sees the first URL; the fetcher follows 302 redirects without re-checking.',
      how: 'Fetch http://localhost:PORT/ssrf/jump?to=<internal secret URL> via /ssrf/fetch3 so the redirect lands on the blocked host.',
    },
    {
      id: 'ssrf-userinfo',
      name: 'Userinfo bypass',
      difficulty: 'Easy',
      hint: 'The allowlist looks for the trusted string anywhere in the URL. What comes before @ is userinfo, not the host.',
      how: 'Fetch http://pentrix.lab@127.0.0.1:PORT/ssrf/internal/secret via /ssrf/userinfo.',
    },
    {
      id: 'ssrf-hex-ip',
      name: 'Hex IP bypass',
      difficulty: 'Medium',
      hint: 'The blocklist compares raw strings, but the URL parser normalizes hex IP parts.',
      how: 'Fetch http://0x7f.0.0.1:PORT/ssrf/internal/secret via /ssrf/hex-ip.',
    },
    {
      id: 'ssrf-octal-ip',
      name: 'Octal IP bypass',
      difficulty: 'Medium',
      hint: 'Leading zeros mean octal to the URL parser, and the blocklist only knows dotted decimal.',
      how: 'Fetch http://0177.0.0.1:PORT/ssrf/internal/secret via /ssrf/octal-ip.',
    },
    {
      id: 'ssrf-zero-ip',
      name: '0.0.0.0 bypass',
      difficulty: 'Easy',
      hint: 'The blocklist never mentions 0.0.0.0, and this fetcher treats it as "this host".',
      how: 'Fetch http://0.0.0.0:PORT/ssrf/internal/secret via /ssrf/zero-ip.',
    },
    {
      id: 'ssrf-single-int',
      name: 'Integer IP bypass',
      difficulty: 'Medium',
      hint: 'An IPv4 address is just a 32-bit number. 127.0.0.1 written as one decimal integer slips past the string check.',
      how: 'Fetch http://2130706433:PORT/ssrf/internal/secret via /ssrf/single-int.',
    },
    {
      id: 'ssrf-metadata',
      name: 'Cloud metadata SSRF',
      difficulty: 'Medium',
      hint: 'Cloud VMs expose instance credentials at a link-local address the fetcher does not block.',
      how: 'Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/ via /ssrf/fetch-meta.',
    },
    {
      id: 'ssrf-file',
      name: 'file:// scheme SSRF',
      difficulty: 'Medium',
      hint: 'This fetcher allows an extra URL scheme that reads from the local disk.',
      how: 'Fetch file:///etc/passwd via /ssrf/fetch-file.',
    },
  ],
  router,
};
