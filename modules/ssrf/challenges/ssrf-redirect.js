'use strict';
// Open-redirect SSRF: /ssrf/fetch3 follows redirects without re-checking the
// blocklist, so bouncing through the open redirect at /ssrf/jump smuggles the
// request to a blocked host. Presented as "HopFetch", a small link-expander
// service that shows where a URL really lands.
const express = require('express');
const http = require('http');
const https = require('https');
const { award } = require('../../../lib/flags');
const {
  appShell, brief, esc, fixPanel, flagBox, hintLadder, page,
} = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'ssrf-redirect',
  name: 'Open-redirect SSRF',
  difficulty: 'Medium',
  hint: 'The blocklist only sees the first URL; the fetcher follows 302 redirects without re-checking.',
  hints: ["The blocklist checks the URL you submit. But what happens after the server follows a redirect?", "The check runs on the initial URL only. Point the fetcher at a URL that 302-redirects to the internal target.", "Point the fetcher at the app's own redirect endpoint so the submitted URL passes the check; the 302 response then pulls the fetcher to the internal target without a second check."],
  tools: "C",
  how: 'Fetch http://localhost:PORT/ssrf/jump?to=<internal secret URL> via /ssrf/fetch3 so the redirect lands on the blocked host.',
  link: '/ssrf#ssrf-redirect',
  start: 'curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}\\n" "http://localhost:3000/ssrf/jump?to=/ssrf/internal/status"\n'
    + 'curl -s "http://localhost:3000/ssrf/fetch3?url=http://localhost:3000/ssrf/jump?to=/ssrf/internal/status"',
};

const APP_NAME = 'HopFetch';
const APP_NAV = ['Link Expander', 'Go Links', 'History'];
const APP_CRUMB = 'Redirect lab / Open-redirect SSRF';

const SECRET_MARKER = 'SSRF-INTERNAL-9921';
const FETCH_TIMEOUT_MS = 5000;
const REDIRECT_BLOCKED = ['127.0.0.1'];

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

// Clay-styled URL form, submitted as a GET so the URL shows up in the address bar.
function fetchForm(url) {
  return `<form method="get" action="/ssrf/fetch3" class="clay-card">
    <div class="clay-field">
      <label for="fetch-url">URL to expand</label>
      <input class="clay-input" id="fetch-url" name="url" value="${esc(url)}" size="60" autocomplete="off" spellcheck="false" placeholder="https://example.com/some/link" />
    </div>
    <button class="clay-btn clay-btn-primary" type="submit">Follow redirects</button>
  </form>`;
}

// Renders the fetch-result block. Same logic as the original router: the flag
// is awarded only when the secret marker is present AND at least one redirect
// was followed, which proves the redirect technique was demonstrated.
function fetchResult(req, url, body, err, redirects) {
  let html = `<section class="clay-card"><h2>SSRF Fetch 3</h2>`;
  html += `<p class="dim">Fetched: <code>${esc(url)}</code></p>`;
  if (err) {
    html += `<div class="error">Fetch failed: <code>${esc(err.message)}</code></div>`;
  } else {
    html += `<h3>Response body</h3><pre class="resp">${esc(body)}</pre>`;
    if (body.includes(SECRET_MARKER)) {
      if (!(redirects > 0)) {
        html += `<p class="dim">Marker found, but no redirect was followed, so the redirect technique was not demonstrated.</p>`;
      } else {
        html += flagBox(award(req, 'ssrf', 'ssrf-redirect'));
        html += fixPanel('ssrf', 'ssrf-redirect');
      }
    }
  }
  html += `</section>`;
  return html;
}

function challengePage(req, url, body, err, redirects) {
  return page('SSRF Fetch 3', appShell(APP_NAME, `
    ${brief('Redirect follower', 'HopFetch shows you where a link really lands. Paste any URL and the service fetches it server-side, following up to 5 redirects, then displays the final response. Our own go-links (<code>/ssrf/jump?to=...</code>) are expanded the same way.')}
    ${fetchForm(url === '(none)' ? '' : url)}
    ${fetchResult(req, url, body, err, redirects)}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>
  `, { crumb: APP_CRUMB, nav: APP_NAV }));
}

function blockedPage(url) {
  return page('SSRF Fetch 3', appShell(APP_NAME, `
    <section class="clay-card">
      <h2>SSRF Fetch 3 (redirect follower)</h2>
      <p class="dim">Fetched: <code>${esc(url)}</code></p>
      <div class="error">Blocked: URL contains a forbidden host.</div>
    </section>
    ${fetchForm(url)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>
  `, { crumb: APP_CRUMB, nav: APP_NAV }));
}

// Open redirect used by the redirect lab. The destination is fully
// attacker-controlled, including internal hosts.
router.get('/jump', (req, res) => {
  const to = String(req.query.to || '/ssrf/internal/status');
  // VULN: open redirect, any destination is allowed.
  res.redirect(302, to);
});

// GET /ssrf/fetch3 -> redirect-following fetcher.
router.get('/fetch3', async (req, res) => {
  const url = String(req.query.url || '');

  // VULN: the blocklist is checked against the initial URL only, and only
  // against its parsed hostname. Redirect targets are followed without any
  // re-validation, so bouncing through the open redirect at /ssrf/jump
  // smuggles the request to a blocked host.
  let initialHost = '';
  try { initialHost = new URL(url).hostname; } catch (e) { /* invalid URL; reported below */ }
  if (REDIRECT_BLOCKED.includes(initialHost)) {
    return res.status(403).send(blockedPage(url));
  }
  const done = (body, err, redirects) => res.send(challengePage(req, url || '(none)', body, err, redirects));
  if (!url) return done('', new Error('Provide a ?url= parameter'), 0);
  try {
    const { body, redirects } = await fetchBodyFollow(url);
    done(body, null, redirects);
  } catch (e) {
    done('', e, 0);
  }
});

module.exports = { vuln, router };
