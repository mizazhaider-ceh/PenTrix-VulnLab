'use strict';
// SSRF module shared helpers: the server-side fetcher primitives used by the
// single-technique bypass challenges. Logic is identical to the module's
// original router.js; this file only exists so the per-challenge routers can
// share it after the challenge split.

const http = require('http');
const https = require('https');
const { esc, flagBox, fixPanel, page } = require('../../lib/page');
const { award } = require('../../lib/flags');

const SECRET_MARKER = 'SSRF-INTERNAL-9921';
const FETCH_TIMEOUT_MS = 5000;
const BLOCKED = ['127.0.0.1', 'localhost'];

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
          html += fixPanel(modId, vulnId);
        } else {
          html += `<p class="dim">Marker found, but the URL used a blocked host string, so this does not count as a bypass.</p>`;
        }
      } else if (opts.requireRedirect && !(opts.redirects > 0)) {
        html += `<p class="dim">Marker found, but no redirect was followed, so the redirect technique was not demonstrated.</p>`;
      } else {
        html += flagBox(award(req, modId, vulnId));
        html += fixPanel(modId, vulnId);
      }
    }
  }
  html += `<p><a href="/ssrf">&larr; Back to the SSRF module</a></p>`;
  return page(title, html);
}

function blockedPage(title, url, msg) {
  return page(title, `<h2>${esc(title)}</h2>
    <p class="dim">Fetched: <code>${esc(url)}</code></p>
    <div class="error">${esc(msg)}</div>
    <p><a href="/ssrf">&larr; Back to the SSRF module</a></p>`);
}

// Runs a fetcher behind a naive check: cfg.check(url) returns an error
// message or null, cfg.fetch(url) does the actual server-side request.
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

// Naive substring blocklist check on the raw URL string: the check the
// single-technique bypass challenges are meant to defeat.
const rawHostBlock = (url) =>
  BLOCKED.some((s) => url.includes(s)) ? 'Blocked: URL contains a forbidden host.' : null;

// Simulated cloud instance metadata document. The credentials contain the
// secret marker so a successful metadata read awards the flag.
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

module.exports = { fetchBody, guardedFetch, rawHostBlock, metadataDoc, resultPage };
