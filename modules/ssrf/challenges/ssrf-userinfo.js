'use strict';
// Userinfo bypass: /ssrf/userinfo only fetches URLs that mention the partner
// domain, but the check inspects the raw URL string instead of parsing the
// real hostname, so http://pentrix.lab@127.0.0.1/ passes the check while the
// request actually goes to loopback. Presented as "VendorPulse", a small
// partner status monitor that fetches approved partner URLs server-side.
const express = require('express');
const http = require('http');
const https = require('https');
const { award } = require('../../../lib/flags');
const {
  appShell, brief, esc, fixPanel, flagBox, hintLadder, page,
} = require('../../../lib/page');

const router = express.Router();

const vuln = {
  id: 'ssrf-userinfo',
  name: 'Userinfo bypass',
  difficulty: 'Easy',
  hint: 'The allowlist looks for the trusted string anywhere in the URL. What comes before @ is userinfo, not the host.',
  hints: ["In Burp Proxy, browse the userinfo page and submit any partner URL; send the intercepted request to Repeater so you can edit the url parameter freely.", "In Repeater, try a URL with no trusted string and read the 403. Then try one where the trusted string sits anywhere in the URL: it passes.", "In Repeater, remember what @ means in a URL: everything before it is userinfo, so the parser connects to the host after it. Put the trusted name before @ and the loopback target after it."],
  tools: "BZ, C",
  how: 'In Burp Repeater, GET /ssrf/userinfo with the url parameter set to a URL whose userinfo carries the trusted domain while the real host is the loopback internal secret path.',
  link: '/ssrf#ssrf-userinfo',
  start: 'Browse to http://localhost:3000/ssrf/userinfo through Burp Proxy, submit any partner URL in the form, and send the intercepted request to Repeater. Watch the 403 for URLs without the trusted string, then experiment with the url parameter in Repeater; the flag appears on the page when the check is bypassed.',
};

const APP_NAME = 'VendorPulse';
const APP_NAV = ['Partners', 'Status Board', 'Incidents'];
const APP_CRUMB = 'Integrations / Userinfo bypass';

const SECRET_MARKER = 'SSRF-INTERNAL-9921';
const FETCH_TIMEOUT_MS = 5000;

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

// Clay-styled URL form, submitted as a GET so the URL shows up in the address bar.
function fetchForm(url) {
  return `<form method="get" action="/ssrf/userinfo" class="clay-card">
    <div class="clay-field">
      <label for="fetch-url">Partner URL to fetch</label>
      <input class="clay-input" id="fetch-url" name="url" value="${esc(url)}" size="60" autocomplete="off" spellcheck="false" placeholder="http://pentrix.lab/status" />
    </div>
    <button class="clay-btn clay-btn-primary" type="submit">Fetch status</button>
  </form>`;
}

// Renders the fetch-result block. Same logic as the original router: the flag
// is awarded only when the internal secret marker comes back, which proves
// the allowlist check was bypassed.
function fetchResult(req, url, body, err) {
  let html = `<section class="clay-card"><h2>SSRF Userinfo</h2>`;
  html += `<p class="dim">Fetched: <code>${esc(url)}</code></p>`;
  if (err) {
    html += `<div class="error">Fetch failed: <code>${esc(err.message)}</code></div>`;
  } else {
    html += `<h3>Response body</h3><pre class="resp">${esc(body)}</pre>`;
    if (body.includes(SECRET_MARKER)) {
      html += flagBox(award(req, 'ssrf', 'ssrf-userinfo'));
      html += fixPanel('ssrf', 'ssrf-userinfo');
    }
  }
  html += `</section>`;
  return html;
}

function challengePage(req, url, body, err) {
  return page('SSRF Userinfo', appShell(APP_NAME, `
    ${brief('Partner status monitor', 'VendorPulse fetches the status pages of approved partners and shows the raw response, so the support team can see exactly what a partner endpoint returns. Only <code>pentrix.lab</code> URLs are accepted.')}
    ${fetchForm(url === '(none)' ? '' : url)}
    ${fetchResult(req, url, body, err)}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>
  `, { crumb: APP_CRUMB, nav: APP_NAV }));
}

function blockedPage(url, msg) {
  return page('SSRF Userinfo', appShell(APP_NAME, `
    <section class="clay-card">
      <h2>SSRF Userinfo</h2>
      <p class="dim">Fetched: <code>${esc(url)}</code></p>
      <div class="error">${esc(msg)}</div>
    </section>
    ${fetchForm(url)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>
  `, { crumb: APP_CRUMB, nav: APP_NAV }));
}

// GET /ssrf/userinfo -> allowlisted fetcher.
router.get('/userinfo', async (req, res) => {
  const url = String(req.query.url || '');
  // VULN: the "allowlist" inspects the raw URL string for a trusted domain
  // instead of parsing the real hostname, so userinfo smuggling
  // (http://pentrix.lab@127.0.0.1/) passes while the request goes to 127.0.0.1.
  const problem = url.includes('pentrix.lab') ? null : 'Blocked: only pentrix.lab URLs may be fetched.';
  if (problem) return res.status(403).send(blockedPage(url, problem));
  if (!url) {
    return res.send(challengePage(req, '(none)', '', new Error('Provide a ?url= parameter')));
  }
  try {
    const body = await fetchBody(url);
    res.send(challengePage(req, url, body, null));
  } catch (e) {
    res.send(challengePage(req, url, '', e));
  }
});

module.exports = { vuln, router };
