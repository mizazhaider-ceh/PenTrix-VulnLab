'use strict';
// CORS Misconfiguration: six labs around broken cross-origin policies. Each
// lab exposes a vulnerable API endpoint (owned by its challenge file) plus a
// shared /cors/prove endpoint: give it an Origin, the server makes a real
// request to the vulnerable endpoint with that Origin (exactly like a browser
// would), inspects the response headers, and awards the flag only when the
// vulnerable header combination is genuinely demonstrated.
const express = require('express');
const { brief, esc, flagBox, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, fixSection, consoleMap } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const challenges = [
  require('./challenges/cors-reflect'),
  require('./challenges/cors-null'),
  require('./challenges/cors-regex'),
  require('./challenges/cors-wildcard-data'),
  require('./challenges/cors-subdomain'),
  require('./challenges/cors-expose-headers'),
];

const router = express.Router();

// Challenge page slug per vuln id (used by the index page links and /prove).
const PAGE_FOR = {
  'cors-reflect': 'reflect',
  'cors-null': 'null-origin',
  'cors-regex': 'regex',
  'cors-wildcard-data': 'wildcard',
  'cors-subdomain': 'subdomain',
  'cors-expose-headers': 'expose',
};

const BRIEF_HTML = `
<p><b>What is a CORS misconfiguration?</b> Cross-Origin Resource Sharing headers
tell the browser which websites may read a response. When the server reflects an
arbitrary <code>Origin</code>, trusts <code>null</code>, or uses a sloppy regex,
an attacker's page can make authenticated requests as the victim and read the
answers.</p>
<p><b>How to prove it in this module:</b> each lab has a vulnerable API endpoint
and a shared <code>/cors/prove</code> endpoint. Give <code>prove</code> an
Origin; the server makes a real request to the vulnerable endpoint with that
Origin, shows you the exact response headers, and awards the flag only when the
vulnerable combination is genuinely demonstrated. This mirrors what
<code>curl -H "Origin: ..."</code> shows you by hand.</p>`;

// GET /cors -> module index page.
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('cors', ordered, consoleMap('/cors/', PAGE_FOR));
  const cards = ordered.map(({ vuln: v }, i) => {
    const done = captured(req, 'cors', v.id);
    const slug = PAGE_FOR[v.id] || v.id;
    return `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="${esc(v.link)}">${esc(v.name)}</a>
        ${difficultyPill(v.difficulty)}
        ${done ? '<span class="captured">flag captured</span>' : ''}
      </h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/cors/${esc(slug)}">Open challenge</a></p>
    </article>`;
  }).join('\n');

  res.send(page('CORS Misconfiguration', `
    ${brief('Module briefing', BRIEF_HTML)}
    ${trackBanner(module.exports)}
    <h2>Challenges</h2>
    <p>Six flaws hide in the endpoints above. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape. The flag for each lab is awarded by the shared
    <code>/cors/prove</code> endpoint once you demonstrate the vulnerable
    Origin/header combination for real.</p>
    ${cards}
  ${fixSection('cors', challenges)}
`));
});

// ------------------------------------------------- prove-it endpoint
// Module-level route: shared by every challenge, belongs to no single one.
function parsedHost(origin) {
  try { return new URL(origin).hostname.toLowerCase(); } catch (e) { return ''; }
}

const PROVE = {
  'cors-reflect': {
    path: '/cors/api/profile',
    need: 'The endpoint must echo your Origin back in Access-Control-Allow-Origin and also send Access-Control-Allow-Credentials: true.',
    why: 'The reflected Origin plus credentials means any website can make authenticated requests and read the responses.',
    check: (h, origin) =>
      h['access-control-allow-origin'] === origin &&
      h['access-control-allow-credentials'] === 'true',
  },
  'cors-null': {
    path: '/cors/api/settings',
    need: 'The endpoint must trust one particular non-URL origin value, answering with that same value in Access-Control-Allow-Origin plus Access-Control-Allow-Credentials: true.',
    why: 'Trusting the null origin hands the data to sandboxed iframes, file:// pages, and redirect chains.',
    check: (h, origin) =>
      origin === 'null' &&
      h['access-control-allow-origin'] === 'null' &&
      h['access-control-allow-credentials'] === 'true',
  },
  'cors-regex': {
    path: '/cors/api/data',
    need: 'Beat the regex ^https://.*pentrix\\.lab (no subdomain boundary, no end anchor) with an origin that passes it but is NOT really under pentrix.lab.',
    why: 'The regex matches any https:// string merely containing pentrix.lab, so an origin on a completely different registrable domain is treated as trusted.',
    check: (h, origin) => {
      const host = parsedHost(origin);
      const actuallyOurs = host === 'pentrix.lab' || host.endsWith('.pentrix.lab');
      return h['access-control-allow-origin'] === origin &&
        h['access-control-allow-credentials'] === 'true' &&
        !actuallyOurs && host !== '';
    },
  },
  'cors-wildcard-data': {
    path: '/cors/api/users',
    showBody: true,
    need: 'The endpoint must send Access-Control-Allow-Origin: * while returning sensitive user data.',
    why: 'A wildcard origin on sensitive data means literally any website can read it.',
    check: (h, origin, body) =>
      h['access-control-allow-origin'] === '*' &&
      body.includes('alice@pentrix.lab'),
  },
  'cors-subdomain': {
    path: '/cors/api/partner',
    need: 'Pass the suffix check with any attacker-controlled subdomain of trusted.pentrix.lab (any invented label works).',
    why: 'The check is only a string suffix match with no allowlist, so any label you invent under .trusted.pentrix.lab is accepted.',
    check: (h, origin) => {
      const host = parsedHost(origin);
      return h['access-control-allow-origin'] === origin &&
        h['access-control-allow-credentials'] === 'true' &&
        host.endsWith('.trusted.pentrix.lab');
    },
  },
  'cors-expose-headers': {
    path: '/cors/api/token',
    need: 'The endpoint must list X-Admin-Token in Access-Control-Expose-Headers and actually send that header.',
    why: 'Exposing the header lets any website read the admin token with JavaScript after the victim visits.',
    check: (h) =>
      (h['access-control-expose-headers'] || '').toLowerCase().includes('x-admin-token') &&
      !!h['x-admin-token'],
  },
};

const SUGGESTED_ORIGIN = {
  'cors-reflect': 'https://example.com',
  'cors-null': '',
  'cors-regex': 'https://example.com',
  'cors-wildcard-data': 'https://example.com',
  'cors-subdomain': 'https://example.com',
  'cors-expose-headers': 'https://example.com',
};

router.get('/prove', async (req, res) => {
  const vuln = String(req.query.vuln || '');
  const def = PROVE[vuln];
  const meta = (module.exports.vulns || []).find((v) => v.id === vuln);
  if (!def || !meta) {
    return res.status(400).send(page('Prove it', `
      <h2>Prove it</h2>
      <p>Unknown vuln. Pick one from the <a href="/cors">CORS module page</a>.</p>
    `));
  }
  const origin = req.query.origin === undefined ? null : String(req.query.origin);
  if (origin === null) {
    return res.send(page('Prove it', `
      <h2>Prove: ${esc(meta.name)}</h2>
      <p>${esc(def.need)}</p>
      <form method="GET" action="/cors/prove">
        <input type="hidden" name="vuln" value="${esc(vuln)}" />
        <div class="clay-field">
          <label for="origin">Origin header to test</label>
          <input class="clay-input" type="text" id="origin" name="origin" size="50" value="${esc(SUGGESTED_ORIGIN[vuln])}" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Send the request</button>
      </form>
      <p class="note">The server will make a real request to
      <code>${esc(def.path)}</code> with your <code>Origin</code> and inspect the
      response headers, the same check a browser performs before allowing a
      cross-origin read.</p>
      <p><a href="/cors">Back to the module</a></p>
    `));
  }
  // Make a genuine server-side request to the vulnerable endpoint with the
  // attacker Origin, then inspect what headers WOULD be sent to a browser.
  const port = req.socket.localPort;
  const target = 'http://127.0.0.1:' + port + def.path;
  const headers = {};
  let body = '';
  let errMsg = '';
  try {
    const r = await fetch(target, {
      headers: { Origin: origin },
      signal: AbortSignal.timeout(5000),
    });
    body = await r.text();
    r.headers.forEach((v, k) => { headers[k] = v; });
  } catch (e) {
    errMsg = String((e && e.message) || e);
  }
  const headerLines = Object.keys(headers).sort().map((k) => k + ': ' + headers[k]).join('\n');
  const ok = !errMsg && def.check(headers, origin, body);
  let flagHtml = '';
  if (ok) {
    const flag = award(req, 'cors', vuln);
    flagHtml = `<hr /><p><b>Vulnerable combination confirmed.</b> ${esc(def.why)}</p>${flagBox(flag)}`;
  }
  res.send(page('Prove it', `
    <h2>Prove: ${esc(meta.name)}</h2>
    <p>Request: <code>GET ${esc(def.path)}</code> with
    <code>Origin: ${esc(origin)}</code></p>
    ${errMsg ? `<p class="note">Request failed: ${esc(errMsg)}</p>` : `
      <p>Response headers the server sent:</p>
      <pre><code>${esc(headerLines || '(none)')}</code></pre>
      ${def.showBody ? `<p>Response body (first 400 chars):</p><pre><code>${esc(body.slice(0, 400))}</code></pre>` : ''}
    `}
    ${ok ? flagHtml : `<p class="note"><b>Not vulnerable for this Origin.</b> ${esc(def.need)}</p>`}
    <p><a href="/cors/prove?vuln=${esc(vuln)}">Try another Origin</a> |
    <a href="/cors/${PAGE_FOR[vuln]}">Back to the challenge</a></p>
  `));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'cors',
  name: 'CORS Misconfiguration',
  tagline: 'Broken cross-origin policies that hand your data to evil.com.',
  description: 'Six CORS misconfiguration labs: a reflected Origin with credentials, a trusted null origin, a regex allowlist that matches strings instead of domain boundaries, a wildcard origin on sensitive user data, a subdomain suffix check with no allowlist, and a sensitive header leaked through Access-Control-Expose-Headers. Each lab is proven through a shared /cors/prove endpoint that inspects the real response headers for your Origin.',
  difficulty: 'Intermediate',
  track: 'Auth and Sessions',
  prerequisites: ['xss'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
