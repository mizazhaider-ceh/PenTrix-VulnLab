// PenTrix VulnLab module: CORS Misconfiguration (cors)
// Six labs around broken cross-origin policies. Each lab exposes a vulnerable
// API endpoint plus a /cors/prove endpoint: give it an Origin, the server makes
// a real request to the vulnerable endpoint with that Origin (exactly like a
// browser would), inspects the response headers, and awards the flag only when
// the vulnerable header combination is genuinely demonstrated.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// Leaked cross-origin by the expose-headers lab. Random per boot, only ever
// revealed through the vulnerable endpoint.
const ADMIN_TOKEN = crypto.randomBytes(16).toString('hex');

// Challenge page slug per vuln id (used by the index page links).
const PAGE_FOR = {
  'cors-reflect': 'reflect',
  'cors-null': 'null-origin',
  'cors-regex': 'regex',
  'cors-wildcard-data': 'wildcard',
  'cors-subdomain': 'subdomain',
  'cors-expose-headers': 'expose',
};

// ------------------------------------------------------- vulnerable endpoints
router.get('/api/profile', (req, res) => {
  const origin = req.headers.origin;
  // VULN: any Origin is reflected with credentials allowed. No allowlist at all.
  if (origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  const alice = getDb()
    .prepare('SELECT username, email, secret FROM users WHERE username = ?')
    .get('alice');
  res.json({ user: alice });
});

router.get('/api/settings', (req, res) => {
  const origin = req.headers.origin;
  // VULN: Origin "null" (sandboxed iframes, file:// pages, redirects) is trusted
  // with credentials, so any null-origin context can read this data.
  if (origin === 'null') {
    res.set('Access-Control-Allow-Origin', 'null');
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ theme: 'dark', twoFactor: true, recoveryEmail: 'alice@pentrix.lab' });
});

router.get('/api/data', (req, res) => {
  const origin = req.headers.origin || '';
  // VULN: naive regex allowlist with no subdomain boundary and no end anchor.
  // The developer forgot the dot before "pentrix" and the "$" at the end, so any
  // https:// origin merely containing "pentrix.lab" passes, including
  // https://pentrix.lab.evil.com.
  if (/^https:\/\/.*pentrix\.lab/.test(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ report: 'weekly security metrics', internal: true });
});

router.get('/api/users', (req, res) => {
  // VULN: wildcard origin on an endpoint returning sensitive data. Any website
  // can read every user's email address.
  res.set('Access-Control-Allow-Origin', '*');
  const users = getDb()
    .prepare('SELECT username, email FROM users ORDER BY username')
    .all();
  res.json({ users });
});

router.get('/api/partner', (req, res) => {
  const origin = req.headers.origin || '';
  let host = '';
  try { host = new URL(origin).hostname; } catch (e) { host = ''; }
  // VULN: suffix-only subdomain check with no allowlist. Any subdomain of
  // trusted.pentrix.lab passes, including attacker-controlled ones.
  if (host.endsWith('.trusted.pentrix.lab')) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ partner: true, discount: '20%' });
});

router.get('/api/token', (req, res) => {
  // VULN: a sensitive response header is exposed cross-origin, so any site the
  // victim visits can read it with JavaScript.
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Expose-Headers', 'X-Admin-Token');
  res.set('X-Admin-Token', ADMIN_TOKEN);
  res.json({ ok: true, message: 'session valid' });
});

// ------------------------------------------------- prove-it endpoint
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
    need: 'Send Origin: null. The endpoint must answer with Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true.',
    why: 'Trusting the null origin hands the data to sandboxed iframes, file:// pages, and redirect chains.',
    check: (h, origin) =>
      origin === 'null' &&
      h['access-control-allow-origin'] === 'null' &&
      h['access-control-allow-credentials'] === 'true',
  },
  'cors-regex': {
    path: '/cors/api/data',
    need: 'Beat the regex ^https://.*pentrix\\.lab (no subdomain boundary, no end anchor) with an origin that passes it but is NOT really under pentrix.lab.',
    why: 'The regex matches any https:// string merely containing pentrix.lab, so https://pentrix.lab.evil.com is treated as trusted.',
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
    need: 'Pass the suffix check with an attacker-controlled subdomain of trusted.pentrix.lab.',
    why: 'The check is only a string suffix match with no allowlist, so evil.trusted.pentrix.lab is accepted.',
    check: (h, origin) => {
      const host = parsedHost(origin);
      return h['access-control-allow-origin'] === origin &&
        h['access-control-allow-credentials'] === 'true' &&
        host.includes('evil');
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
  'cors-reflect': 'https://evil.com',
  'cors-null': 'null',
  'cors-regex': 'https://pentrix.lab.evil.com',
  'cors-wildcard-data': 'https://evil.com',
  'cors-subdomain': 'https://evil.trusted.pentrix.lab',
  'cors-expose-headers': 'https://evil.com',
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
        <input type="text" name="origin" size="50" value="${esc(SUGGESTED_ORIGIN[vuln])}" />
        <button type="submit">Send the request</button>
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

// ------------------------------------------------------- challenge pages
function challengePage(slug, vulnId, title, endpoint, curlExample, proveNote) {
  router.get('/' + slug, (req, res) => {
    const meta = module.exports.vulns.find((v) => v.id === vulnId);
    res.send(page(title, `
      <h2>${esc(title)}</h2>
      ${hintBox(meta.hint)}
      <p>Vulnerable endpoint: <a href="${endpoint}"><code>${esc(endpoint)}</code></a></p>
      <p>Try it raw:</p>
      <pre><code>${esc(curlExample)}</code></pre>
      <p>${proveNote}</p>
      <p><a href="/cors/prove?vuln=${vulnId}&origin=${encodeURIComponent(SUGGESTED_ORIGIN[vulnId])}"><b>Prove it with the suggested Origin</b></a>
      or <a href="/cors/prove?vuln=${vulnId}">choose your own Origin</a>.</p>
      <p><a href="/cors">Back to the module</a></p>
    `));
  });
}

challengePage('reflect', 'cors-reflect', 'Reflected Origin with Credentials',
  '/cors/api/profile',
  'curl -si -H "Origin: https://evil.com" http://localhost:PORT/cors/api/profile',
  'The endpoint reflects <b>any</b> Origin and adds <code>Access-Control-Allow-Credentials: true</code>. Prove the combination with the suggested origin.');

challengePage('null-origin', 'cors-null', 'Null Origin Trusted',
  '/cors/api/settings',
  'curl -si -H "Origin: null" http://localhost:PORT/cors/api/settings',
  'Only <code>Origin: null</code> is trusted here (with credentials). Prove it with exactly that origin.');

challengePage('regex', 'cors-regex', 'Regex Allowlist Bypass',
  '/cors/api/data',
  'curl -si -H "Origin: https://pentrix.lab.evil.com" http://localhost:PORT/cors/api/data',
  'The allowlist regex is <code>^https://.*pentrix\\.lab</code> (no subdomain boundary, no end anchor). Find an origin that passes it without being under pentrix.lab.');

challengePage('wildcard', 'cors-wildcard-data', 'Wildcard on Sensitive Data',
  '/cors/api/users',
  'curl -si http://localhost:PORT/cors/api/users',
  'The endpoint answers <code>Access-Control-Allow-Origin: *</code> while returning every user\'s email address.');

challengePage('subdomain', 'cors-subdomain', 'Subdomain Suffix Check',
  '/cors/api/partner',
  'curl -si -H "Origin: https://evil.trusted.pentrix.lab" http://localhost:PORT/cors/api/partner',
  'The check is <code>hostname.endsWith(".trusted.pentrix.lab")</code> with no allowlist behind it.');

challengePage('expose', 'cors-expose-headers', 'Exposed Admin Token Header',
  '/cors/api/token',
  'curl -si http://localhost:PORT/cors/api/token',
  'The response carries <code>X-Admin-Token</code> and exposes it via <code>Access-Control-Expose-Headers</code>, so any site can read it.');

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

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const done = captured(req, 'cors', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/cors/${PAGE_FOR[v.id] || v.id}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('CORS Misconfiguration', `
    ${brief('Module briefing', BRIEF_HTML)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

module.exports = {
  id: 'cors',
  name: 'CORS Misconfiguration',
  tagline: 'Broken cross-origin policies that hand your data to evil.com.',
  description: 'Six CORS misconfiguration labs: a reflected Origin with credentials, a trusted null origin, a regex allowlist beaten by pentrix.lab.evil.com, a wildcard origin on sensitive user data, a subdomain suffix check with no allowlist, and a sensitive header leaked through Access-Control-Expose-Headers. Each lab is proven through a shared /cors/prove endpoint that inspects the real response headers for your Origin.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'cors-reflect',
      name: 'Reflected Origin with Credentials',
      difficulty: 'Medium',
      hint: 'The endpoint echoes any Origin back and adds Access-Control-Allow-Credentials: true. There is no allowlist at all.',
      how: 'Prove it: /cors/prove?vuln=cors-reflect&origin=https://evil.com',
    },
    {
      id: 'cors-null',
      name: 'Null Origin Trusted',
      difficulty: 'Medium',
      hint: 'Only one origin value is trusted here, and it is the one sandboxed iframes and file:// pages send.',
      how: 'Prove it: /cors/prove?vuln=cors-null&origin=null',
    },
    {
      id: 'cors-regex',
      name: 'Regex Allowlist Bypass',
      difficulty: 'Medium',
      hint: 'The regex is ^https://.*pentrix\\.lab with no subdomain boundary and no end anchor. It matches strings, not domain boundaries.',
      how: 'Prove it with origin https://pentrix.lab.evil.com, which passes the regex but is not under pentrix.lab.',
    },
    {
      id: 'cors-wildcard-data',
      name: 'Wildcard on Sensitive Data',
      difficulty: 'Easy',
      hint: 'Access-Control-Allow-Origin: * on an endpoint that returns every user\'s email address.',
      how: 'Prove it: /cors/prove?vuln=cors-wildcard-data&origin=https://evil.com',
    },
    {
      id: 'cors-subdomain',
      name: 'Subdomain Suffix Check',
      difficulty: 'Medium',
      hint: 'The check is hostname.endsWith(".trusted.pentrix.lab") with no allowlist of real subdomains behind it.',
      how: 'Prove it with origin https://evil.trusted.pentrix.lab.',
    },
    {
      id: 'cors-expose-headers',
      name: 'Exposed Admin Token Header',
      difficulty: 'Easy',
      hint: 'The response carries X-Admin-Token and the endpoint lists it in Access-Control-Expose-Headers.',
      how: 'Prove it: /cors/prove?vuln=cors-expose-headers&origin=https://evil.com',
    },
  ],
  router,
};
