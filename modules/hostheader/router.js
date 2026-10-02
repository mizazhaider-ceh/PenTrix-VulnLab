// PenTrix VulnLab module: Host Header Injection (hostheader)
// Six labs around one trust mistake: building links, cache entries, and
// server-side request URLs out of the Host header (and its proxy variants
// X-Forwarded-Host and X-Host-Override) without validation. Includes a password
// reset poisoner with an attacker collector, a cache poisoned by path-only keys,
// a server-side fetch driven to a loopback-only internal agent, and an absolute
// login-continue URL built from Host.
const express = require('express');
const crypto = require('crypto');
const http = require('http');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// Challenge page slug per vuln id (used by the index page links).
const PAGE_FOR = {
  'host-reset-poison': 'forgot',
  'host-cache-poison': 'app',
  'host-ssrf': 'status',
  'host-xforwarded': 'forgot-xfwd',
  'host-override': 'forgot-override',
  'host-abs-url': 'login',
};

function tokenDb() {
  const db = getDb();
  db.exec(`CREATE TABLE IF NOT EXISTS hostheader_tokens (
    token TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    issued_host TEXT NOT NULL,
    vuln TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  return db;
}

function bareHost(h) {
  return String(h || '').split(':')[0].trim().toLowerCase();
}
// The lab app is served on localhost. Any other Host value is attacker-controlled.
function isLocalHost(h) {
  const n = bareHost(h);
  return n === '' || n === 'localhost' || n === '127.0.0.1' || n === '::1';
}

const BRIEF_HTML = `
<p><b>What is host header injection?</b> Many apps build absolute links, emails,
and even server-side request URLs from the <code>Host</code> header, trusting a
value the client fully controls. Behind proxies, the equivalent headers are
<code>X-Forwarded-Host</code> and vendor variants like
<code>X-Host-Override</code>.</p>
<p><b>The labs below:</b> poison a password-reset email so the victim's token
goes to your collector, poison a path-keyed cache, drive a server-side fetch at
a loopback-only internal agent, and bend an absolute login URL to your domain.</p>
<p><b>How to attack:</b> <code>curl -H "Host: evil.com" ...</code> The in-lab
attacker collector is <code>/hostheader/evil-collect?token=...</code>. A flag is
awarded only when the poisoned value genuinely flows through the vulnerable
code path.</p>`;

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const done = captured(req, 'hostheader', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/hostheader/${PAGE_FOR[v.id] || v.id}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('Host Header Injection', `
    ${brief('Module briefing', BRIEF_HTML)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

// --------------------------------- v1/v4/v5: poisoned password reset emails
function forgotPages(path, vulnId, headerLabel, getHost) {
  router.get(path, (req, res) => {
    res.send(page('Forgot password', `
      <h2>Forgot your password?</h2>
      <p>Enter your email and we will send a reset link.</p>
      <form method="POST" action="/hostheader${path}">
        <input type="email" name="email" placeholder="alice@pentrix.lab" required size="30" />
        <button type="submit">Send reset link</button>
      </form>
      <p class="note">The reset link is built from the <code>${headerLabel}</code>
      request header. The "sent" email is shown on the next page so you can play
      both attacker and victim.</p>
      <p><a href="/hostheader">Back to the module</a></p>
    `));
  });

  router.post(path, (req, res) => {
    const email = String(req.body.email || '').slice(0, 120);
    if (!email.includes('@')) {
      return res.status(400).send(page('Forgot password', `
        <p>A valid email address is required.</p>
        <p><a href="/hostheader${path}">Back</a></p>
      `));
    }
    const host = String(getHost(req));
    const token = crypto.randomBytes(16).toString('hex');
    tokenDb()
      .prepare('INSERT INTO hostheader_tokens (token, email, issued_host, vuln) VALUES (?,?,?,?)')
      .run(token, email, host, vulnId);
    // VULN: the password-reset link is built from an untrusted Host-style header.
    const link = 'http://' + host + '/hostheader/reset?token=' + token;
    res.send(page('Reset link sent', `
      <h2>Email sent (lab view)</h2>
      <p>In a real app this would be emailed. The lab shows it so you can play
      both attacker and victim:</p>
      <div class="comment">
        <p>Hi ${esc(email)},</p>
        <p>Reset your password here:<br /><a href="${esc(link)}">${esc(link)}</a></p>
      </div>
      <p class="note">Poison the <code>${headerLabel}</code> header and the link
      above points at the attacker's domain while carrying a valid token. When the
      victim "clicks" it, the token lands in the attacker's collector at
      <code>/hostheader/evil-collect?token=...</code>.</p>
      <p><a href="/hostheader${path}">Send another</a> | <a href="/hostheader">Back to the module</a></p>
    `));
  });
}

forgotPages('/forgot', 'host-reset-poison', 'Host',
  (req) => req.headers.host || '');
forgotPages('/forgot-xfwd', 'host-xforwarded', 'X-Forwarded-Host',
  (req) => req.headers['x-forwarded-host'] || req.headers.host || '');
forgotPages('/forgot-override', 'host-override', 'X-Host-Override',
  (req) => req.headers['x-host-override'] || req.headers.host || '');

// The real reset endpoint the emailed link points at (one-time token).
router.get('/reset', (req, res) => {
  const token = String(req.query.token || '');
  const row = token
    ? tokenDb().prepare('SELECT * FROM hostheader_tokens WHERE token = ?').get(token)
    : undefined;
  if (!row) {
    return res.status(400).send(page('Reset password', `
      <p>Invalid or expired token.</p>
      <p><a href="/hostheader/forgot">Request a new link</a></p>
    `));
  }
  tokenDb().prepare('DELETE FROM hostheader_tokens WHERE token = ?').run(token);
  res.send(page('Reset password', `
    <h2>Password reset</h2>
    <p>Password for <b>${esc(row.email)}</b> has been reset
    (demo: nothing actually changed).</p>
    <p class="note">This is where the victim lands after clicking the link in the
    email. If the link pointed at the attacker's domain, the token went to the
    collector instead.</p>
  `));
});

// Attacker collector: awards only for tokens issued under a poisoned host.
router.get('/evil-collect', (req, res) => {
  const token = String(req.query.token || '');
  const row = token
    ? tokenDb().prepare('SELECT * FROM hostheader_tokens WHERE token = ?').get(token)
    : undefined;
  if (row && !isLocalHost(row.issued_host)) {
    const flag = award(req, 'hostheader', row.vuln);
    return res.send(page('Attacker collector', `
      <h2>Token captured</h2>
      <p>A password-reset token for <b>${esc(row.email)}</b> was just harvested.
      It was issued while the app believed its own host was
      <code>${esc(row.issued_host)}</code>, so the reset email pointed the victim
      at the attacker's domain.</p>
      <pre><code>${esc(token)}</code></pre>
      ${flagBox(flag)}
      <p><a href="/hostheader">Back to the module</a></p>
    `));
  }
  res.send(page('Attacker collector', `
    <h2>Evil collector</h2>
    <p>This page belongs to the attacker. It awards the flag when a reset token
    that was issued under a <b>poisoned</b> host arrives here as
    <code>?token=...</code>.</p>
    ${row
      ? '<p class="note">That token was issued for the legitimate host, so no flag: poison the Host header (or X-Forwarded-Host / X-Host-Override on their own pages) when requesting the reset email, then bring the token here.</p>'
      : '<p>No token received yet.</p>'}
    <p><a href="/hostheader">Back to the module</a></p>
  `));
});

// ------------------------------------------------- v2: cache poisoning (Hard)
const pageCache = {}; // naive cache: keyed by path only, never by host.

router.get('/app', (req, res) => {
  const key = req.path;
  const curHost = req.headers.host || '';
  const entry = pageCache[key];
  if (entry) {
    // VULN: the cached page is served to everyone regardless of Host, so a page
    // rendered under the attacker's Host is later served to legitimate users.
    let flagHtml = '';
    if (isLocalHost(curHost) && !isLocalHost(entry.host)) {
      const flag = award(req, 'hostheader', 'host-cache-poison');
      flagHtml = `<div class="comment"><p><b>Cache poison demonstrated:</b> you
        asked with the normal host <code>${esc(curHost)}</code> but received the
        page cached under <code>${esc(entry.host)}</code>. Every visitor now gets
        the attacker's links.</p>${flagBox(flag)}</div>`;
    }
    return res.send(page('Reset portal (cached)', entry.html + flagHtml));
  }
  // VULN: absolute portal link built from the Host header, then cached by path only.
  const host = curHost;
  const html = `
    <h2>Password reset portal</h2>
    <p>Start a reset here:<br />
    <a href="http://${esc(host)}/hostheader/forgot">http://${esc(host)}/hostheader/forgot</a></p>
    <p class="note">This page is cached for performance. The cache key is the path
    only: the Host header is not part of it.</p>
    <p><a href="/hostheader/app/clear">Clear the cache</a> | <a href="/hostheader">Back to the module</a></p>`;
  pageCache[key] = { html, host };
  res.send(page('Reset portal', html));
});

router.get('/app/clear', (req, res) => {
  delete pageCache['/app'];
  res.send(page('Cache cleared', `
    <p>Cache cleared.</p>
    <p><a href="/hostheader/app">Reload the portal</a></p>
  `));
});

// ------------------------------------------- v3: Host-header SSRF (Medium)
// Internal monitoring agent. It binds 127.0.0.1 only, so in the lab story it is
// reachable solely by the server itself, never directly from the internet.
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

// The same path on the public app returns only boring public metrics.
router.get('/internal/metrics', (req, res) => {
  res.json({ service: 'pentrix-web', status: 'ok', version: '1.0-lab' });
});

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
      URL on your behalf and handed you its secrets.</p>${flagBox(flag)}`;
  }
  res.send(page('Service health check', `
    <h2>Service health check</h2>
    <p>The server fetches its own metrics page to check health. The fetch target
    is built from the <code>Host</code> header:</p>
    <pre><code>GET ${esc(target)}</code></pre>
    ${errMsg
      ? `<p class="note">Fetch failed: ${esc(errMsg)}</p>`
      : `<pre><code>${esc(body.slice(0, 2000))}</code></pre>`}
    <p class="note">An internal monitoring agent listens on
    <code>127.0.0.1:${INTERNAL_PORT}</code> (loopback only)
    ${internalUp ? '(agent is up)' : '(agent failed to start - see server log)'}. Can you make the
    server's fetch reach it?</p>
    ${flagHtml}
    <p><a href="/hostheader">Back to the module</a></p>
  `));
});

// -------------------------------------- v6: absolute login continue URL
router.get('/login', (req, res) => {
  const host = req.headers.host || '';
  const cont = String(req.query.continue || '/hostheader/dashboard');
  // VULN: the post-login "continue" destination is rendered as an absolute URL
  // built from the Host header.
  const absolute = 'http://' + host + cont;
  res.send(page('Login', `
    <h2>Login</h2>
    <p>After login you will continue to:<br /><code>${esc(absolute)}</code></p>
    <form method="POST" action="/hostheader/login">
      <input type="text" name="username" placeholder="alice" required /><br /><br />
      <input type="password" name="password" placeholder="alice123" required /><br /><br />
      <input type="hidden" name="continue" value="${esc(cont)}" />
      <button type="submit">Log in</button>
    </form>
    <p class="note">Demo accounts: alice/alice123, bob/bob123. Try logging in with
    a poisoned <code>Host</code> header and watch where the 302 goes
    (<code>curl -i</code>).</p>
    <p><a href="/hostheader">Back to the module</a></p>
  `));
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  const cont = String(req.body.continue || '/hostheader/dashboard');
  const user = getDb()
    .prepare('SELECT * FROM users WHERE username = ? AND password = ?')
    .get(username, password);
  if (!user) {
    return res.status(401).send(page('Login', `
      <p>Bad credentials.</p>
      <p><a href="/hostheader/login">Back</a></p>
    `));
  }
  const host = req.headers.host || '';
  // VULN: the post-login redirect is an absolute URL built from the Host header.
  const target = 'http://' + host + (cont.startsWith('/') ? cont : '/' + cont);
  let flagHtml = '';
  if (!isLocalHost(host)) {
    const flag = award(req, 'hostheader', 'host-abs-url');
    flagHtml = `<hr /><p>Login succeeded, and the 302 below points at the
      attacker-controlled host from the poisoned header.</p>${flagBox(flag)}`;
  }
  res.status(302).set('Location', target).send(page('Logged in', `
    <h2>Welcome, ${esc(user.username)}</h2>
    <p>Continuing to <a href="${esc(target)}">${esc(target)}</a> ...</p>
    ${flagHtml}
    <p><a href="/hostheader">Back to the module</a></p>
  `));
});

module.exports = {
  id: 'hostheader',
  name: 'Host Header Injection',
  tagline: 'Poison the Host header and watch links, caches, and server-side fetches obey it.',
  description: 'Six host-header injection labs: password-reset poisoning through Host, X-Forwarded-Host, and X-Host-Override with an attacker token collector, cache poisoning via path-only cache keys, server-side request forgery that reaches a loopback-only internal agent, and an absolute login continue URL built from the Host header.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'host-reset-poison',
      name: 'Password Reset Poisoning',
      difficulty: 'Medium',
      hint: 'The reset email builds its link from the Host header. Make the victim\'s token land in your collector.',
      how: 'POST /hostheader/forgot with Host: evil.com, then bring the token to /hostheader/evil-collect?token=...',
    },
    {
      id: 'host-cache-poison',
      name: 'Cache Poisoning via Host',
      difficulty: 'Hard',
      hint: 'The portal page is cached by path only, not by host. Poison it first, then visit as a normal user.',
      how: 'GET /hostheader/app with Host: evil.com to poison the cache, then GET it again with the normal host.',
    },
    {
      id: 'host-ssrf',
      name: 'SSRF via Host Header',
      difficulty: 'Medium',
      hint: 'The health check fetches http://<Host>/hostheader/internal/metrics server-side. A loopback-only agent on 127.0.0.1:13919 holds secrets.',
      how: 'GET /hostheader/status with Host: 127.0.0.1:13919 so the server fetches the internal agent for you.',
    },
    {
      id: 'host-xforwarded',
      name: 'X-Forwarded-Host Poisoning',
      difficulty: 'Easy',
      hint: 'Behind a proxy, this reset page trusts X-Forwarded-Host over Host. Same attack, different header.',
      how: 'POST /hostheader/forgot-xfwd with X-Forwarded-Host: evil.com, then bring the token to the collector.',
    },
    {
      id: 'host-override',
      name: 'X-Host-Override Poisoning',
      difficulty: 'Easy',
      hint: 'A vendor-specific variant of the same flaw: X-Host-Override wins over Host here.',
      how: 'POST /hostheader/forgot-override with X-Host-Override: evil.com, then bring the token to the collector.',
    },
    {
      id: 'host-abs-url',
      name: 'Absolute Continue URL',
      difficulty: 'Easy',
      hint: 'The login page renders an absolute continue URL built from Host, and the post-login 302 uses it too.',
      how: 'Log in at /hostheader/login with Host: evil.com and watch the 302 Location point at evil.com.',
    },
  ],
  router,
};
