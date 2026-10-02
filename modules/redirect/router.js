// PenTrix VulnLab module: Open Redirect (redirect)
// Six labs built around one idea: the server decides where the browser goes
// next, but lets the attacker choose the destination. Covers protocol-relative
// URLs, dangerous schemes in the Location header, a naive allowlist beaten by
// backslashes, OAuth code theft through an unvalidated redirect_uri, and
// parameter pollution where the last ?next= value wins.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// Challenge page slug per vuln id (used by the index page links).
const PAGE_FOR = {
  'redirect-double-slash': 'go',
  'redirect-javascript': 'js',
  'redirect-data': 'data',
  'redirect-backslash': 'trusted',
  'redirect-oauth-theft': 'oauth/authorize',
  'redirect-pollution': 'polluted',
};

function redirectDb() {
  const db = getDb();
  db.exec(`CREATE TABLE IF NOT EXISTS redirect_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    victim TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  return db;
}

// Every lab answers with a real 302 plus a readable body, so `curl -i` shows the
// Location header and the explanation page at the same time.
function sendRedirect(res, target, innerHtml) {
  res.status(302).set('Location', target);
  res.send(page('Redirecting', innerHtml));
}

function challengeForm(action, noteHtml) {
  return `
    <form method="GET" action="${action}">
      <input type="text" name="next" size="60" placeholder="https://example.com/welcome" />
      <button type="submit">Go</button>
    </form>
    <p class="note">${noteHtml}</p>`;
}

const BRIEF_HTML = `
<p><b>What is an open redirect?</b> After an action like login, the app sends the
browser to a URL taken from user input (often <code>?next=</code>) without
validating it. Attackers love it for phishing: the link shows the trusted
domain, but the victim lands on the attacker's page.</p>
<p><b>How to verify in this module:</b> every lab answers with a real HTTP 302.
Use <code>curl -i</code> and read the <code>Location</code> header. That header is
the proof of where the browser would go. A flag is awarded only when the evil
destination is genuinely honored.</p>
<p><b>The OAuth lab</b> chains several steps: simulate the victim login, authorize
with an attacker <code>redirect_uri</code>, then catch the stolen code at the
in-lab attacker collector <code>/redirect/evil-collect</code>.</p>`;

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const done = captured(req, 'redirect', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/redirect/${PAGE_FOR[v.id] || v.id}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('Open Redirect', `
    ${brief('Module briefing', BRIEF_HTML)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

// ----------------------------------------------- v1: protocol-relative URL
router.get('/go', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(page('Open redirect: no validation', `
      <h2>Login complete - where to next?</h2>
      <p>After logging in, the app sends you to the <code>next</code> parameter.
      This endpoint performs <b>no validation at all</b>.</p>
      ${challengeForm('/redirect/go', 'Try <code>?next=//evil.com</code> and watch the <code>Location</code> header with <code>curl -i</code>.')}
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  const target = String(next);
  // VULN: the next parameter is used as the redirect target with zero validation.
  let flagHtml = '';
  if (target.startsWith('//')) {
    const flag = award(req, 'redirect', 'redirect-double-slash');
    flagHtml = `<hr /><p>A protocol-relative URL was honored: the browser keeps the
      current scheme (<code>http:</code> or <code>https:</code>) but navigates to
      the attacker's host.</p>${flagBox(flag)}`;
  }
  sendRedirect(res, target, `
    <h2>Redirecting...</h2>
    <p>If your browser does not follow automatically,
    <a href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a href="/redirect/go">Try another value</a> | <a href="/redirect">Back to the module</a></p>
  `);
});

// ------------------------------------------------------ v2: javascript: URL
router.get('/js', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(page('Redirect: javascript: scheme', `
      <h2>Promo redirect</h2>
      <p>This promo endpoint redirects to <code>next</code>. It never checks the
      URL scheme.</p>
      ${challengeForm('/redirect/js', 'Try <code>?next=javascript:alert(1)</code> and inspect the <code>Location</code> header with <code>curl -i</code>.')}
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  const target = String(next);
  // VULN: the Location header is set from user input with no scheme allowlist.
  let flagHtml = '';
  if (/^javascript:/i.test(target)) {
    const flag = award(req, 'redirect', 'redirect-javascript');
    flagHtml = `<hr /><p>The server honored a <code>javascript:</code> URL in the
      <code>Location</code> header. Older browsers execute it in the context of
      the trusted site; modern ones still leak it into logs, referers, and
      link previews.</p>${flagBox(flag)}`;
  }
  sendRedirect(res, target, `
    <h2>Redirecting...</h2>
    <p>If your browser does not follow automatically,
    <a href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a href="/redirect/js">Try another value</a> | <a href="/redirect">Back to the module</a></p>
  `);
});

// ----------------------------------------------------------- v3: data: URL
router.get('/data', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(page('Redirect: data: scheme', `
      <h2>Share redirect</h2>
      <p>This share endpoint redirects to <code>next</code>. Same missing scheme
      check as the promo endpoint, different payload.</p>
      ${challengeForm('/redirect/data', 'Try <code>?next=data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</code> (URL-encoded) and inspect the <code>Location</code> header.')}
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  const target = String(next);
  // VULN: the Location header is set from user input with no scheme allowlist.
  let flagHtml = '';
  if (/^data:/i.test(target)) {
    const flag = award(req, 'redirect', 'redirect-data');
    flagHtml = `<hr /><p>The server honored a <code>data:</code> URL in the
      <code>Location</code> header. A <code>data:text/html</code> URL smuggles a
      whole attacker-controlled document through the redirect.</p>${flagBox(flag)}`;
  }
  sendRedirect(res, target, `
    <h2>Redirecting...</h2>
    <p>If your browser does not follow automatically,
    <a href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a href="/redirect/data">Try another value</a> | <a href="/redirect">Back to the module</a></p>
  `);
});

// ------------------------------------------------- v4: backslash allowlist bypass
// VULN: naive allowlist. The check compares the raw string prefix instead of the
// parsed hostname, and it also accepts the backslash spelling of a URL. Browsers
// and the WHATWG URL parser treat backslash as a path separator, so
// https:\\evil.com navigates to evil.com while sailing through this check.
function naiveTrusted(next) {
  const n = String(next).toLowerCase();
  return n.startsWith('https://pentrix.lab') || /^https:\\\\[^\\]+/.test(n);
}

router.get('/trusted', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(page('Redirect: naive allowlist', `
      <h2>Partner redirect</h2>
      <p>This endpoint only allows redirects to <code>https://pentrix.lab</code>.
      It checks the <b>raw string prefix</b> instead of parsing the URL.</p>
      ${challengeForm('/redirect/trusted', 'Try <code>?next=https:%5C%5Cevil.com</code> (that is <code>https:\\\\evil.com</code> URL-encoded). Browsers normalize backslashes to slashes.')}
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  const target = String(next);
  if (!naiveTrusted(target)) {
    return res.status(400).send(page('Redirect blocked', `
      <h2>Blocked</h2>
      <p><code>${esc(target)}</code> is not an allowed redirect target.</p>
      <p><a href="/redirect/trusted">Try another value</a></p>
    `));
  }
  let host = '';
  try { host = new URL(target).hostname.toLowerCase(); } catch (e) { host = ''; }
  let flagHtml = '';
  // Award only when the check passed but the real destination is NOT pentrix.lab.
  if (host && host !== 'pentrix.lab') {
    const flag = award(req, 'redirect', 'redirect-backslash');
    flagHtml = `<hr /><p>The naive check passed, but the parsed hostname is
      <code>${esc(host)}</code>, not <code>pentrix.lab</code>. The browser would
      navigate to the attacker's site.</p>${flagBox(flag)}`;
  }
  sendRedirect(res, target, `
    <h2>Redirecting...</h2>
    <p>Target passed the allowlist check.</p>
    <p>If your browser does not follow automatically,
    <a href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a href="/redirect/trusted">Try another value</a> | <a href="/redirect">Back to the module</a></p>
  `);
});

// -------------------------------------------- v5: OAuth code theft (chained)
router.get('/oauth/authorize', (req, res) => {
  const clientId = String(req.query.client_id || 'pentrix-app');
  const redirectUri = String(req.query.redirect_uri || '');
  if (!redirectUri) {
    return res.status(400).send(page('OAuth authorize', `
      <p>Missing <code>redirect_uri</code>.</p>
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  if (!req.session.oauthVictim) {
    const then = encodeURIComponent(req.originalUrl);
    return res.send(page('OAuth authorize', `
      <h2>Pentrix OAuth</h2>
      <p>App <b>${esc(clientId)}</b> is requesting access, but nobody is logged in.</p>
      <p><a href="/redirect/oauth/victim-login?then=${then}">Log in as the victim (alice) to continue the demo</a></p>
      <p class="note">In a real attack the victim is already logged in; this button
      only simulates their session for the lab.</p>
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  res.send(page('OAuth authorize', `
    <h2>Pentrix OAuth</h2>
    <p>Logged in as victim <b>${esc(req.session.oauthVictim)}</b>.</p>
    <p>App <b>${esc(clientId)}</b> wants read access to the victim's account.</p>
    <p>After approval the code will be sent to:<br />
    <code>${esc(redirectUri)}</code></p>
    <form method="POST" action="/redirect/oauth/consent">
      <input type="hidden" name="client_id" value="${esc(clientId)}" />
      <input type="hidden" name="redirect_uri" value="${esc(redirectUri)}" />
      <button type="submit">Authorize app</button>
    </form>
    <p class="note">Look at the <code>redirect_uri</code> above. The server never
    checks it against the app's registered URLs. Point it at
    <code>/redirect/evil-collect</code> and the victim's code goes to the attacker.</p>
  `));
});

router.get('/oauth/victim-login', (req, res) => {
  req.session.oauthVictim = 'alice';
  const then = String(req.query.then || '/redirect/');
  const safe = then.startsWith('/redirect/') ? then : '/redirect/';
  res.redirect(safe);
});

router.post('/oauth/consent', (req, res) => {
  if (!req.session.oauthVictim) {
    return res.status(403).send(page('OAuth', '<p>Victim session expired. Start over.</p>'));
  }
  const clientId = String(req.body.client_id || 'pentrix-app');
  const redirectUri = String(req.body.redirect_uri || '');
  if (!redirectUri) {
    return res.status(400).send(page('OAuth', '<p>Missing redirect_uri.</p>'));
  }
  const code = crypto.randomBytes(16).toString('hex');
  redirectDb()
    .prepare('INSERT INTO redirect_codes (code, client_id, victim, redirect_uri) VALUES (?,?,?,?)')
    .run(code, clientId, req.session.oauthVictim, redirectUri);
  // VULN: redirect_uri is never validated against the client's registered URLs,
  // so the authorization code is delivered straight to the attacker's site.
  const sep = redirectUri.includes('?') ? '&' : '?';
  const target = redirectUri + sep + 'code=' + code;
  sendRedirect(res, target, `
    <h2>Authorized</h2>
    <p>Code issued for <b>${esc(req.session.oauthVictim)}</b>. Returning to the app...</p>
    <p><a href="${esc(target)}">Continue</a></p>
  `);
});

router.get('/evil-collect', (req, res) => {
  const code = String(req.query.code || '');
  const row = code
    ? redirectDb().prepare('SELECT * FROM redirect_codes WHERE code = ?').get(code)
    : undefined;
  if (row) {
    const flag = award(req, 'redirect', 'redirect-oauth-theft');
    return res.send(page('Attacker collector', `
      <h2>Code captured</h2>
      <p>An OAuth authorization code for victim <b>${esc(row.victim)}</b> just
      landed on the attacker's page:</p>
      <pre><code>${esc(code)}</code></pre>
      <p>The attacker can now exchange it for an access token, because the code
      was issued for <b>${esc(row.client_id)}</b> and delivered to an
      unregistered <code>redirect_uri</code>.</p>
      ${flagBox(flag)}
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  res.send(page('Attacker collector', `
    <h2>Evil collector</h2>
    <p>This page belongs to the attacker. It awards the flag when a genuine OAuth
    code issued by <code>/redirect/oauth/authorize</code> arrives here as
    <code>?code=...</code>.</p>
    <p>No code received yet. Run the authorize flow with
    <code>redirect_uri</code> pointing at this page.</p>
    <p><a href="/redirect">Back to the module</a></p>
  `));
});

// ------------------------------------------------- v6: parameter pollution
router.get('/polluted', (req, res) => {
  const raw = req.query.next;
  if (raw === undefined) {
    return res.send(page('Redirect: parameter pollution', `
      <h2>Legacy redirect</h2>
      <p>This old endpoint redirects to <code>next</code>. When the parameter
      appears more than once, the server silently honors the <b>last</b> value.</p>
      ${challengeForm('/redirect/polluted', 'Try <code>?next=safe&amp;next=https://evil.com</code> and check which value lands in the <code>Location</code> header.')}
      <p><a href="/redirect">Back to the module</a></p>
    `));
  }
  const vals = Array.isArray(raw) ? raw : [raw];
  // VULN: with duplicate parameters the code honors the last value; the first
  // one is only camouflage for anyone reviewing the link.
  const target = String(vals[vals.length - 1]);
  let host = '';
  try { host = new URL(target).hostname.toLowerCase(); } catch (e) { host = ''; }
  let flagHtml = '';
  if (vals.length > 1 && host && host !== 'pentrix.lab') {
    const flag = award(req, 'redirect', 'redirect-pollution');
    flagHtml = `<hr /><p>${vals.length} values were supplied
      (<code>${vals.map((v) => esc(String(v))).join('</code>, <code>')}</code>);
      the server honored the last one.</p>${flagBox(flag)}`;
  }
  sendRedirect(res, target, `
    <h2>Redirecting...</h2>
    <p>If your browser does not follow automatically,
    <a href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a href="/redirect/polluted">Try another value</a> | <a href="/redirect">Back to the module</a></p>
  `);
});

module.exports = {
  id: 'redirect',
  name: 'Open Redirect',
  tagline: 'Six open-redirect flaws: from //evil.com to a stolen OAuth code.',
  description: 'Six open-redirect labs: an unvalidated next parameter abused with protocol-relative URLs, javascript: and data: schemes, a naive string-prefix allowlist beaten by backslash separators, a full OAuth authorization-code theft chain through an unvalidated redirect_uri, and parameter pollution where the last ?next= value wins.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'redirect-double-slash',
      name: 'Protocol-Relative Redirect',
      difficulty: 'Easy',
      hint: 'The ?next= parameter is passed straight to the redirect with no validation. What does a URL starting with // mean to a browser?',
      how: 'Request /redirect/go?next=//evil.com and confirm the Location header points at evil.com.',
    },
    {
      id: 'redirect-javascript',
      name: 'javascript: Scheme Honored',
      difficulty: 'Medium',
      hint: 'The redirect puts whatever you give it into the Location header, with no scheme allowlist. Browsers treat javascript: as code, not a page.',
      how: 'Request /redirect/js?next=javascript:alert(1) and inspect the Location header with curl -i.',
    },
    {
      id: 'redirect-data',
      name: 'data: Scheme Honored',
      difficulty: 'Medium',
      hint: 'Same sink, different scheme: data: URLs let you smuggle a whole HTML document through the redirect.',
      how: 'Request /redirect/data?next=data:text/html,<script>alert(1)</script> (URL-encoded) and check the Location header.',
    },
    {
      id: 'redirect-backslash',
      name: 'Backslash Allowlist Bypass',
      difficulty: 'Medium',
      hint: 'The code allowlists URLs starting with https://pentrix.lab, but compares the raw string and accepts backslashes as separators. Browsers normalize backslash to slash.',
      how: 'Pass ?next=https:%5C%5Cevil.com (https:\\\\evil.com URL-encoded) to /redirect/trusted and watch the check pass.',
    },
    {
      id: 'redirect-oauth-theft',
      name: 'OAuth Code Theft via redirect_uri',
      difficulty: 'Hard',
      hint: 'The authorize endpoint never validates redirect_uri against the registered app. Make the victim\'s code go to your collector.',
      how: 'Chain victim-login, authorize with redirect_uri pointing at /redirect/evil-collect, approve, and catch the code there.',
    },
    {
      id: 'redirect-pollution',
      name: 'Parameter Pollution Picks Last',
      difficulty: 'Medium',
      hint: 'When ?next= appears twice, the server silently honors the last value. The first one is just camouflage.',
      how: 'Request /redirect/polluted?next=safe&next=https://evil.com and check which value lands in the Location header.',
    },
  ],
  router,
};
