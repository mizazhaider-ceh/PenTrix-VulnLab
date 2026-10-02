// PenTrix VulnLab - CSRF & Open Redirect module (csrf)
// Intentionally vulnerable training module. Local lab use only.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing (urlencoded). JSON and text parsers are added per-route.
router.use(express.urlencoded({ extended: false }));

// Challenge page slug per vuln id (used by the index page links).
const ROUTES = {
  email: 'change-email', redirect: 'go', clickjacking: 'framedemo',
  'json-csrf': 'json-email', 'login-csrf': 'attacker-login',
  'multipart-csrf': 'password-multipart', 'referer-bypass': 'nickname',
  'get-passwd-change': 'change-password', 'contenttype-bypass': 'theme',
  'method-override-csrf': 'account', '2fa-disable-get': '2fa',
};

function notLoggedInPage() {
  return page('Not logged in', `
    <h1>Not logged in</h1>
    <p><a href="/csrf/login/alice">Quick-login as alice</a> first, then come back.</p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `);
}

const VULNS = [
  {
    id: 'email',
    name: 'Change Email with No CSRF Token (state-changing GET)',
    difficulty: 'Easy',
    hint: 'The email change is a plain GET request with no anti-CSRF token. Any page the victim visits can trigger it - a link, an image tag, anything. Log in as alice, then visit the change-email URL with ?email= set.',
    how: 'Log in, then open /csrf/change-email?email=evil@attacker.com - the email changes with no token or confirmation.',
  },
  {
    id: 'redirect',
    name: 'Unvalidated Open Redirect',
    difficulty: 'Easy',
    hint: 'The "to" parameter is passed straight to res.redirect() with no allow-list check. Attackers use trusted domains like this to make phishing links look safe.',
    how: 'Open /csrf/go?to=https://evil.example.com - the app redirects to an external site. The flag is captured before the redirect happens.',
  },
  {
    id: 'clickjacking',
    name: 'Clickjacking (missing X-Frame-Options)',
    difficulty: 'Easy',
    hint: 'The VIP action page sends no X-Frame-Options header, so any site can embed it in an invisible iframe and trick clicks into landing on its buttons.',
    how: 'Visit /csrf/framedemo to see the page framed in an iframe - proof that any attacker site could overlay and hijack clicks.',
  },
  {
    id: 'json-csrf',
    name: 'JSON API CSRF via text/plain (simple request)',
    difficulty: 'Medium',
    hint: 'The endpoint accepts text/plain bodies and extracts JSON from them. A cross-site form with enctype="text/plain" is a CORS simple request: no preflight, cookies attached. Make the form body contain {"email":"..."}.',
    how: 'Submit the text/plain form so its body carries a JSON email change to /csrf/api/email.',
  },
  {
    id: 'login-csrf',
    name: 'Login CSRF (forged session switch)',
    difficulty: 'Medium',
    hint: 'The login endpoint sets the session user with no CSRF token. An attacker page can auto-submit a login as "mallory", silently switching the victim into the attacker-controlled account.',
    how: 'While logged in as alice, visit /csrf/attacker-login; it auto-submits a login as mallory and your session switches.',
  },
  {
    id: 'multipart-csrf',
    name: 'Password Change via multipart/form-data (no token)',
    difficulty: 'Easy',
    hint: 'The password-change API reads multipart bodies and checks no CSRF token. A plain cross-site form with enctype="multipart/form-data" can submit it.',
    how: 'Submit the multipart form to change the account password.',
  },
  {
    id: 'referer-bypass',
    name: 'Weak Referer Check Bypass',
    difficulty: 'Medium',
    hint: 'The check is referer.includes("pentrix.lab"). The attacker controls the referer of requests from their own page, so https://evil.com/?pentrix.lab contains the magic string.',
    how: 'POST the nickname change with a Referer header of https://evil.com/?pentrix.lab.',
  },
  {
    id: 'get-passwd-change',
    name: 'Password Change via GET (no token)',
    difficulty: 'Easy',
    hint: 'Same flaw class as the email lab, different target: the password changes through a GET parameter with no token, so a forged link or image tag does it.',
    how: 'Open /csrf/change-password?password=... while logged in.',
  },
  {
    id: 'contenttype-bypass',
    name: 'Content-Type Confusion on a JSON API',
    difficulty: 'Medium',
    hint: 'The endpoint was built for JSON clients, but the urlencoded body parser also fills req.body. A plain HTML form (no fetch, no preflight) can drive this "JSON-only" API.',
    how: 'Submit the plain HTML form to change the theme setting on the JSON endpoint.',
  },
  {
    id: 'method-override-csrf',
    name: 'HTTP Method Override Smuggling (_method=DELETE)',
    difficulty: 'Medium',
    hint: 'The app treats DELETE as the privileged method, but honors a _method=DELETE field on a plain POST. Cross-site forms can only send GET/POST, so the override smuggles the "protected" method through with no preflight.',
    how: 'POST the account form with _method=DELETE to trigger the privileged delete path.',
  },
  {
    id: '2fa-disable-get',
    name: 'Disable 2FA via GET Link (no token)',
    difficulty: 'Easy',
    hint: 'Disabling two-factor auth is a GET request with no token. One click on an attacker link (or a single image load) turns the victim\'s 2FA off.',
    how: 'Open /csrf/2fa/disable while logged in.',
  },
];

function currentUser(req) {
  return req.session && req.session.user ? req.session.user : null;
}

function aliceEmail() {
  const row = getDb().prepare('SELECT email FROM users WHERE id = 2').get();
  return row ? row.email : '(unknown)';
}

// ---------------------------------------------------------------------------
// Quick-login. In a real lab this is just a shortcut so the student does not
// have to go through the auth module.
// ---------------------------------------------------------------------------
router.get('/login/alice', (req, res) => {
  req.session.user = { id: 2, username: 'alice', role: 'user' };
  res.send(page('Logged in', `
    <h1>Logged in</h1>
    <p>You are now logged in as <b>alice</b> (user id 2).</p>
    <p>Current account email: <code>${esc(aliceEmail())}</code></p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v1: change email through a plain GET request.
// VULN: state-changing action accepts GET, so any third-party page the victim
// visits can fire it. VULN: no anti-CSRF token anywhere in the flow.
// ---------------------------------------------------------------------------
router.get('/change-email', (req, res) => {
  const user = currentUser(req);
  if (!user) {
    return res.send(page('Change Email', `
      <h1>Change Email</h1>
      <p>You are not logged in. <a href="/csrf/login/alice">Log in as alice first</a>.</p>
      <p><a href="/csrf">Back to the CSRF module</a></p>
    `));
  }

  const email = req.query.email === undefined ? null : String(req.query.email);

  if (email === null) {
    // Attack surface: the vulnerable endpoint plus a demo of the forged link.
    return res.send(page('Change Email', `
      <h1>Change Email</h1>
      ${brief('Challenge', `
        This settings page changes the logged-in account's email address with a
        <b>plain GET request</b> and <b>no CSRF token</b>. That means any site the
        victim visits can change their email for them, e.g. with a hidden
        <code>&lt;img src="/csrf/change-email?email=attacker@evil.com"&gt;</code>
        tag. The attacker then uses "forgot password" to take over the account.
      `)}
      <p>Your current email: <code>${esc(aliceEmail())}</code></p>
      <form method="get" action="/csrf/change-email">
        <label>New email: <input name="email" size="40" value="attacker@evil.com" /></label>
        <button type="submit">Change email</button>
      </form>
      <p class="dim">Simulated attacker link (try it yourself):
        <a href="/csrf/change-email?email=attacker@evil.com">/csrf/change-email?email=attacker@evil.com</a>
      </p>
      ${hintBox('Because the change is triggered by GET with no token, the attacker does not need the victim to click anything suspicious - a single forged request does the job.')}
      <p><a href="/csrf">Back to the CSRF module</a></p>
    `));
  }

  if (email.trim() === '') {
    return res.send(page('Change Email', `
      <h1>Change Email</h1>
      <p>Email was empty - nothing changed.</p>
      <p><a href="/csrf/change-email">Try again</a> | <a href="/csrf">Back to the CSRF module</a></p>
    `));
  }

  // VULN: state change performed over GET with no CSRF token, so a forged
  // cross-site request from any third-party page succeeds silently.
  getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(email, user.id);
  const flag = award(req, 'csrf', 'email');
  res.send(page('Change Email', `
    <h1>Email changed</h1>
    ${flagBox(flag)}
    <p>Your account email is now: <code>${esc(email)}</code></p>
    ${hintBox('That request carried no token and did not even need a form submit - this is exactly what an attacker\'s forged link or image tag would have done from another site.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v2: open redirect.
// VULN: the "to" parameter is passed to res.redirect() with no validation or
// allow-list, so any external URL is accepted.
// ---------------------------------------------------------------------------
router.get('/go', (req, res) => {
  const to = req.query.to === undefined ? null : String(req.query.to);

  if (to === null) {
    return res.send(page('Redirect Service', `
      <h1>Redirect Service</h1>
      ${brief('Challenge', `
        This helper redirects you wherever the <code>to</code> parameter says,
        with <b>no validation</b>. Attackers love this pattern: a phishing link
        like <code>https://pentrix.lab/csrf/go?to=https://evil.example.com</code>
        looks trustworthy because it starts with the real domain.
      `)}
      <form method="get" action="/csrf/go">
        <label>Destination: <input name="to" size="50" value="https://evil.example.com" /></label>
        <button type="submit">Go</button>
      </form>
      <p class="dim">Try: <a href="/csrf/go?to=https://evil.example.com">/csrf/go?to=https://evil.example.com</a></p>
      ${hintBox('A safe redirector would check the destination against an allow-list or at least reject external URLs.')}
      <p><a href="/csrf">Back to the CSRF module</a></p>
    `));
  }

  const isExternal = to.startsWith('http') && !to.includes('localhost') && !to.includes('127.0.0.1');
  if (isExternal) {
    // VULN: external redirect target accepted blindly - award before redirecting.
    award(req, 'csrf', 'redirect');
  }
  // VULN: unvalidated user input flows straight into res.redirect().
  res.redirect(to);
});

// ---------------------------------------------------------------------------
// v3: clickjacking target. The "dangerous" button is deliberately harmless -
// the vulnerability under test is the missing framing protection.
// ---------------------------------------------------------------------------
function vipPage(message) {
  return page('VIP Action', `
    <h1>Account Settings</h1>
    <p class="dim">This page has no <code>X-Frame-Options</code> header, so it can be embedded anywhere.</p>
    ${message || ''}
    <form method="post" action="/csrf/vip-action">
      <button type="submit">Delete my account</button>
    </form>
  `);
}

router.get('/vip-action', (req, res) => {
  // Deliberately no X-Frame-Options (and no CSP frame-ancestors): this missing
  // header is the vulnerability, so any site can frame this page.
  res.removeHeader('X-Frame-Options');
  res.send(vipPage(''));
});

router.post('/vip-action', (req, res) => {
  res.removeHeader('X-Frame-Options');
  res.send(vipPage(`
    <p><b>Demo only:</b> your account was <u>not</u> deleted. This page exists to
    demonstrate clickjacking framing, not to do anything destructive.</p>
  `));
});

// ---------------------------------------------------------------------------
// Framing demo: embeds /csrf/vip-action in an iframe to prove framing works.
// ---------------------------------------------------------------------------
router.get('/framedemo', (req, res) => {
  const flag = award(req, 'csrf', 'clickjacking');
  res.send(page('Framing Demo', `
    <h1>Clickjacking Demo</h1>
    ${flagBox(flag)}
    ${brief('What is clickjacking?', `
      <b>Clickjacking</b> tricks a user into clicking something different from
      what they think they are clicking. The attacker embeds a legitimate page in
      an invisible (or disguised) <code>&lt;iframe&gt;</code> and layers their own
      content on top. When the victim clicks the attacker's button, the click
      actually lands on the hidden page - for example on a "Delete my account"
      button.
      <br><br>The fix is a single header: <code>X-Frame-Options: DENY</code> (or
      <code>SAMEORIGIN</code>). This page sends <b>neither</b>, so the frame below
      loads fine - that is the vulnerability.
    `)}
    <h2>The framed page (proof it can be embedded)</h2>
    <iframe src="/csrf/vip-action" width="600" height="320" style="border:2px solid #ccc;"></iframe>
    ${hintBox('An attacker would make the iframe invisible and place a fake button exactly over the real one. The victim clicks "Win a prize" but hits "Delete my account".')}
    <p><a href="/csrf/vip-action">Open the framed page directly</a></p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v4: JSON email change that also accepts text/plain bodies.
// A cross-site <form enctype="text/plain"> is a CORS simple request (no
// preflight, cookies attached), so it can drive this "JSON" API.
// VULN: no CSRF token, and text/plain bodies are mined for a JSON object.
// ---------------------------------------------------------------------------
router.get('/json-email', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());
  res.send(page('Change Email (JSON API)', `
    <h1>Change Email (JSON API)</h1>
    ${brief('Challenge', `
      This API changes your email from a <b>JSON body</b>. The developers assumed
      only their own JavaScript client would call it, so there is <b>no CSRF
      token</b>. But the endpoint also accepts <code>Content-Type:
      text/plain</code> bodies and fishes a JSON object out of them. A cross-site
      <code>&lt;form enctype="text/plain"&gt;</code> is a CORS <b>simple
      request</b>: no preflight, cookies attached. An attacker's page can drive
      this "JSON-only" API with a plain auto-submitting form.
    `)}
    <p>Your current email: <code>${esc(aliceEmail())}</code></p>
    <h2>Attack form (what the evil site would host)</h2>
    <form method="POST" action="/csrf/api/email" enctype="text/plain">
      <input type="hidden" name='{"email":"attacker@evil.com"}' value="ignored" />
      <button type="submit">Fire forged JSON request</button>
    </form>
    <p class="dim">The form body becomes
    <code>{"email":"attacker@evil.com"}=ignored</code>, and the server extracts
    the JSON object from it.</p>
    ${hintBox('Simple requests (plain forms) skip CORS preflight, so the missing token is the only thing that had to fail - and it did.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.post('/api/email', express.text({ type: 'text/plain' }), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage());
  let email = null;
  try {
    // VULN: text/plain body is mined for anything shaped like a JSON object.
    const m = /\{[\s\S]*\}/.exec(String(req.body || ''));
    if (m) email = JSON.parse(m[0]).email;
  } catch (e) { /* not JSON shaped */ }
  if (!email || String(email).trim() === '') {
    return res.status(400).send(page('JSON Email', '<p>No usable email found in the request body.</p><p><a href="/csrf/json-email">Back</a></p>'));
  }
  // VULN: state-changing JSON API with no CSRF token, reachable by a simple form.
  getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(String(email), user.id);
  const flag = award(req, 'csrf', 'json-csrf');
  res.send(page('JSON Email', `
    <h1>Email changed</h1>
    ${flagBox(flag)}
    <p>Your account email is now: <code>${esc(String(email))}</code></p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v5: login CSRF. The demo login sets the session user with no token, so an
// attacker page can auto-submit a login as "mallory" and silently switch the
// victim into the attacker's account (classic session-fixation setup).
// ---------------------------------------------------------------------------
router.get('/login', (req, res) => {
  res.send(page('Demo Login', `
    <h1>Demo Login</h1>
    <p>This demo login sets your session user. There is <b>no CSRF token</b> on it.</p>
    <form method="POST" action="/csrf/login">
      <label>Username: <input name="username" value="mallory" /></label>
      <button type="submit">Log in</button>
    </form>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim().slice(0, 40) || 'anonymous';
  // VULN: login performs a state-changing session switch with no CSRF token.
  req.session.user = { id: 9000, username, role: 'user' };
  let flagHtml = '';
  if (username.toLowerCase() === 'mallory') {
    // Award only when the forged login genuinely switched the session to mallory.
    flagHtml = flagBox(award(req, 'csrf', 'login-csrf'));
  }
  res.send(page('Demo Login', `
    <h1>Logged in</h1>
    ${flagHtml}
    <p>Your session user is now: <b>${esc(username)}</b>.</p>
    <p class="dim">If you arrived here from the attacker demo page, that page just
    switched your identity without you clicking anything.</p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.get('/attacker-login', (req, res) => {
  const user = currentUser(req);
  res.send(page('Free Security Ebook', `
    <h1>Free security ebook (totally legit site)</h1>
    <p>While you read this, a hidden form is submitting a login as
    <b>mallory</b> against the lab...</p>
    ${user
      ? `<p>You arrived here as <b>${esc(user.username)}</b>. Watch your session switch.</p>`
      : '<p>You are not logged in yet. <a href="/csrf/login/alice">Log in as alice first</a>, then come back here.</p>'}
    <form id="evil" method="POST" action="/csrf/login">
      <input type="hidden" name="username" value="mallory" />
    </form>
    <script>document.getElementById('evil').submit();</script>
    ${hintBox('Login CSRF lets the attacker choose which account the victim ends up in. Combined with a password the attacker knows, every subsequent login the victim performs can be observed.')}
    <p><a href="/csrf">Back to the CSRF module</a> (check who you are logged in as)</p>
  `));
});

// ---------------------------------------------------------------------------
// v6: password change over multipart/form-data, no token.
// VULN: the endpoint parses multipart bodies and checks no CSRF token, so a
// plain cross-site form with enctype="multipart/form-data" can submit it.
// ---------------------------------------------------------------------------
function parseMultipartField(buf, contentType, fieldName) {
  const m = /boundary=([^;]+)/i.exec(contentType || '');
  if (!m) return null;
  const boundary = '--' + m[1].trim().replace(/^"|"$/g, '');
  const parts = String(buf).split(boundary);
  for (const part of parts) {
    if (part.includes(`name="${fieldName}"`)) {
      const idx = part.indexOf('\r\n\r\n');
      if (idx === -1) continue;
      return part.slice(idx + 4).replace(/\r\n$/, '').trim();
    }
  }
  return null;
}

router.get('/password-multipart', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());
  res.send(page('Change Password (multipart)', `
    <h1>Change Password</h1>
    ${brief('Challenge', `
      This password-change API reads <code>multipart/form-data</code> bodies and
      checks <b>no CSRF token</b>. Developers sometimes assume multipart means
      "file upload form on our site", but any cross-site page can send a
      multipart form too - no preflight, cookies attached.
    `)}
    <form method="POST" action="/csrf/api/password-multipart" enctype="multipart/form-data">
      <label>New password: <input type="password" name="password" value="hacked123" /></label>
      <button type="submit">Change password</button>
    </form>
    ${hintBox('The enctype does not protect anything: it is just a body format, and the attacker can use the same format from their own page.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.post('/api/password-multipart', express.raw({ type: 'multipart/form-data', limit: '1mb' }), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage());
  const pw = parseMultipartField(req.body, req.get('content-type'), 'password');
  if (!pw) {
    return res.status(400).send(page('Password', '<p>No password field found in the multipart body.</p><p><a href="/csrf/password-multipart">Back</a></p>'));
  }
  // VULN: password change via multipart with no CSRF token.
  getDb().prepare('UPDATE users SET password = ? WHERE id = ?').run(pw, user.id);
  const flag = award(req, 'csrf', 'multipart-csrf');
  res.send(page('Password', `
    <h1>Password changed</h1>
    ${flagBox(flag)}
    <p>The account password was changed through a multipart request carrying no token.</p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v7: weak referer check. The app is meant to be served at pentrix.lab, and
// the check is referer.includes('pentrix.lab'). The attacker controls the
// referer sent from their own page, so https://evil.com/?pentrix.lab passes.
// ---------------------------------------------------------------------------
router.get('/nickname', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());
  const nick = req.session.nickname || '(not set)';
  res.send(page('Change Nickname', `
    <h1>Change Nickname</h1>
    ${brief('Challenge', `
      This endpoint checks the <code>Referer</code> header and only accepts
      requests whose referer contains <code>pentrix.lab</code> (this app's
      production domain). There is <b>no CSRF token</b>. The check looks solid
      until you realize the attacker fully controls the referer of requests sent
      from <i>their own</i> page.
    `)}
    <p>Current nickname: <b>${esc(nick)}</b></p>
    <form method="POST" action="/csrf/api/nickname">
      <label>New nickname: <input name="nickname" placeholder="new nickname" /></label>
      <button type="submit">Change nickname</button>
    </form>
    <p class="dim">Note: in this lab the app runs on localhost, so even this
    legitimate form is blocked (your referer is localhost, not pentrix.lab) -
    that is the check working as coded. The attacker bypasses it anyway.</p>
    ${hintBox('A substring check on an attacker-controlled value is not a security boundary. The bypass referer is https://evil.com/?pentrix.lab.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.post('/api/nickname', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage());
  const ref = req.get('referer') || '';
  // VULN: substring referer check is attacker-controlled; evil.com/?pentrix.lab passes it.
  if (!ref.includes('pentrix.lab')) {
    return res.status(403).send(page('Forbidden', `
      <h1>403</h1><p>Referer check failed.</p><p><a href="/csrf/nickname">Back</a></p>
    `));
  }
  const nick = String(req.body.nickname || '').slice(0, 40);
  req.session.nickname = nick;
  // Award only when the change came through a forged (non-same-origin) referer.
  const host = req.get('host') || '';
  const sameOrigin = ref.startsWith('http://' + host) || ref.startsWith('https://' + host);
  const flagHtml = sameOrigin ? '' : flagBox(award(req, 'csrf', 'referer-bypass'));
  res.send(page('Nickname', `
    <h1>Nickname changed</h1>
    ${flagHtml}
    <p>Nickname is now: <b>${esc(nick)}</b> (referer was <code>${esc(ref)}</code>)</p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v8: password change via GET, no token. Same flaw class as the email lab, a
// different target: a forged link or image tag changes the victim's password.
// VULN: state-changing action accepts GET, and no anti-CSRF token is checked.
// ---------------------------------------------------------------------------
router.get('/change-password', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());

  const password = req.query.password === undefined ? null : String(req.query.password);

  if (password === null) {
    return res.send(page('Change Password', `
      <h1>Change Password</h1>
      ${brief('Challenge', `
        This settings page changes the logged-in account's password with a
        <b>plain GET request</b> and <b>no CSRF token</b>. Any site the victim
        visits can change their password for them, e.g. with a hidden
        <code>&lt;img src="/csrf/change-password?password=hacked123"&gt;</code>
        tag. The attacker then logs in with the known password.
      `)}
      <form method="get" action="/csrf/change-password">
        <label>New password: <input name="password" value="hacked123" /></label>
        <button type="submit">Change password</button>
      </form>
      <p class="dim">Simulated attacker link:
        <a href="/csrf/change-password?password=hacked123">/csrf/change-password?password=hacked123</a>
      </p>
      ${hintBox('GET requests are meant to be safe and repeatable. Browsers prefetch them, proxies cache them, and any third-party page can trigger them.')}
      <p><a href="/csrf">Back to the CSRF module</a></p>
    `));
  }

  if (password.trim() === '') {
    return res.send(page('Change Password', `
      <h1>Change Password</h1>
      <p>Password was empty - nothing changed.</p>
      <p><a href="/csrf/change-password">Try again</a> | <a href="/csrf">Back</a></p>
    `));
  }

  // VULN: password change performed over GET with no CSRF token.
  getDb().prepare('UPDATE users SET password = ? WHERE id = ?').run(password, user.id);
  const flag = award(req, 'csrf', 'get-passwd-change');
  res.send(page('Change Password', `
    <h1>Password changed</h1>
    ${flagBox(flag)}
    <p>The account password was changed through a GET request carrying no token.</p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v9: content-type confusion. The endpoint was built for JSON clients, but the
// urlencoded parser also populates req.body, so a plain cross-site HTML form
// (no fetch, no preflight) drives this "JSON-only" API.
// ---------------------------------------------------------------------------
router.get('/theme', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());
  const theme = req.session.theme || 'light';
  res.send(page('Theme Setting', `
    <h1>Theme Setting (JSON API)</h1>
    ${brief('Challenge', `
      <code>POST /csrf/api/theme</code> was built for the app's JavaScript
      client, which sends <code>Content-Type: application/json</code>. The
      developers skipped the CSRF token because "only JSON clients call it, and
      forms cannot send JSON". Wrong: the urlencoded body parser also fills
      <code>req.body</code>, so a plain cross-site HTML form drives the endpoint
      just fine. No preflight, cookies attached.
    `)}
    <p>Current theme: <b>${esc(theme)}</b></p>
    <h2>Attack form (plain HTML, no JavaScript)</h2>
    <form method="POST" action="/csrf/api/theme">
      <label>Theme: <input name="theme" value="dark" /></label>
      <button type="submit">Set theme</button>
    </form>
    <p class="dim">Intended client:
    <code>curl -X POST -H 'Content-Type: application/json' -d '{"theme":"dark"}' /csrf/api/theme</code>
    (works, but earns no flag)</p>
    ${hintBox('If the server fills req.body from more than one content type, the "JSON-only" assumption is fiction.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.post('/api/theme', express.json(), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage());
  const theme = String((req.body && req.body.theme) || '').slice(0, 20);
  if (!theme) {
    return res.status(400).send(page('Theme', '<p>Theme is required.</p><p><a href="/csrf/theme">Back</a></p>'));
  }
  // VULN: no CSRF token; urlencoded parser fills req.body so plain forms work on this "JSON" API.
  req.session.theme = theme;
  // The flag is for the bypass: a non-JSON content type driving the endpoint.
  const flagHtml = req.is('application/json') ? '' : flagBox(award(req, 'csrf', 'contenttype-bypass'));
  res.send(page('Theme', `
    <h1>Theme updated</h1>
    ${flagHtml}
    <p>Theme is now: <b>${esc(theme)}</b></p>
    <p><a href="/csrf/theme">Back</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v10: HTTP method override smuggling. DELETE is treated as the privileged
// method (cross-site DELETE needs a CORS preflight), but the app honors a
// _method=DELETE field on a plain POST, which needs no preflight at all.
// ---------------------------------------------------------------------------
router.get('/account', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());
  const deleted = !!req.session.accountDeleted;
  res.send(page('Account', `
    <h1>Account</h1>
    ${brief('Challenge', `
      Deleting the account is meant to require an HTTP <code>DELETE</code>
      request. Browsers run a CORS preflight for cross-site <code>DELETE</code>,
      so the developers felt safe with <b>no CSRF token</b>. But the app also
      honors a <code>_method=DELETE</code> field on a plain <code>POST</code> -
      and a cross-site form can send <i>that</i> with no preflight at all.
    `)}
    <p>Account status: <b>${deleted ? 'DELETED' : 'active'}</b></p>
    <h2>Attack form (the override)</h2>
    <form method="POST" action="/csrf/account">
      <input type="hidden" name="_method" value="DELETE" />
      <button type="submit">Delete account via override</button>
    </form>
    <p class="dim">The "proper" client would send <code>DELETE /csrf/account</code>
    (try it with curl - no flag for that path).</p>
    ${hintBox('Method-override parameters exist for HTML forms, which can only send GET and POST. Honoring them on state-changing routes re-opens every method you thought was protected.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.post('/account', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage());
  // VULN: manual _method override lets a plain POST trigger the privileged DELETE path.
  if (String(req.body._method || '').toUpperCase() === 'DELETE') {
    req.session.accountDeleted = true;
    const flag = award(req, 'csrf', 'method-override-csrf');
    return res.send(page('Account', `
      <h1>Account deleted</h1>
      ${flagBox(flag)}
      <p>The <code>_method=DELETE</code> override on a plain POST triggered the delete path.</p>
      <p><a href="/csrf/account">Back</a></p>
    `));
  }
  res.send(page('Account', `
    <h1>Account</h1>
    <p>Nothing to do. Add <code>_method=DELETE</code> to reach the delete path.</p>
    <p><a href="/csrf/account">Back</a></p>
  `));
});

router.delete('/account', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage());
  req.session.accountDeleted = true;
  res.send(page('Account', `
    <h1>Account deleted</h1>
    <p>Deleted via the DELETE method. No flag on this path: the challenge is the override.</p>
    <p><a href="/csrf/account">Back</a></p>
  `));
});

// ---------------------------------------------------------------------------
// v11: disabling 2FA via a GET link, no token. One click (or one image load)
// on an attacker page silently strips the victim's second factor.
// VULN: security-sensitive state change over GET with no CSRF token.
// ---------------------------------------------------------------------------
router.get('/2fa', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());
  const on = req.session.twofa !== false;
  res.send(page('Two-Factor Auth', `
    <h1>Two-Factor Authentication</h1>
    <p>Status: <b>${on ? 'ENABLED' : 'DISABLED'}</b></p>
    ${on
      ? '<p><a href="/csrf/2fa/disable">Disable 2FA</a> (this link is the vulnerability)</p>'
      : '<p class="dim">2FA is off. It resets when your session resets.</p>'}
    ${hintBox('Disabling 2FA is a GET request with no token: an attacker link or image tag turns it off silently.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

router.get('/2fa/disable', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage());
  // VULN: security-sensitive state change performed over GET with no CSRF token.
  req.session.twofa = false;
  const flag = award(req, 'csrf', '2fa-disable-get');
  res.send(page('Two-Factor Auth', `
    <h1>2FA disabled</h1>
    ${flagBox(flag)}
    <p>Two-factor authentication is now off for your account.</p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// Module index page
// ---------------------------------------------------------------------------
router.get('/', (req, res) => {
  const user = currentUser(req);
  const loginHtml = user
    ? `<p>Logged in as <b>${esc(user.username)}</b> (id ${esc(String(user.id))}). Current email: <code>${esc(aliceEmail())}</code></p>`
    : `<p>You are <b>not logged in</b>. <a href="/csrf/login/alice">Quick-login as alice</a> to try the CSRF challenges.</p>`;

  const rows = VULNS.map((v) => `
    <tr>
      <td><b>${esc(v.name)}</b><br><span class="dim">${esc(v.how)}</span></td>
      <td>${esc(v.difficulty)}</td>
      <td>${hintBox(esc(v.hint))}</td>
      <td><a href="/csrf/${ROUTES[v.id] || v.id}">Open challenge</a></td>
    </tr>`).join('');

  res.send(page('CSRF & Open Redirect', `
    <h1>CSRF &amp; Open Redirect</h1>
    ${brief('Briefing', `
      <b>Cross-Site Request Forgery (CSRF)</b> abuses the fact that browsers
      automatically send your cookies with every request, even ones triggered by
      a <i>different</i> site. If an application changes state (password, email,
      transfer, delete) on a plain <b>GET</b> request with <b>no CSRF token</b>,
      an attacker can forge that request from their own page - a link, an
      <code>&lt;img&gt;</code> tag, a hidden auto-submitting form - and your
      browser will happily execute it while you are logged in.
      <br><br><b>Open redirects</b> are the social-engineering cousin: the app
      redirects to an unvalidated URL, so phishing links can wear a trusted
      domain as a disguise.
      <br><br><b>Clickjacking</b> layers the attack visually: a page that sends
      no <code>X-Frame-Options</code> header can be embedded in an invisible
      <code>&lt;iframe&gt;</code> on an attacker's site, so your clicks land on
      buttons you never saw.
    `)}
    ${loginHtml}
    <h2>Challenges</h2>
    <table>
      <tr><th>Challenge</th><th>Difficulty</th><th>Hint</th><th>Link</th></tr>
      ${rows}
    </table>
  `));
});

module.exports = {
  id: 'csrf',
  name: 'CSRF & Open Redirect',
  tagline: 'Forge cross-site requests, redirect anywhere, and frame the unframeable.',
  description: 'Learn how state-changing GET requests with no CSRF token let attackers act as you, how unvalidated redirects launder phishing links, and how a missing X-Frame-Options header enables clickjacking.',
  difficulty: 'Beginner',
  vulns: VULNS,
  router,
};
