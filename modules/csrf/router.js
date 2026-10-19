// PenTrix VulnLab - CSRF & Open Redirect module (csrf)
// Intentionally vulnerable training module. Local lab use only.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { brief, esc, fixPanel, flagBox, hintBox, hintLadder, page, toolsPill, trackBanner } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing (urlencoded). JSON and text parsers are added per-route.
router.use(express.urlencoded({ extended: false }));

// Challenge page slug per vuln id (used by the index page links).
const ROUTES = {
  email: 'change-email', clickjacking: 'framedemo',
  'json-csrf': 'json-email', 'referer-bypass': 'nickname',
  'method-override-csrf': 'account',
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
    hints: ["The email change is a GET request with no token. What happens if someone else triggers that URL?", "A forged link or <img> tag from an attacker's page will change YOUR email while you're logged in.", "While logged in, open /csrf/change-email?email=evil@evil.com (or have the 'attacker page' do it)."],
    tools: "B",
    how: 'Log in, then open /csrf/change-email?email=evil@attacker.com - the email changes with no token or confirmation.',
  },
  {
    id: 'clickjacking',
    name: 'Clickjacking (missing X-Frame-Options)',
    difficulty: 'Easy',
    hint: 'The VIP action page sends no X-Frame-Options header, so any site can embed it in an invisible iframe and trick clicks into landing on its buttons. Open /csrf/framedemo and click the decoy prize button: your click lands on the hidden "Delete my account" button, and the framed form submission captures the flag.',
    hints: ["The VIP action page has no X-Frame-Options. Can it be framed?", "An attacker's invisible iframe can host the page. Your click on their decoy button lands on the hidden real button.", "Open /csrf/framedemo and click the decoy. The framed form submits with the one-time token."],
    tools: "B",
    how: 'Open /csrf/framedemo and click the decoy button layered over the nearly-invisible framed page. The click submits the framed form, which carries the one-time framing token.',
  },
  {
    id: 'json-csrf',
    name: 'JSON API CSRF via text/plain (simple request)',
    difficulty: 'Medium',
    hint: 'The endpoint accepts text/plain bodies and extracts JSON from them. A cross-site form with enctype="text/plain" is a CORS simple request: no preflight, cookies attached. Make the form body contain {"email":"..."}. The same confusion applies whenever the server fills req.body from more than one content type: a plain HTML form can drive a "JSON-only" API.',
    hints: ["The API wants JSON, but it also accepts text/plain. Why does that matter for CSRF?", "text/plain POSTs are CORS 'simple requests': no preflight, cookies attached. A plain HTML form can send JSON.", "Build a form with enctype='text/plain' whose body is {\"email\":\"evil@evil.com\"} and submit it to /csrf/api/email."],
    tools: "BZ, C",
    how: 'Submit the text/plain form so its body carries a JSON email change to /csrf/api/email.',
  },
  {
    id: 'referer-bypass',
    name: 'Weak Referer Check Bypass',
    difficulty: 'Medium',
    hint: 'The check is referer.includes("pentrix.lab"). The attacker controls the referer of requests from their own page, so https://evil.com/?pentrix.lab contains the magic string.',
    hints: ["The nickname change checks the Referer header. Who controls the Referer?", "You do. The check is referer.includes('pentrix.lab'), so https://evil.com/?pentrix.lab passes.", "POST to /csrf/api/nickname with Referer: https://evil.com/?pentrix.lab."],
    tools: "C",
    how: 'POST the nickname change with a Referer header of https://evil.com/?pentrix.lab.',
  },
  {
    id: 'method-override-csrf',
    name: 'HTTP Method Override Smuggling (_method=DELETE)',
    difficulty: 'Medium',
    hint: 'The app treats DELETE as the privileged method, but honors a _method=DELETE field on a plain POST. Cross-site forms can only send GET/POST, so the override smuggles the "protected" method through with no preflight.',
    hints: ["The app honors _method=DELETE on a POST. Why is that a CSRF problem?", "Cross-site forms can only send GET/POST. The override smuggles the 'protected' DELETE through a plain POST with no preflight.", "POST the account form with _method=DELETE. The privileged path triggers."],
    tools: "BZ, C",
    how: 'POST the account form with _method=DELETE to trigger the privileged delete path.',
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
    ${fixPanel('csrf', 'email')}
    <p>Your account email is now: <code>${esc(email)}</code></p>
    ${hintBox('That request carried no token and did not even need a form submit - this is exactly what an attacker\'s forged link or image tag would have done from another site.')}
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

// v3: clickjacking target. The "dangerous" button is deliberately harmless -
// the vulnerability under test is the missing framing protection.
//
// Verification model: merely visiting /csrf/framedemo awards nothing (that was
// the old Rule 2 violation). The flag is awarded only when the server observes
// the full framing chain: (1) the framing demo issues a one-time frame token,
// (2) the victim page is actually loaded inside the frame carrying that token,
// (3) the framed form is submitted back with the token. A bare page visit or a
// bare POST with no token earns no flag.
// ---------------------------------------------------------------------------
function vipPage(message, frameToken) {
  return page('VIP Action', `
    <h1>Account Settings</h1>
    <p class="dim">This page has no <code>X-Frame-Options</code> header, so it can be embedded anywhere.</p>
    ${message || ''}
    <div style="margin-top:60px; text-align:center;">
      <form method="post" action="/csrf/vip-action">
        ${frameToken ? `<input type="hidden" name="frame" value="${esc(frameToken)}" />` : ''}
        <button type="submit" style="font-size:16px; padding:10px 24px;">Delete my account</button>
      </form>
    </div>
  `);
}

router.get('/vip-action', (req, res) => {
  // Deliberately no X-Frame-Options (and no CSP frame-ancestors): this missing
  // header is the vulnerability, so any site can frame this page.
  res.removeHeader('X-Frame-Options');
  // A frame token proves this load came through the framing demo; record it so
  // the later form submission can be tied to a real framed load.
  const f = String(req.query.frame || '');
  const frameToken = (f && req.session.frameNonce === f) ? f : null;
  if (frameToken) req.session.frameSeen = frameToken;
  res.send(vipPage('', frameToken));
});

router.post('/vip-action', (req, res) => {
  res.removeHeader('X-Frame-Options');
  const f = String(req.body.frame || '');
  // Award only when the submission carries the one-time token AND the token was
  // previously seen on a framed load of the victim page: evidence the click
  // actually landed on the framed button.
  const ok = f.length > 0 && req.session.frameNonce === f && req.session.frameSeen === f;
  if (ok) {
    req.session.frameSeen = null; // single-use: the token cannot award twice
    const flag = award(req, 'csrf', 'clickjacking');
    return res.send(vipPage(`
      <p><b>Demo only:</b> your account was <u>not</u> deleted. But the click you
      just made landed on this framed button through the attacker's overlay -
      that is a successful clickjacking.</p>
      ${flagBox(flag)}
      ${fixPanel('csrf', 'clickjacking')}
    `, null));
  }
  res.send(vipPage(`
    <p><b>Demo only:</b> your account was <u>not</u> deleted. This page exists to
    demonstrate clickjacking framing, not to do anything destructive.</p>
    <p class="dim">No flag: the flag is awarded only when this form is submitted
    from inside the framing demo (with its one-time framing token), proving a
    framed click actually happened.</p>
  `, null));
});

// ---------------------------------------------------------------------------
// Framing demo: the in-lab attacker page. It layers a decoy "prize" button
// under a nearly-invisible iframe of /csrf/vip-action, so a click on the
// decoy lands on the hidden "Delete my account" button. Visiting this page
// alone awards nothing; the flag comes from the framed submission.
// ---------------------------------------------------------------------------
router.get('/framedemo', (req, res) => {
  // VULN: the demo issues the framing token, but the token alone is worthless:
  // it only becomes evidence when the framed page loads with it and posts back.
  req.session.frameNonce = crypto.randomBytes(16).toString('hex');
  req.session.frameSeen = null;
  const nonce = req.session.frameNonce;
  res.send(page('Framing Demo', `
    <h1>Clickjacking Demo</h1>
    ${brief('What is clickjacking?', `
      <b>Clickjacking</b> tricks a user into clicking something different from
      what they think they are clicking. The attacker embeds a legitimate page in
      an invisible (or disguised) <code>&lt;iframe&gt;</code> and layers their own
      content on top. When the victim clicks the attacker's button, the click
      actually lands on the hidden page - for example on a "Delete my account"
      button.
      <br><br>The fix is a single header: <code>X-Frame-Options: DENY</code> (or
      <code>SAMEORIGIN</code>). The framed page below sends <b>neither</b>, so it
      loads fine inside the attacker's frame - that is the vulnerability.
      <br><br><b>Try it:</b> click the shiny "prize" button. It sits <i>under</i>
      a nearly-invisible iframe, so your click passes through and hits the hidden
      "Delete my account" button. The framed form carries a one-time token, and
      only that framed submission captures the flag.
    `)}
    <h2>The attacker's page (live demo)</h2>
    <div style="position:relative; width:600px; height:340px; border:2px solid #ccc; overflow:hidden; background:#fff;">
      <div style="position:absolute; left:185px; top:140px; z-index:1;">
        <button type="button" tabindex="-1" style="font-size:20px; padding:14px 28px; background:#ffd54a; border:3px solid #c90; border-radius:10px; cursor:pointer;">Claim your FREE prize</button>
      </div>
      <iframe src="/csrf/vip-action?frame=${nonce}" width="600" height="320" style="position:absolute; left:0; top:0; z-index:2; opacity:0.07; border:0;"></iframe>
    </div>
    <p class="dim">The iframe is rendered at 7% opacity - almost invisible, but the
    real "Delete my account" button is in there, sitting over your prize button.</p>
    ${hintBox('An attacker would make the iframe fully invisible and place a fake button exactly over the real one. The victim clicks "Win a prize" but hits "Delete my account".')}
    <p><a href="/csrf/vip-action">Open the framed page directly</a> (no token: submitting here earns no flag)</p>
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
    ${fixPanel('csrf', 'json-csrf')}
    <p>Your account email is now: <code>${esc(String(email))}</code></p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

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
  const flagHtml = sameOrigin ? '' : flagBox(award(req, 'csrf', 'referer-bypass')) + fixPanel('csrf', 'referer-bypass');
  res.send(page('Nickname', `
    <h1>Nickname changed</h1>
    ${flagHtml}
    <p>Nickname is now: <b>${esc(nick)}</b> (referer was <code>${esc(ref)}</code>)</p>
    <p><a href="/csrf">Back to the CSRF module</a></p>
  `));
});

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
      ${fixPanel('csrf', 'method-override-csrf')}
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
      <br><br><b>Clickjacking</b> layers the attack visually: a page that sends
      no <code>X-Frame-Options</code> header can be embedded in an invisible
      <code>&lt;iframe&gt;</code> on an attacker's site, so your clicks land on
      buttons you never saw.
    `)}
    ${trackBanner(module.exports)}
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
  name: 'CSRF & Clickjacking',
  tagline: 'Forge cross-site requests and frame the unframeable.',
  description: 'Learn how state-changing requests with no CSRF token let attackers act as you, how content-type confusion smuggles simple requests into JSON APIs, and how a missing X-Frame-Options header enables clickjacking.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['xss'],
  vulns: VULNS,
  router,
};
