// PenTrix VulnLab - CSRF & Open Redirect module (csrf)
// Intentionally vulnerable training module. Local lab use only.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();

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
      <td><a href="/csrf/${v.id === 'email' ? 'change-email' : v.id === 'redirect' ? 'go' : 'framedemo'}">Open challenge</a></td>
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
