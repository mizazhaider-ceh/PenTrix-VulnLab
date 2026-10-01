// Broken Authentication module for the PenTrix VulnLab.
// Three intentionally real, exploitable auth flaws:
//   v1 brute-force: login with no rate limiting and a weak password
//   v2 jwt-none:    verification that accepts unsigned (alg=none) JWTs
//   v3 reset:       predictable password-reset tokens displayed on screen
const express = require('express');
const jwt = require('jsonwebtoken');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

// VULN: the JWT signing secret is hardcoded in the source; anyone who can
// read this file can forge fully valid HS256 tokens.
const JWT_SECRET = 'pentrix-dev-secret';
const MOD = 'auth';

// ---- VULN (v3): the reset token is just base64(username) — fully predictable
// and handed out without any email verification.
function resetTokenFor(username) {
  return Buffer.from(username, 'utf8').toString('base64');
}

function findUser(username) {
  return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

const router = express.Router();

// ---------------------------------------------------------------- index
router.get('/', (req, res) => {
  const rows = module.exports.vulns
    .map((v) => {
      const flag = captured(req, MOD, v.id)
        ? flagBox(`PENTRIX{${MOD}_${v.id}}`)
        : '';
      return `<article class="card">
  <h3>${esc(v.name)} <span class="badge">${esc(v.difficulty)}</span></h3>
  <p><i>${esc(v.how)}</i></p>
  ${hintBox(esc(v.hint))}
  ${flag}
  <p><a class="btn" href="${esc(v.link)}">Open challenge</a></p>
</article>`;
    })
    .join('\n');

  res.send(
    page(
      'Broken Authentication',
      brief(
        'Broken Authentication',
        `Weak credentials, no lockouts, unsigned JWTs, and password resets that leak
         their own tokens. This module is intentionally broken so you can break it.
         Each challenge page has a form you can attack directly.`
      ) + `<div class="grid">${rows}</div>
<p><a href="/">Back to all modules</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v1 brute-force
router.get('/login', (req, res) => {
  const attempts = req.session.authAttempts || 0;
  res.send(
    page(
      'Login (vulnerable)',
      brief(
        'Brute-force the login',
        `This login has <b>no rate limiting, no lockout, and no CAPTCHA</b>.
         Try as many passwords as you like. Alice's password is weak and guessable.`
      ) +
        `<p class="dim">Failed attempts this session: <b>${attempts}</b></p>` +
        `<form method="POST" action="/auth/login">
  <label>Username<br><input name="username" value="alice" required></label><br><br>
  <label>Password<br><input name="password" type="password" required></label><br><br>
  <button type="submit">Log in</button>
</form>` +
        hintBox(esc(module.exports.vulns[0].hint))
    )
  );
});

router.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = findUser(username);
  const attempts = req.session.authAttempts || 0;

  if (user && user.password === password) {
    // VULN: no rate limiting or account lockout, and the server happily
    // reports how many failed attempts preceded a success.
    let extra = '';
    if (username === 'alice' && attempts >= 5) {
      extra = flagBox(award(req, MOD, 'brute-force'));
    }
    req.session.authAttempts = 0; // counter resets on success
    return res.send(
      page(
        'Welcome',
        `<h2>Welcome back, ${esc(user.username)}!</h2>
<p>Role: <b>${esc(user.role)}</b>. You logged in after <b>${attempts}</b> failed
attempt(s) this session.</p>
${extra}
<p><a href="/auth/login">Back to login</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  req.session.authAttempts = attempts + 1;
  return res.send(
    page(
      'Login failed',
      `<h2>Login failed</h2>
<p>Invalid username or password. Failed attempts this session:
<b>${req.session.authAttempts}</b></p>
<p class="dim">Keep trying, there is nothing stopping you.</p>
<p><a href="/auth/login">Try again</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v2 jwt-none
router.get('/jwt-login', (req, res) => {
  res.send(
    page(
      'JWT login',
      brief(
        'JWT admin panel',
        `Log in to receive a signed JWT (<code>HS256</code>), then try to reach
         the <a href="/auth/jwt-admin">admin page</a> as an admin.
         The verifier on the admin page is not picky about algorithms...`
      ) +
        `<form method="POST" action="/auth/jwt-login">
  <label>Username<br><input name="username" value="bob" required></label><br><br>
  <label>Password<br><input name="password" type="password" required></label><br><br>
  <button type="submit">Get JWT</button>
</form>` +
        hintBox(esc(module.exports.vulns[1].hint))
    )
  );
});

router.post('/jwt-login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = findUser(username);

  if (!user || user.password !== password) {
    return res.send(
      page(
        'JWT login failed',
        `<h2>Login failed</h2><p>Bad credentials.</p>
<p><a href="/auth/jwt-login">Try again</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  const token = jwt.sign({ user: user.username, role: user.role }, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '1h',
  });

  res.send(
    page(
      'Your JWT',
      `<h2>Your JWT</h2>
<p>Logged in as <b>${esc(user.username)}</b> (role <b>${esc(user.role)}</b>).</p>
<p>Paste it into an <code>Authorization: Bearer &lt;token&gt;</code> header when
visiting the <a href="/auth/jwt-admin">admin page</a>:</p>
<pre class="token">${esc(token)}</pre>
<p class="dim">Tip: you can decode the payload at the dots; the server re-verifies it.</p>
<p><a href="/auth/jwt-admin">Go to the admin page</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

function tokenFromRequest(req) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : req.query.token || '';
}

router.get('/jwt-admin', (req, res) => {
  const token = tokenFromRequest(req);
  if (!token) {
    return res.status(401).send(
      page(
        'Admin only',
        `<h2>401 — Admins only</h2>
<p>You need a JWT with <code>role: "admin"</code>. Bring one as
<code>Authorization: Bearer &lt;token&gt;</code> or <code>?token=...</code>.</p>
<p><a href="/auth/jwt-login">Get a token</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  let payload, header;
  try {
    // VULN: when the token's header declares {"alg":"none"}, the signature is
    // skipped entirely and the payload is trusted as-is. (jsonwebtoken 9.x
    // refuses unsigned tokens whenever a secret is passed to verify(), so the
    // flaw is expressed as the classic branch: none-alg tokens never reach
    // verify() at all.)
    header = jwt.decode(token, { complete: true })?.header;
    if (!header) throw new Error('malformed token');
    payload =
      header.alg === 'none'
        ? jwt.decode(token)
        : jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch (e) {
    return res.status(401).send(
      page(
        'Bad token',
        `<h2>401 — Invalid token</h2><p>${esc(e.message)}</p>
<p><a href="/auth/jwt-login">Get a token</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  if (payload.role !== 'admin') {
    return res.status(403).send(
      page(
        'Forbidden',
        `<h2>403 — Admins only</h2>
<p>Your token is valid, but its role is
<b>${esc(String(payload.role))}</b>, not admin.</p>
<p><a href="/auth/jwt-login">Get a token</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  // Award only when the admin page is reached with an *unsigned* alg=none token.
  let extra = '';
  if (header.alg === 'none' && payload.role === 'admin') {
    extra = flagBox(award(req, MOD, 'jwt-none'));
  }

  res.send(
    page(
      'Admin panel',
      `<h2>Admin panel</h2>
<p>Welcome, administrator <b>${esc(String(payload.user))}</b>.</p>
<p>Token algorithm seen by the verifier: <code>${esc(String(header.alg))}</code></p>
${extra}
<p class="dim">Seeding secret for later modules: <code>${esc(
      findUser('admin')?.secret || ''
    )}</code></p>
<p><a href="/auth">Module index</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v3 reset
router.get('/reset', (req, res) => {
  const user = String(req.query.user || '').trim();
  let result = '';

  if (user) {
    const u = findUser(user);
    if (u) {
      const token = resetTokenFor(u.username);
      req.session.issuedResets = req.session.issuedResets || [];
      if (!req.session.issuedResets.includes(token)) {
        req.session.issuedResets.push(token);
      }
      // VULN: the "email" with the reset link is rendered right here on the
      // page for anyone to read, and the token is trivially predictable.
      const link = `/auth/reset/confirm?token=${encodeURIComponent(token)}`;
      result = `<div class="card">
<p>An email was "sent" to <b>${esc(u.email)}</b>. The lab has no mail server,
so here is the reset link on screen instead:</p>
<p><a href="${esc(link)}">${esc(link)}</a></p>
<pre class="token">${esc(token)}</pre>
<p class="dim">The token is just base64 of the username. Convenient.</p>
</div>`;
    } else {
      result = `<p>No account for user <b>${esc(user)}</b>.</p>`;
    }
  }

  res.send(
    page(
      'Password reset',
      brief(
        'Forgot your password?',
        `Enter a username and we will "email" a reset link. This demo shows the
         link on screen, no email required.`
      ) +
        `<form method="GET" action="/auth/reset">
  <label>Username<br><input name="user" value="${esc(user || 'alice')}" required></label>
  <button type="submit">Send reset link</button>
</form><br>` +
        result +
        hintBox(esc(module.exports.vulns[2].hint))
    )
  );
});

router.get('/reset/confirm', (req, res) => {
  const token = String(req.query.token || '');
  res.send(
    page(
      'Set a new password',
      `<h2>Set a new password</h2>
<form method="POST" action="/auth/reset/confirm">
  <label>Reset token<br><input name="token" value="${esc(token)}" required></label><br><br>
  <label>New password<br><input name="newPassword" type="password" required></label><br><br>
  <button type="submit">Change password</button>
</form>
<p class="dim">No identity check here: whoever holds a token can set the password
for the account it decodes to.</p>`
    )
  );
});

router.post('/reset/confirm', (req, res) => {
  const token = String(req.body.token || '').trim();
  const newPassword = String(req.body.newPassword || '');

  if (!token || !newPassword) {
    return res.send(
      page(
        'Reset failed',
        `<h2>Reset failed</h2><p>Token and new password are both required.</p>
<p><a href="/auth/reset">Try again</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  let username;
  try {
    // VULN: any base64-decodable string is treated as a token, and it maps
    // straight onto an account. No signature, no expiry, no binding.
    username = Buffer.from(token, 'base64').toString('utf8');
  } catch (e) {
    username = null;
  }

  const user = username ? findUser(username) : null;
  if (!user) {
    return res.send(
      page(
        'Reset failed',
        `<h2>Reset failed</h2><p>This token does not map to an account.</p>
<p><a href="/auth/reset">Try again</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  const issued = req.session.issuedResets || [];
  const wasLegit = issued.includes(token);
  getDb()
    .prepare('UPDATE users SET password = ? WHERE username = ?')
    .run(newPassword, user.username);

  // Award when a password was changed with a token this session never issued
  // (i.e. a forged / guessed token), the classic outcome being admin's password.
  let extra = '';
  if (!wasLegit) {
    extra = flagBox(award(req, MOD, 'reset'));
  }

  res.send(
    page(
      'Password changed',
      `<h2>Password changed</h2>
<p>The password for user <b>${esc(user.username)}</b> was updated.</p>
${extra}
<p class="dim">Original token: <code>${esc(token)}</code></p>
<p><a href="/auth/login">Log in with it</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

module.exports = {
  id: MOD,
  name: 'Broken Authentication',
  tagline: 'No lockouts, unsigned JWTs, and reset tokens anyone can guess.',
  description:
    'Authentication the way it happens when nobody threat-models: a login page that lets you guess forever, a JWT verifier that trusts the word "none", and a password reset flow that hands you the keys on screen.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'brute-force',
      name: 'No Rate Limiting (Brute-Force Login)',
      difficulty: 'Medium',
      hint: 'There is no rate limiting, no lockout, and no CAPTCHA. Alice\'s password is very weak. If a few tries don\'t work, script it: the counter resets only on success, and the flag lands when you finally log in as alice after at least 5 failed attempts in the same session.',
      how: 'Brute-force / guess alice\'s weak password; the flag is awarded once you log in as alice after 5+ failed attempts in one session.',
      link: '/auth/login',
    },
    {
      id: 'jwt-none',
      name: 'JWT Algorithm Confusion (alg=none)',
      difficulty: 'Medium',
      hint: 'The verifier explicitly allows the "none" algorithm. Take a valid token, swap the header to {"alg":"none"}, drop the signature, set role to "admin", and visit the admin page with it.',
      how: 'Forge an unsigned JWT with {"alg":"none"} claiming role admin and present it at /auth/jwt-admin.',
      link: '/auth/jwt-login',
    },
    {
      id: 'reset',
      name: 'Predictable Password Reset Tokens',
      difficulty: 'Easy',
      hint: 'The reset link is displayed on screen and the token is just base64(username). Request a reset for alice to see the pattern, then mint a token for admin yourself and confirm it with a new password.',
      how: 'Forge a reset token for admin (base64 of "admin") and use it at /auth/reset/confirm to change admin\'s password.',
      link: '/auth/reset',
    },
  ],
  router,
};
