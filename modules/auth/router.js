// Broken Authentication module for the PenTrix VulnLab.
// Eight intentionally real, exploitable auth flaws: brute-force with no rate
// limiting, predictable and deterministic password-reset tokens, username
// enumeration, OTP brute-forcing, security questions with public answers,
// password change without re-authentication, and support-ticket impersonation.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getDb } = require('../../lib/db');
const { brief, esc, fixPanel, flagBox, hintBox, hintLadder, page, toolsPill, trackBanner } = require('../../lib/page');
const { award, captured, flagFor } = require('../../lib/flags');

// VULN: the JWT signing secret is hardcoded in the source; anyone who can
// read this file can forge fully valid HS256 tokens.
const JWT_SECRET = 'pentrix-dev-secret';
const MOD = 'auth';

// ---- VULN (v3): the reset token is just base64(username) , fully predictable
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
        ? flagBox(flagFor(MOD, v.id)) + fixPanel('auth', v.id)
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
      ) + trackBanner(module.exports) + `<div class="grid">${rows}</div>
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
      extra = flagBox(award(req, MOD, 'brute-force')) + fixPanel('auth', 'brute-force');
    }
    req.session.authAttempts = 0; // counter resets on success
    req.session.authUser = username; // login identity used by the newer auth labs
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
    extra = flagBox(award(req, MOD, 'reset')) + fixPanel('auth', 'reset');
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

// ---------------------------------------------------------------- v4 user-enum
// Login identity shared by the newer auth labs.
function authSessionUser(req) {
  return req.session && req.session.authUser ? req.session.authUser : null;
}

router.get('/enum-login', (req, res) => {
  res.send(
    page(
      'Login (user enumeration)',
      brief(
        'Does this user exist?',
        `This login form answers two different questions out loud: whether the
         <b>username</b> exists, and whether the <b>password</b> is right.
         Probe usernames, watch the error messages, then submit the valid
         username you find on the <a href="/auth/enum-submit">submit page</a>.`
      ) +
        `<form method="POST" action="/auth/enum-login">
  <label>Username<br><input name="username" required></label><br><br>
  <label>Password<br><input name="password" type="password" required></label><br><br>
  <button type="submit">Log in</button>
</form>` +
        hintBox(esc(module.exports.vulns[3].hint))
    )
  );
});

router.post('/enum-login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = findUser(username);

  // VULN: the error message reveals whether the username exists, so an
  // attacker can enumerate valid accounts one probe at a time.
  if (!user) {
    return res.send(
      page(
        'Login failed',
        `<h2>Login failed</h2><p>User <b>${esc(username)}</b> not found.</p>
<p><a href="/auth/enum-login">Try again</a> · <a href="/auth/enum-submit">Submit a found username</a></p>`
      )
    );
  }
  if (user.password !== password) {
    req.session.enumFound = req.session.enumFound || [];
    if (!req.session.enumFound.includes(user.username)) {
      req.session.enumFound.push(user.username);
    }
    return res.send(
      page(
        'Login failed',
        `<h2>Login failed</h2><p>Wrong password for user <b>${esc(user.username)}</b>.</p>
<p class="dim">The username exists; only the password was wrong. That difference is the whole vulnerability.</p>
<p><a href="/auth/enum-login">Try again</a> · <a href="/auth/enum-submit">Submit a found username</a></p>`
      )
    );
  }
  req.session.authUser = user.username;
  return res.send(
    page(
      'Welcome',
      `<h2>Welcome back, ${esc(user.username)}!</h2>
<p>You are logged in for the other auth labs.</p>
<p><a href="/auth">Module index</a></p>`
    )
  );
});

router.get('/enum-submit', (req, res) => {
  res.send(
    page(
      'Submit enumerated username',
      brief(
        'Prove the enumeration',
        `Enter a username you confirmed exists through the
         <a href="/auth/enum-login">enumeration login</a>: the one that answered
         "wrong password" instead of "user not found".`
      ) +
        `<form method="POST" action="/auth/enum-submit">
  <label>Enumerated username<br><input name="username" required></label><br><br>
  <button type="submit">Submit</button>
</form>` +
        hintBox(esc(module.exports.vulns[3].hint))
    )
  );
});

router.post('/enum-submit', (req, res) => {
  const username = String(req.body.username || '').trim();
  const found =
    (req.session.enumFound || []).includes(username) && findUser(username);
  let extra = '';
  if (found) extra = flagBox(award(req, MOD, 'user-enum')) + fixPanel('auth', 'user-enum');
  res.send(
    page(
      'Enumeration result',
      `<h2>Enumeration result</h2>
<p>${
        found
          ? `Username <b>${esc(username)}</b> confirmed through the login oracle.`
          : `Nope. <b>${esc(username)}</b> was not enumerated through the login form in this session.`
      }</p>
${extra}
<p><a href="/auth/enum-login">Back to the login</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v6 otp-bruteforce
function ensureAuthOtpTable() {
  getDb().exec(`CREATE TABLE IF NOT EXISTS auth_otp (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    otp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
}
ensureAuthOtpTable();

router.get('/otp-reset', (req, res) => {
  const admin = findUser('admin');
  const token = crypto.randomBytes(16).toString('hex');
  const otp = String(Math.floor(Math.random() * 10000)).padStart(4, '0');
  getDb()
    .prepare('INSERT INTO auth_otp (token, user_id, otp) VALUES (?,?,?)')
    .run(token, admin.id, otp);

  res.send(
    page(
      'Admin password reset (OTP)',
      brief(
        'Four digits stand between you and admin',
        `A password-reset SMS was "sent" to the admin's phone with a <b>4-digit
         code</b>. The scenario hands you the reset <b>token</b> below, but never
         the code. There is <b>no rate limiting</b> on the verify endpoint, so
         all 10,000 codes are fair game. Script it.`
      ) +
        `<div class="card">
<p>Your reset token for <b>admin</b>:</p>
<pre class="token">${esc(token)}</pre>
</div>
<form method="POST" action="/auth/otp-reset/verify">
  <label>Reset token<br><input name="token" value="${esc(token)}" size="40" required></label><br><br>
  <label>4-digit code<br><input name="otp" pattern="[0-9]{4}" required></label><br><br>
  <label>New password<br><input name="newPassword" type="password" required></label><br><br>
  <button type="submit">Verify and reset</button>
</form>` +
        hintBox(esc(module.exports.vulns[5].hint))
    )
  );
});

router.post('/otp-reset/verify', (req, res) => {
  const token = String(req.body.token || '').trim();
  const otp = String(req.body.otp || '').trim();
  const newPassword = String(req.body.newPassword || '');
  const row = getDb().prepare('SELECT * FROM auth_otp WHERE token = ?').get(token);

  if (!row) {
    return res.send(
      page(
        'OTP failed',
        `<h2>Reset failed</h2><p>Unknown reset token.</p>
<p><a href="/auth/otp-reset">Get a token</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  // VULN: a 4-digit code with no rate limiting, no lockout and no expiry is
  // brute-forceable; the token alone was never meant to be the only secret.
  if (row.otp !== otp) {
    return res.send(
      page(
        'OTP failed',
        `<h2>Wrong code</h2>
<p>The code <b>${esc(otp)}</b> did not match. No lockout, no delay. Try the next one.</p>
<p><a href="/auth/otp-reset">Back</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  const user = getDb().prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
  getDb().prepare('UPDATE users SET password = ? WHERE id = ?').run(newPassword, row.user_id);
  getDb().prepare('DELETE FROM auth_otp WHERE token = ?').run(token);

  const extra = flagBox(award(req, MOD, 'otp-bruteforce')) + fixPanel('auth', 'otp-bruteforce');
  res.send(
    page(
      'Password reset',
      `<h2>Password changed</h2>
<p>The password for <b>${esc(user.username)}</b> was reset with a brute-forced OTP.</p>
${extra}
<p><a href="/auth/login">Log in as admin</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v7 reset-predictable
// VULN: the reset token is a deterministic hash of public data, so anyone who
// knows the recipe can mint a valid token for any account.
function shaResetToken(username) {
  return crypto.createHash('sha256').update(username + 'reset-salt', 'utf8').digest('hex');
}

router.get('/sha-reset', (req, res) => {
  const user = String(req.query.user || '').trim();
  let result = '';

  if (user) {
    const u = findUser(user);
    if (u) {
      const token = shaResetToken(u.username);
      req.session.shaIssued = req.session.shaIssued || [];
      if (!req.session.shaIssued.includes(u.username)) {
        req.session.shaIssued.push(u.username);
      }
      const link = `/auth/sha-reset/confirm?token=${encodeURIComponent(token)}`;
      result = `<div class="card">
<p>Reset link "emailed" to <b>${esc(u.email)}</b>:</p>
<p><a href="${esc(link)}">${esc(link)}</a></p>
<pre class="token">${esc(token)}</pre>
</div>`;
    } else {
      result = `<p>No account for user <b>${esc(user)}</b>.</p>`;
    }
  }

  res.send(
    page(
      'Password reset (v2)',
      brief(
        'Read the source, mint the token',
        `This reset flow builds its token in code you can read right here:
         <code>sha256(username + 'reset-salt')</code>. Nothing random, nothing
         secret. Request a reset for alice to see the shape, then forge one for
         admin yourself and confirm it.`
      ) +
        `<p class="dim">Token recipe (straight from the app source):</p>
<pre><code>crypto.createHash('sha256').update(username + 'reset-salt').digest('hex')</code></pre>
<form method="GET" action="/auth/sha-reset">
  <label>Username<br><input name="user" value="${esc(user || 'alice')}" required></label>
  <button type="submit">Send reset link</button>
</form><br>` +
        result +
        hintBox(esc(module.exports.vulns[6].hint))
    )
  );
});

router.get('/sha-reset/confirm', (req, res) => {
  const token = String(req.query.token || '');
  res.send(
    page(
      'Set a new password',
      `<h2>Set a new password</h2>
<form method="POST" action="/auth/sha-reset/confirm">
  <label>Reset token<br><input name="token" value="${esc(token)}" size="70" required></label><br><br>
  <label>New password<br><input name="newPassword" type="password" required></label><br><br>
  <button type="submit">Change password</button>
</form>`
    )
  );
});

router.post('/sha-reset/confirm', (req, res) => {
  const token = String(req.body.token || '').trim();
  const newPassword = String(req.body.newPassword || '');

  if (!token || !newPassword) {
    return res.send(
      page(
        'Reset failed',
        `<h2>Reset failed</h2><p>Token and new password are both required.</p>
<p><a href="/auth/sha-reset">Try again</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  const users = getDb().prepare('SELECT username FROM users').all();
  const target = users.find((u) => shaResetToken(u.username) === token);
  if (!target) {
    return res.send(
      page(
        'Reset failed',
        `<h2>Reset failed</h2><p>This token does not map to an account.</p>
<p><a href="/auth/sha-reset">Try again</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  getDb()
    .prepare('UPDATE users SET password = ? WHERE username = ?')
    .run(newPassword, target.username);

  // Award when admin's password was changed with a token this session never
  // legitimately received, i.e. a forged one.
  let extra = '';
  const issued = req.session.shaIssued || [];
  if (target.username === 'admin' && !issued.includes('admin')) {
    extra = flagBox(award(req, MOD, 'reset-predictable')) + fixPanel('auth', 'reset-predictable');
  }

  res.send(
    page(
      'Password changed',
      `<h2>Password changed</h2>
<p>The password for user <b>${esc(target.username)}</b> was updated.</p>
${extra}
<p class="dim">Token used: <code>${esc(token)}</code></p>
<p><a href="/auth/login">Log in</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v8 security-question
const MAIDEN_NAMES = { alice: 'Smith', bob: 'Jones', admin: 'Blackwood' };
const PUBLIC_BIOS = {
  alice:
    "Alice loves CTFs and sticker packs. A fun fact she tells everyone at meetups: her mother's maiden name is Smith.",
  bob:
    'Bob collects USB rubber duckies (training ones only). His go-to party story involves his mother\'s maiden name: Jones.',
  admin:
    'The admin keeps this lab running. Ancient forum posts mention the family name Blackwood more than once.',
};

router.get('/bio/:username', (req, res) => {
  const name = String(req.params.username || '').toLowerCase();
  const u = findUser(name);
  if (!u || !PUBLIC_BIOS[name]) {
    return res.status(404).send(
      page('Not found', `<h2>404</h2><p>No public bio for that user.</p>
<p><a href="/auth/question-reset">Password reset</a> · <a href="/auth">Module index</a></p>`)
    );
  }
  res.send(
    page(
      `${u.username}'s bio`,
      `<h2>${esc(u.username)}'s public bio</h2>
<p>${esc(PUBLIC_BIOS[name])}</p>
<p class="dim">Other bios: <a href="/auth/bio/alice">alice</a> ·
<a href="/auth/bio/bob">bob</a> · <a href="/auth/bio/admin">admin</a></p>
<p><a href="/auth/question-reset">Password reset via security question</a> ·
<a href="/auth">Module index</a></p>`
    )
  );
});

router.get('/question-reset', (req, res) => {
  res.send(
    page(
      'Reset via security question',
      brief(
        'What was her maiden name?',
        `Forgot your password? Just answer the security question: <b>what is
         your mother's maiden name?</b> The answers are not secret at all:
         people print them in their <a href="/auth/bio/alice">public bios</a>.`
      ) +
        `<form method="POST" action="/auth/question-reset">
  <label>Username<br><input name="username" value="alice" required></label><br><br>
  <label>Mother's maiden name<br><input name="answer" required></label><br><br>
  <label>New password<br><input name="newPassword" type="password" required></label><br><br>
  <button type="submit">Reset password</button>
</form>` +
        hintBox(esc(module.exports.vulns[7].hint))
    )
  );
});

router.post('/question-reset', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const answer = String(req.body.answer || '').trim();
  const newPassword = String(req.body.newPassword || '');
  const u = findUser(username);

  // VULN: the "secret" answer is public knowledge (printed in the user's bio),
  // so the security question is not authentication at all.
  if (
    !u ||
    !newPassword ||
    (MAIDEN_NAMES[username] || '').toLowerCase() !== answer.toLowerCase()
  ) {
    return res.send(
      page(
        'Reset failed',
        `<h2>Reset failed</h2><p>Wrong answer to the security question.</p>
<p><a href="/auth/question-reset">Try again</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  getDb().prepare('UPDATE users SET password = ? WHERE username = ?').run(newPassword, u.username);
  const extra = flagBox(award(req, MOD, 'security-question')) + fixPanel('auth', 'security-question');
  res.send(
    page(
      'Password changed',
      `<h2>Password changed</h2>
<p>The password for <b>${esc(u.username)}</b> was reset with a public "secret".</p>
${extra}
<p><a href="/auth/login">Log in</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v9 change-pass-noverify
router.get('/change-password', (req, res) => {
  const me = authSessionUser(req);
  if (!me) {
    return res.send(
      page(
        'Change password',
        `<h2>Log in first</h2>
<p><a href="/auth/login">Log in</a>, then come back here.</p>`
      )
    );
  }
  res.send(
    page(
      'Change password',
      brief(
        'No current password asked',
        `You are logged in as <b>${esc(me)}</b>. This form sets a new password
         <b>without ever asking for the current one</b>. Anyone with brief access
         to your session owns the account.`
      ) +
        `<form method="POST" action="/auth/change-password">
  <label>New password<br><input name="newPassword" type="password" required></label><br><br>
  <button type="submit">Change password</button>
</form>` +
        hintBox(esc(module.exports.vulns[8].hint))
    )
  );
});

router.post('/change-password', (req, res) => {
  const me = authSessionUser(req);
  if (!me) {
    return res.status(401).send(
      page('Denied', `<h2>401</h2><p>Log in first.</p>
<p><a href="/auth/login">Log in</a> · <a href="/auth">Module index</a></p>`)
    );
  }
  const newPassword = String(req.body.newPassword || '');
  if (!newPassword) {
    return res.send(
      page(
        'Change failed',
        `<h2>Change failed</h2><p>A new password is required.</p>
<p><a href="/auth/change-password">Try again</a></p>`
      )
    );
  }

  // VULN: changing the password needs only an active session, never the
  // current password, so an unattended or hijacked session is enough to take
  // over the account.
  getDb().prepare('UPDATE users SET password = ? WHERE username = ?').run(newPassword, me);
  const extra = flagBox(award(req, MOD, 'change-pass-noverify')) + fixPanel('auth', 'change-pass-noverify');
  res.send(
    page(
      'Password changed',
      `<h2>Password changed</h2>
<p>The password for <b>${esc(me)}</b> was changed without the old one.</p>
${extra}
<p><a href="/auth">Module index</a></p>`
    )
  );
});

// ---------------------------------------------------------------- v10 support-impersonate
function ensureSupportTickets() {
  const db = getDb();
  db.exec(`CREATE TABLE IF NOT EXISTS auth_support_tickets (
    ticket INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    subject TEXT NOT NULL
  )`);
  const count = db.prepare('SELECT COUNT(*) AS c FROM auth_support_tickets').get().c;
  if (count === 0) {
    const idOf = (n) => db.prepare('SELECT id FROM users WHERE username = ?').get(n).id;
    const ins = db.prepare('INSERT INTO auth_support_tickets (ticket, user_id, subject) VALUES (?,?,?)');
    ins.run(1001, idOf('alice'), 'Password reset help');
    ins.run(1002, idOf('bob'), 'Locked out of account');
    ins.run(1003, idOf('alice'), 'Billing question');
    ins.run(1004, idOf('bob'), 'API access request');
    ins.run(1005, idOf('admin'), 'Urgent: admin account recovery');
  }
}
ensureSupportTickets();

router.get('/support', (req, res) => {
  res.send(
    page(
      'Support login',
      brief(
        'Support staff portal',
        `Support agents paste a <b>ticket number</b> to jump straight into the
         customer's session. Ticket numbers are <b>sequential</b>, and this page
         never checks whether <i>you</i> are support staff. Recent tickets sit
         in the 1001-1005 range...`
      ) +
        `<form method="GET" action="/auth/support/login">
  <label>Ticket number<br><input name="ticket" value="1001" required></label><br><br>
  <button type="submit">Impersonate customer</button>
</form>` +
        hintBox(esc(module.exports.vulns[9].hint))
    )
  );
});

router.get('/support/login', (req, res) => {
  const n = parseInt(req.query.ticket, 10);
  const row = Number.isNaN(n)
    ? null
    : getDb()
        .prepare(
          `SELECT t.ticket, t.subject, u.username, u.role
           FROM auth_support_tickets t JOIN users u ON u.id = t.user_id
           WHERE t.ticket = ?`
        )
        .get(n);

  if (!row) {
    return res.send(
      page(
        'Bad ticket',
        `<h2>Unknown ticket</h2>
<p>No ticket <b>${esc(req.query.ticket || '')}</b>. Tickets are sequential, keep guessing.</p>
<p><a href="/auth/support">Back</a> · <a href="/auth">Module index</a></p>`
      )
    );
  }

  // VULN: predictable sequential ticket ids plus zero authorization on the
  // support endpoint means anyone can impersonate any customer, even admin.
  req.session.authUser = row.username;
  let extra = '';
  if (row.role === 'admin') {
    extra = flagBox(award(req, MOD, 'support-impersonate')) + fixPanel('auth', 'support-impersonate');
  }
  res.send(
    page(
      'Support impersonation',
      `<h2>Impersonating ${esc(row.username)}</h2>
<p>Ticket <b>${n}</b> (${esc(row.subject)}) accepted. You are now logged in as
<b>${esc(row.username)}</b> (role <b>${esc(row.role)}</b>).</p>
${extra}
<p><a href="/auth/settings">Open settings as them</a> · <a href="/auth">Module index</a></p>`
    )
  );
});

module.exports = {
  id: MOD,
  name: 'Broken Authentication',
  tagline: 'No lockouts, predictable resets, and OTPs anyone can brute-force.',
  description:
    'Authentication the way it happens when nobody threat-models: a login page that lets you guess forever, password reset tokens anyone can predict, and one-time codes with no lockout.',
  difficulty: 'Intermediate',
  track: 'Auth and Sessions',
  prerequisites: ['Foundations track'],
  vulns: [
    {
      id: 'brute-force',
      name: 'No Rate Limiting (Brute-Force Login)',
      difficulty: 'Medium',
      hint: 'There is no rate limiting, no lockout, and no CAPTCHA. Alice\'s password is very weak. If a few tries don\'t work, script it: the counter resets only on success, and the flag lands when you finally log in as alice after at least 5 failed attempts in the same session.',
      hints: ["The login has no rate limit, no lockout, no CAPTCHA. What does that mean for password guessing?", "Without throttling, you can try thousands of passwords. Alice's password is weak and guessable.", "Script the login attempts (or guess manually). The flag lands when you log in as alice after 5+ failed attempts in one session."],
      tools: "B, P",
      how: 'Brute-force / guess alice\'s weak password; the flag is awarded once you log in as alice after 5+ failed attempts in one session.',
      link: '/auth/login',
    },
    {
      id: 'reset',
      name: 'Predictable Password Reset Tokens',
      difficulty: 'Easy',
      hint: 'The reset link is displayed on screen and the token is just base64(username). Request a reset for alice to see the pattern, then mint a token for admin yourself and confirm it with a new password.',
      hints: ["The password reset asks for a username and gives you a token. What does the token look like?", "The token is just base64(username) with no randomness. Anyone can compute it for any user.", "Request a reset for admin, decode the pattern (base64 of 'admin'), forge the token, and set a new password."],
      tools: "B, C",
      how: 'Forge a reset token for admin (base64 of "admin") and use it at /auth/reset/confirm to change admin\'s password.',
      link: '/auth/reset',
    },
    {
      id: 'user-enum',
      name: 'Username Enumeration',
      difficulty: 'Easy',
      hint: 'The login says "user not found" for bad usernames but "wrong password" for real ones. Probe names like alice, bob, admin, or anything else, then submit the confirmed username on the submit page.',
      hints: ["Try logging in with a wrong username vs a wrong password. Does the error message change?", "Different errors for 'bad username' vs 'bad password' reveal which usernames exist. That's an oracle.", "Enumerate usernames by comparing error messages, then submit a valid one."],
      tools: "B, C",
      how: 'Enumerate a valid username through the different error messages and submit it.',
      link: '/auth/enum-login',
    },
    {
      id: 'otp-bruteforce',
      name: 'Brute-Forcing a 4-Digit OTP',
      difficulty: 'Medium',
      hint: 'You get a valid reset token for admin on screen, but the 4-digit code is never shown and there is no rate limiting. Script all 10,000 codes against the verify endpoint.',
      hints: ["The OTP is 4 digits. How many possibilities is that, and is there any lockout?", "10,000 codes, no lockout, no expiry. A simple Python loop trying 0000-9999 will hit it.", "Script POSTs to the verify endpoint with codes 0000-9999 until one works."],
      tools: "P, C",
      how: 'Brute-force the 4-digit OTP for the given admin reset token, then reset the password.',
      link: '/auth/otp-reset',
    },
    {
      id: 'reset-predictable',
      name: 'SHA-256 Predictable Reset Token',
      difficulty: 'Medium',
      hint: 'The page shows the exact recipe: sha256(username + "reset-salt"). Compute it for "admin" with node or python and confirm the forged token without ever requesting an admin reset.',
      hints: ["The reset token is a SHA-256 hash. Hash of what? What inputs are predictable?", "The token is SHA-256(username + a public value like the date). Both are known or guessable, so you can recompute it.", "Compute SHA-256(admin + today's date) in Python, use it as the reset token."],
      tools: "B, P",
      how: 'Forge the admin reset token with SHA-256 and use it to change admin\'s password.',
      link: '/auth/sha-reset',
    },
    {
      id: 'security-question',
      name: 'Guessable Security Question',
      difficulty: 'Easy',
      hint: 'The reset asks for the mother\'s maiden name, and alice printed hers in her public bio. Read the bio, answer the question, reset her password.',
      hints: ["The security question asks for something 'only you know'. But the user's bio is public. What does the bio say?", "The 'secret' answer is in the public bio. Security questions are just weak passwords when the answer is public.", "Read the bio, answer the question with the public info, and reset the password."],
      tools: "B",
      how: 'Read alice\'s public bio for the maiden name, then reset her password via the security question.',
      link: '/auth/question-reset',
    },
    {
      id: 'change-pass-noverify',
      name: 'Password Change Without Current Password',
      difficulty: 'Easy',
      hint: 'Log in as anyone through /auth/login, then open the change-password page and notice it never asks for the current password.',
      hints: ["You're logged in and want to change your password. Does it ask for the current one?", "The change-password endpoint only checks your session, not your current password. Anyone with session access (XSS, shared computer) can set a new password.", "While logged in, POST a new password to /auth/change-password without the old one."],
      tools: "B",
      how: 'While logged in, change the account password without knowing the current one.',
      link: '/auth/change-password',
    },
    {
      id: 'support-impersonate',
      name: 'Support Ticket Impersonation',
      difficulty: 'Medium',
      hint: 'Tickets are sequential (try 1001 upward). One of them belongs to admin. The support endpoint never checks that you are staff.',
      hints: ["Support tickets have sequential IDs. What happens if you open someone else's ticket?", "Ticket IDs are predictable and there's no authorization check. Enumerate to the admin's ticket to get their session.", "Fetch /auth/support/ticket/1, /ticket/2, ... until you find the admin's session token."],
      tools: "B, C",
      how: 'Enumerate ticket numbers at /auth/support/login until you land an admin session.',
      link: '/auth/support',
    },
  ],
  router,
};
