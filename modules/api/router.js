// API Security Flaws module: intentionally vulnerable JSON API training targets.
const express = require('express');
const { getDb } = require('../../lib/db');
const { brief, esc, fixPanel, flagBox, hintBox, hintLadder, page, toolsPill, trackBanner } = require('../../lib/page');
const { award, captured, flagFor } = require('../../lib/flags');

const router = express.Router();

// VULN: brute-force counter lives in memory and is never enforced, so an
// attacker can hammer POST /api/login without lockout or slowdown.
const attempts = {};

// ---------- extra tables for the batch-02 labs (prefixed, self-contained) ----------
function apiExtraTables() {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS api_profiles (
      user_id INTEGER PRIMARY KEY,
      display_name TEXT NOT NULL DEFAULT '',
      bio TEXT NOT NULL DEFAULT '',
      is_admin INTEGER NOT NULL DEFAULT 0,
      api_secret TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS api_invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      description TEXT NOT NULL,
      amount REAL NOT NULL
    );
  `);
  const insP = db.prepare('INSERT OR IGNORE INTO api_profiles (user_id, display_name, bio, api_secret) VALUES (?,?,?,?)');
  insP.run(2, 'alice', 'Bug hunter in training', 'ak_live_alice_9f2c41');
  insP.run(3, 'bob', 'Just here for the stickers', 'ak_live_bob_77d0be');
  if (db.prepare('SELECT COUNT(*) AS c FROM api_invoices').get().c === 0) {
    const insI = db.prepare('INSERT INTO api_invoices (user_id, description, amount) VALUES (?,?,?)');
    insI.run(2, 'PenTrix Hoodie order', 39.99);
    insI.run(3, 'Sticker Pack order', 4.99);
  }
}
apiExtraTables();

// Rate-limit state for POST /api/v1/login, keyed by claimed client IP.
const v1LoginAttempts = {};

function requireLogin(req, res) {
  const user = req.session.user;
  if (!user) {
    res.status(401).json({ ok: false, error: 'Not logged in. Use GET /api/login/alice first.' });
    return null;
  }
  return user;
}

function userTable() {
  return getDb().prepare('SELECT * FROM users').all();
}

// GET /api/login/alice -> quick-login as alice (id 2) for lab convenience.
router.get('/login/alice', (req, res) => {
  req.session.user = { id: 2, username: 'alice', role: 'user' };
  res.json({ ok: true, loggedInAs: 'alice', id: 2 });
});

// PATCH /api/me -> v1 mass assignment. Every key in the JSON body is written
// straight into the users row of the logged-in user.
router.patch('/me', (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ ok: false, error: 'Not logged in. Use GET /api/login/alice first.' });

  const body = req.body || {};
  const keys = Object.keys(body);
  if (keys.length === 0) return res.status(400).json({ ok: false, error: 'Empty JSON body.' });

  const db = getDb();
  // VULN: mass assignment, no allowlist. Client-controlled keys (even "role"
  // or "id") become columns in the UPDATE, so privilege escalation is trivial.
  const setClause = keys.map((k) => `"${k}" = ?`).join(', ');
  const values = keys.map((k) => body[k]);
  db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, user.id);

  const updated = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(user.id);
  let flag = null;
  if (updated && updated.role === 'admin') {
    flag = award(req, 'api', 'mass-assignment');
  }
  res.json({ ok: true, user: updated, flag });
});

// GET /api/users -> v2 excessive data exposure. Full user rows leak out.
router.get('/users', (req, res) => {
  const rows = userTable();
  const json = JSON.stringify(rows);
  if (json.includes('"password"')) {
    const flag = award(req, 'api', 'exposure');
    res.set('X-Pentrix-Flag', flag);
  }
  res.json(rows);
});

// GET /api/users/view -> browser-friendly rendering of the same leaky endpoint.
router.get('/users/view', (req, res) => {
  const rows = userTable();
  const json = JSON.stringify(rows, null, 2);
  let flagHtml = '';
  if (json.includes('"password"')) {
    flagHtml = flagBox(award(req, 'api', 'exposure'));
  } else if (captured(req, 'api', 'exposure')) {
    flagHtml = flagBox(flagFor('api', 'exposure')) + fixPanel('api', 'exposure');
  }
  res.send(page('API: excessive data', `
    ${brief('Excessive Data Exposure', `This page renders the raw response of <code>GET /api/users</code>.
      Real APIs often return whole database rows; the <code>password</code> and <code>secret</code>
      fields below were never meant to leave the server.`)}
    ${flagHtml}
    <pre>${esc(json)}</pre>
    <p><a href="/api">Back to the module index</a></p>
  `));
});

// POST /api/login -> v3 credential stuffing target with no rate limiting.
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const key = String(username || '');
  // VULN: attempts are counted but never limited, so unlimited password
  // guesses can be fired at this endpoint with no lockout or CAPTCHA.
  attempts[key] = (attempts[key] || 0) + 1;

  const user = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = !!(user && user.password === password);
  let flag = null;
  if (ok && key === 'alice' && attempts[key] >= 15) {
    flag = award(req, 'api', 'rate-limit');
  }
  res.json({ ok, attempts: attempts[key], flag });
});

// ---------- v7: rate limit keyed by spoofable X-Forwarded-For ----------
router.post('/v1/login', (req, res) => {
  const { username, password } = req.body || {};
  const realIp = req.ip || req.socket.remoteAddress || 'unknown';
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const key = xff || realIp;
  v1LoginAttempts[key] = (v1LoginAttempts[key] || 0) + 1;
  // VULN: the rate-limit identity comes from the client-controlled
  // X-Forwarded-For header, so the lockout is bypassed by spoofing a new IP.
  if (v1LoginAttempts[key] > 3) {
    return res.status(429).json({ ok: false, error: 'Too many attempts. Try again later.', attempts: v1LoginAttempts[key] });
  }
  const dbUser = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = !!(dbUser && dbUser.password === password);
  let flag = null;
  if (ok && xff && (v1LoginAttempts[realIp] || 0) > 3) {
    // Genuine bypass: the real IP was locked out, yet login succeeded under a spoofed one.
    flag = award(req, 'api', 'ratelimit-xff');
  }
  if (ok) {
    req.session.user = { id: dbUser.id, username: dbUser.username, role: dbUser.role };
  }
  res.json({ ok, attempts: v1LoginAttempts[key], flag });
});

// ---------- v9: v2 forgot the authorization check that v1 enforces ----------
function vUserRow(id) {
  return getDb().prepare('SELECT id, username, email, role, secret FROM users WHERE id = ?').get(id);
}

router.get('/v1/users/:id', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const target = vUserRow(req.params.id);
  if (!target) return res.status(404).json({ ok: false, error: 'No such user.' });
  // v1 does it right: you may read your own record, or any record as admin.
  if (Number(req.params.id) !== user.id && user.role !== 'admin') {
    return res.status(403).json({ ok: false, error: 'Forbidden: you can only view your own record.' });
  }
  res.json({ ok: true, user: target });
});

router.get('/v2/users/:id', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const target = vUserRow(req.params.id);
  if (!target) return res.status(404).json({ ok: false, error: 'No such user.' });
  // VULN: v2 was copy-pasted from v1 but the authorization check never made
  // it over, so any logged-in user can read anyone's full record.
  let flag = null;
  if (Number(req.params.id) !== user.id && user.role !== 'admin') {
    flag = award(req, 'api', 'api-version-bypass');
  }
  res.json({ ok: true, user: target, flag });
});

// GET /api -> module index page.
router.get('/', (req, res) => {
  const who = req.session.user ? esc(req.session.user.username) : 'nobody';
  const vulnList = module.exports.vulns
    .map((v) => `
      <div class="vuln">
        <h3>${esc(v.name)} <span class="diff">${esc(v.difficulty)}</span></h3>
        <p>${esc(v.how)}</p>
        ${hintLadder(v)}
      ${toolsPill(v)}
      </div>`)
    .join('');

  res.send(page('Acme API Docs', `
    ${brief('API Security Flaws', `
      A tiny JSON API for a fictional startup. The endpoints below are the
      public surface; your job is to find where the API trusts the client too
      much. You are currently logged in as <b>${who}</b>.
      Flags for the JSON endpoints arrive in the response body (<code>"flag"</code>)
      or the <code>X-Pentrix-Flag</code> response header (use <code>curl -i</code>).`)}
    ${trackBanner(module.exports)}

    <h3>Endpoints</h3>
    <table>
      <tr><th>Method</th><th>Path</th><th>Description</th></tr>
      <tr><td>GET</td><td><code>/api/login/:user</code></td><td>Log in as a user (demo only)</td></tr>
      <tr><td>POST</td><td><code>/api/login</code></td><td>Log in with username and password (JSON)</td></tr>
      <tr><td>GET</td><td><code>/api/me</code></td><td>Your profile</td></tr>
      <tr><td>PATCH</td><td><code>/api/me</code></td><td>Update your profile (JSON)</td></tr>
      <tr><td>GET</td><td><code>/api/users</code></td><td>List users</td></tr>
      <tr><td>GET</td><td><code>/api/v1/login</code></td><td>Log in (v1, rate limited)</td></tr>
      <tr><td>GET</td><td><code>/api/v1/users/:id</code></td><td>Get user by id (v1)</td></tr>
      <tr><td>GET</td><td><code>/api/v2/users/:id</code></td><td>Get user by id (v2)</td></tr>
    </table>

    <h3>Quick login</h3>
    <p>
      <a class="btn" href="/api/login/alice">Log in as alice</a>
      <a class="btn" href="/api/users/view">View user list (browser)</a>
    </p>

    <h3>Challenges</h3>
    <p>Five flaws hide in the endpoints above. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${vulnList}
  `));
});

module.exports = {
  id: 'api',
  name: 'API Security Flaws',
  tagline: 'Mass assignment, data exposure, and brute force on a JSON API.',
  description: 'A small JSON API with five classic flaws: a profile endpoint that merges every client-supplied field, a user-list endpoint that leaks full database rows, a login endpoint with no rate limiting, a rate limit bypassed via X-Forwarded-For, and a v2 endpoint that forgot its authorization check. All flags are awarded server-side on real exploitation.',
  difficulty: 'Intermediate',
  track: 'Advanced',
  prerequisites: ['Auth and Sessions track', 'Injection track'],
  vulns: [
    {
      id: 'mass-assignment',
      name: 'Mass Assignment',
      difficulty: 'Medium',
      hint: 'PATCH /api/me builds its SQL SET clause from Object.keys(req.body). Nothing stops you from adding fields the form never showed you, like "role".',
      hints: ["The PATCH /me endpoint updates your profile. What happens if you send fields the form never showed you?", "There is no allowlist: every key in the JSON body becomes a column in the UPDATE.", "Send a PATCH with a JSON body containing an extra privilege-related field."],
      tools: "C",
      how: 'Log in as alice, then send a JSON body with an extra field that escalates your privilege.',
    },
    {
      id: 'exposure',
      name: 'Excessive Data Exposure',
      difficulty: 'Easy',
      hint: 'GET /api/users runs SELECT * and returns the rows as JSON. Read the response body, or check the X-Pentrix-Flag response header.',
      hints: ["The /users endpoint returns user objects. Compare what the UI shows versus what the JSON contains.", "The response includes fields the client should never see. APIs must return only what the client needs.", "Fetch /api/users and inspect the full JSON, including headers, for sensitive fields."],
      tools: "B, C",
      how: 'Fetch the user list and read fields the client should never see.',
    },
    {
      id: 'rate-limit',
      name: 'Missing Rate Limiting',
      difficulty: 'Medium',
      hint: 'POST /api/login counts attempts per username but never blocks them. Fire 14+ wrong guesses for alice, then log in with the right password on the 15th attempt.',
      hints: ["The login endpoint counts attempts but never blocks them. What does that allow?", "Without throttling, you can try as many passwords as you want. The flag rewards persistence.", "Automate login attempts: many failures followed by a success triggers the award."],
      tools: "P, C",
      how: 'Brute force alice\u2019s password; the flag is awarded when the successful login follows 15 or more attempts.',
    },
    {
      id: 'ratelimit-xff',
      name: 'Rate Limit Bypass via X-Forwarded-For',
      difficulty: 'Medium',
      hint: 'POST /api/v1/login locks an IP out after 3 bad attempts, but the "client IP" comes from the X-Forwarded-For header, which you control.',
      hints: ["The rate limit is keyed by client IP. Where does the server get the IP from?", "It trusts a client-controlled header. If you can change your apparent IP, the limit resets.", "Send requests with a spoofed forwarding header, varying it per attempt."],
      tools: "C",
      how: 'Trigger the lockout with bad passwords, then retry with the correct password and a spoofed X-Forwarded-For header.',
    },
    {
      id: 'api-version-bypass',
      name: 'API Version AuthZ Bypass',
      difficulty: 'Medium',
      hint: 'GET /api/v1/users/:id checks that you only read your own record (unless admin). Somebody copy-pasted the route for v2 and forgot the check.',
      hints: ["v1 checks that you only read your own record. v2 was added later by copying v1.", "Compare the authorization logic between versions. Copy-paste often drops the check.", "Request the same user id through v1 and v2; one of them forgets to verify ownership."],
      tools: "C",
      how: 'Log in as alice, confirm v1 blocks you from reading user 3, then read the same record through v2.',
    },
  ],
  router,
};
