// API Security Flaws module: intentionally vulnerable JSON API training targets.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();

// VULN: brute-force counter lives in memory and is never enforced, so an
// attacker can hammer POST /api/login without lockout or slowdown.
const attempts = {};

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
      A tiny JSON API with three classic flaws: <b>mass assignment</b> on the profile
      endpoint, <b>excessive data exposure</b> on the user list, and a login endpoint
      with <b>no rate limiting</b>. You are currently logged in as <b>${who}</b>.
      Flags for the JSON endpoints arrive in the <code>X-Pentrix-Flag</code> response
      header (use <code>curl -i</code>), or claim them in your browser at the links below.`)}

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
  ],
  router,
};
