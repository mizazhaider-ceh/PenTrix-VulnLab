'use strict';
// SQL Injection in kid Lookup: GET/POST /kid picks the HMAC key from a key
// table using the token's kid header, interpolated straight into SQL.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');

const router = express.Router();

// --- storage: the jwt_keys table this challenge needs. Idempotent, so the
// module finisher may hoist it into shared.js/index.js instead. ---
function initJwtKeys() {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS jwt_keys (
      kid TEXT PRIMARY KEY,
      key TEXT NOT NULL
    );
  `);
  const n = db.prepare('SELECT COUNT(*) AS c FROM jwt_keys').get().c;
  if (n === 0) {
    db.prepare('INSERT INTO jwt_keys (kid, key) VALUES (?, ?)').run(
      'main',
      crypto.randomBytes(24).toString('hex')
    );
  }
  return db;
}
const db = initJwtKeys();
const mainKey = db.prepare('SELECT key FROM jwt_keys WHERE kid = ?').get('main').key;

// Sample token minted at boot for the demo.
const sampleMainGuest = jwt.sign({ user: 'guest', role: 'user' }, mainKey, { algorithm: 'HS256', header: { kid: 'main' } });

// --- helpers ---
function b64uDecode(seg) {
  return JSON.parse(Buffer.from(String(seg), 'base64url').toString('utf8'));
}
function decodeFull(token) {
  const parts = String(token || '').trim().split('.');
  if (parts.length !== 3) return null;
  try {
    return { header: b64uDecode(parts[0]), claims: b64uDecode(parts[1]) };
  } catch (e) {
    return null;
  }
}
function tokenForm(action, note) {
  return `
    <form method="POST" action="${esc(action)}">
      <label>Paste a JWT:<br />
      <textarea class="clay-input" name="token" rows="5" cols="72" placeholder="eyJhbGciOi..."></textarea></label><br /><br />
      <button type="submit" class="clay-btn clay-btn-primary">Submit token</button>
    </form>
    ${note || ''}`;
}
function denied(title, msg) {
  return page(title, `
    <h2>Access denied</h2>
    <div class="warn"><p>${msg}</p></div>
    <p><a href="/jwt">Back to the JWT module</a></p>`);
}

// GET /kid -> the admin panel demo page for the kid lookup.
router.get('/kid', (req, res) => {
  res.send(page('Admin panel (kid lookup)', `
    <div class="brief">
      <h2>Admin panel</h2>
      <p>This endpoint picks the HMAC key from a key table using the token's
      <code>kid</code> header:</p>
      <pre><code>SELECT key FROM jwt_keys WHERE kid='&lt;kid from token&gt;'</code></pre>
      <p>One key is registered: <code>kid = "main"</code>.</p>
    </div>
    ${tokenForm('/jwt/kid', `
      <p class="note">A legitimate guest token (kid "main"):
      <code>${esc(sampleMainGuest)}</code></p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

// POST /kid -> verify the token with the key returned by the kid lookup.
router.post('/kid', (req, res) => {
  const d = decodeFull(req.body.token);
  let claims = null;
  if (d && d.header.kid) {
    // VULN: the kid header is interpolated straight into SQL, so an attacker can
    // choose which key verifies their token.
    const row = db.prepare(`SELECT key FROM jwt_keys WHERE kid='${d.header.kid}'`).get();
    if (row && row.key) {
      try {
        claims = jwt.verify(String(req.body.token || '').trim(), row.key, { algorithms: ['HS256'] });
      } catch (e) { /* bad signature */ }
    }
  }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'kid-sqli');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>Your token verified with a key you smuggled in through the
      <code>kid</code> header.</p>
      ${flagBox(flag)}
      ${fixPanel('jwt', 'kid-sqli')}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'No key found for that kid, signature invalid, or role is not admin.'));
});

module.exports = {
  vuln: {
    id: 'kid-sqli',
    name: 'SQL Injection in kid Lookup',
    difficulty: 'Medium',
    hint: 'The kid header goes straight into a SQL query that picks the verifying key. Make the query return a key you control.',
    hints: ["Proxy on, open /jwt/kid and submit the sample token once, then find the POST in Proxy history and send it to Repeater. The kid header goes straight into a SQL query that picks the verifying key. What happens if the kid contains a quote?", "In Repeater, shape the kid so it breaks out of the quoted lookup and makes the SELECT return a key of your own choosing instead of the registered one.", "Shape: a kid value that turns the lookup into a query returning a key you chose, plus a token signed with that same key. The Burp JWT extension or a small local signing script can mint the token; Repeater delivers it."],
    tools: "BZ, N",
    est: 'about 10 to 20 minutes',
    how: 'The key that verifies your token is chosen by a database lookup built from a header you control.',
    link: '/jwt#kid-sqli',
    start: 'Open /jwt/kid in the Burp browser with Proxy on, submit the sample token once, then send the POST to Repeater.',
  },
  router,
};
