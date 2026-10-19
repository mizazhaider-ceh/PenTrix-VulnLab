'use strict';
// JWT kid default: the key is chosen from the token's kid header, but a token
// with no kid header falls back to a hardcoded, guessable default key.
// Sign a kid-less admin token with the default key to win.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getDb } = require('../../../lib/db');
const { award } = require('../../../lib/flags');
const { esc, page, flagBox, fixPanel, hintLadder, toolsPill, payloadBlock } = require('../../../lib/page');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const DEFAULT_KID_KEY = 'test';       // VULN: hardcoded fallback key

// ------------------------------------------------------------------ storage
// Mirrors the jwt module's key table seeding for this challenge's routes:
// jwt_keys must exist with the "main" key so kid="main" lookups behave exactly
// as they do in the combined router.
function jwtKeysDb() {
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
const db = jwtKeysDb();
const mainKey = db.prepare('SELECT key FROM jwt_keys WHERE kid = ?').get('main').key;

// ------------------------------------------------------------------ helpers
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
      <div class="clay-field">
        <label for="token">Paste a JWT:</label>
        <textarea id="token" name="token" class="clay-input" rows="5" placeholder="eyJhbGciOi..."></textarea>
      </div>
      <button type="submit" class="clay-btn clay-btn-primary">Submit token</button>
    </form>
    ${note || ''}`;
}
function denied(title, msg) {
  return page(title, `
    <div class="card">
      <h2>Access denied</h2>
      <div class="warn"><p>${msg}</p></div>
      <p><a href="/jwt">Back to the JWT module</a></p>
    </div>`);
}

// A legitimate guest token, for reference (kid "main", verifies with the
// seeded main key, so kidnapped kids cannot use it).
const sampleMainGuest = jwt.sign({ user: 'guest', role: 'user' }, mainKey, { algorithm: 'HS256', header: { kid: 'main' } });

const vuln = {
  id: 'kid-default',
  name: 'Default Key for Missing kid',
  difficulty: 'Medium',
  hint: 'Tokens without a kid header fall back to a hardcoded default key. Developers pick very predictable defaults.',
  hints: ["No kid header? The server falls back to a default key. What might it be?", "'default', 'secret', 'key'. Guessable.", "Send a token with no kid, signed with the guessed default key."],
  tools: "N",
  how: 'Guess the default key, sign a kid-less admin token with it, and submit it.',
  link: '/jwt#kid-default',
  start: 'curl -s http://localhost:3000/jwt/kiddefault\nnode -e "const jwt=require(\'jsonwebtoken\'); console.log(jwt.sign({user:\'guest\',role:\'admin\'},\'<guessed-key>\',{algorithm:\'HS256\'}))"',
};

// --------------------------------------------------------------- challenge
router.get('/kiddefault', (req, res) => {
  res.send(page('Admin panel (kid default)', `
    <div class="card app-shell">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span>
        <b>Key-Rotating Admin Console</b>
        <span class="app-nav"><span class="dim">Admin</span><span class="dim"> · </span><span class="dim">Keys</span><span class="dim"> · </span><span class="dim">Audit</span></span>
      </div>
      <h2>Admin panel</h2>
      <p>The key is chosen by the token's <code>kid</code> header. Tokens without a
      <code>kid</code> header are verified with the deployment default key.</p>
      ${hintLadder(vuln)}
      ${toolsPill(vuln)}
      <h3>Reference token</h3>
      <p class="dim">A legitimate guest token (kid "main"):</p>
      ${payloadBlock('Guest token (kid "main")', sampleMainGuest)}
      <p class="note dim">What is the default key? Think about what developers type when testing.</p>
      <h3>Submit a token</h3>
      ${tokenForm('/jwt/kiddefault')}
      <p><a href="/jwt">Back to the JWT module</a></p>
    </div>
  `));
});

router.post('/kiddefault', (req, res) => {
  const token = String(req.body.token || '').trim();
  const d = decodeFull(token);
  let claims = null;
  if (d) {
    let key;
    if (!d.header.kid) {
      // VULN: a missing kid falls back to a hardcoded, guessable default key.
      key = DEFAULT_KID_KEY;
    } else {
      const row = db.prepare('SELECT key FROM jwt_keys WHERE kid = ?').get(String(d.header.kid));
      key = row && row.key;
    }
    if (key) {
      try {
        claims = jwt.verify(token, key, { algorithms: ['HS256'] });
      } catch (e) { /* bad signature */ }
    }
  }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'kid-default');
    return res.send(page('Admin panel', `
      <div class="card">
        <h2>Welcome, admin</h2>
        <p>Your kid-less token verified with the default key.</p>
        ${flagBox(flag)}
        ${fixPanel('jwt', 'kid-default')}
        <p><a href="/jwt">Back to the JWT module</a></p>
      </div>`));
  }
  res.status(403).send(denied('Admin panel', 'Unknown kid, signature invalid, or role is not admin.'));
});

module.exports = { vuln, router };
