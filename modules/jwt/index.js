'use strict';
// JWT Attacks (jwt): thin aggregator. Every challenge lives in its own file
// under challenges/; module-level helper routes that are not part of any
// single challenge (the attacker key server used by the jku challenge) live
// here, copied from modules/jwt/router.js.
const express = require('express');
const { getDb } = require('../../lib/db');
const { fixCta, brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill } = require('../../lib/page');

const challenges = [
  require('./challenges/none-admin'),
  require('./challenges/weak-secret'),
  require('./challenges/kid-sqli'),
  require('./challenges/jku'),
  require('./challenges/alg-confusion'),
  require('./challenges/no-expiry'),
  require('./challenges/aud-bypass'),
  require('./challenges/kid-default'),
];

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const PORT = process.env.PORT || 3000;

// Key table for the attacker key server. The jwt_keys table is seeded by the
// kid-sqli and kid-default challenge files themselves (idempotent).
function jkuDb() {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS jwt_jku_keys (
      kid TEXT PRIMARY KEY,
      secret TEXT NOT NULL
    );
  `);
  return db;
}
const db = jkuDb();

// Attacker-controlled key server, living inside the lab for the jku exercise.
router.get('/attacker-keys', (req, res) => {
  const rows = db.prepare('SELECT kid FROM jwt_jku_keys ORDER BY kid').all();
  const items = rows.map((r) => `
    <li><code>${esc(r.kid)}</code> - JWKS:
      <code>http://localhost:${esc(String(PORT))}/jwt/attacker-keys/jwks?kid=${esc(r.kid)}</code></li>`).join('') || '<li><i>none registered yet</i></li>';
  res.send(page('Attacker key server', `
    <h2>Your key server</h2>
    <p>You are the attacker. Publish a signing key here, exactly like a real
    compromised or rogue key server would.</p>
    <form method="POST" action="/jwt/attacker-keys/register">
      <input type="text" name="kid" placeholder="key id, e.g. evil" required />
      <input type="text" name="secret" placeholder="your HMAC secret" required />
      <button type="submit">Publish key</button>
    </form>
    <h3>Published keys</h3>
    <ul>${items}</ul>
    <p><a href="/jwt/jku">Back to the jku challenge</a></p>
  `));
});

router.post('/attacker-keys/register', (req, res) => {
  const kid = String(req.body.kid || '').slice(0, 64).trim();
  const secret = String(req.body.secret || '').slice(0, 256);
  if (!kid || !secret) {
    return res.status(400).send(page('Attacker key server', '<p>kid and secret are required.</p><p><a href="/jwt/attacker-keys">Back</a></p>'));
  }
  db.prepare('INSERT OR REPLACE INTO jwt_jku_keys (kid, secret) VALUES (?, ?)').run(kid, secret);
  res.redirect('/jwt/attacker-keys');
});

router.get('/attacker-keys/jwks', (req, res) => {
  const row = db.prepare('SELECT kid, secret FROM jwt_jku_keys WHERE kid = ?').get(String(req.query.kid || ''));
  if (!row) return res.status(404).json({ error: 'unknown kid' });
  res.json({
    keys: [{
      kty: 'oct',
      kid: row.kid,
      alg: 'HS256',
      use: 'sig',
      k: Buffer.from(row.secret, 'utf8').toString('base64url'),
    }],
  });
});

// GET /jwt -> module index page.
router.get('/', (req, res) => {
  const links = {
    'none-admin': '/jwt/none',
    'weak-secret': '/jwt/weak',
    'kid-sqli': '/jwt/kid',
    'jku': '/jwt/jku',
    'alg-confusion': '/jwt/confusion',
    'no-expiry': '/jwt/noexpiry',
    'aud-bypass': '/jwt/aud',
    'kid-default': '/jwt/kiddefault',
  };
  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="${links[v.id]}">${esc(v.name)}</a> ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('jwt', c.vuln.id)).join('')}
    </section>`;
  res.send(page('JWT Attacks', `
    ${brief('JWT Attacks', `
      A JSON Web Token is three base64url segments joined by dots:
      <code>header.payload.signature</code>. The header names the algorithm
      (<code>alg</code>) and the key (<code>kid</code>); the signature proves the
      token was minted by someone holding the secret.
      <b>Your goal in this module:</b> get the admin panel to accept a token with
      <code>role: "admin"</code>. Every challenge page shows you a legitimate token
      first; your job is to break the verification around it.
      <code>jsonwebtoken</code> is installed, so you can mint and verify tokens
      locally with <code>node -e</code> one-liners.`)}
    ${trackBanner(module.exports)}

    <h2>Challenges</h2>
    <p>Eight token-verification flaws hide behind the admin panels below. Each
    challenge card has a hint ladder: level 1 nudges, level 2 teaches the technique,
    level 3 shows the payload shape.</p>
    ${cards}
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'jwt',
  name: 'JWT Attacks',
  tagline: 'Break token verification: none-alg, weak secrets, kid tricks, jku, and alg confusion.',
  description: 'Eight ways JSON Web Token verification fails in the real world. Each challenge hands you a legitimate token and a flawed verifier; forge an admin token and take the flag.',
  difficulty: 'Intermediate',
  track: 'Auth and Sessions',
  prerequisites: ['auth'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
