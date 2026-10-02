// PenTrix VulnLab module: JWT Attacks (jwt)
// Eight token-validation failures: alg=none trust, weak HMAC secret, SQL injection
// in the kid key lookup, jku key-server fetch, RS256/HS256 alg confusion, ignored
// expiry, ignored audience, and a hardcoded default key for missing kid headers.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const PORT = process.env.PORT || 3000;
const WEAK_SECRET = 'secret123';      // VULN lab 2: guessable HMAC secret
const DEFAULT_KID_KEY = 'test';       // VULN lab 8: hardcoded fallback key

// ------------------------------------------------------------------ storage
function jwtDb() {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS jwt_keys (
      kid TEXT PRIMARY KEY,
      key TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS jwt_jku_keys (
      kid TEXT PRIMARY KEY,
      secret TEXT NOT NULL
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
const db = jwtDb();
const mainKey = db.prepare('SELECT key FROM jwt_keys WHERE kid = ?').get('main').key;

// VULN lab 5: RSA key pair generated at boot; the public half is published and
// later misused as an HMAC secret.
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUB_PEM = publicKey.export({ type: 'spki', format: 'pem' });
const PRIV_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });

// --------------------------------------------------------------- small tools
function b64u(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}
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
      <textarea name="token" rows="5" cols="72" placeholder="eyJhbGciOi..."></textarea></label><br /><br />
      <button type="submit">Submit token</button>
    </form>
    ${note || ''}`;
}
function denied(title, msg) {
  return page(title, `
    <h2>Access denied</h2>
    <div class="warn"><p>${msg}</p></div>
    <p><a href="/jwt">Back to the JWT module</a></p>`);
}
function checkCreds(username, password) {
  return db.prepare('SELECT username, role FROM users WHERE username = ? AND password = ?')
    .get(String(username || ''), String(password || ''));
}

// Sample tokens minted at boot for the demos.
const sampleWeakGuest = jwt.sign({ user: 'guest', role: 'user' }, WEAK_SECRET, { algorithm: 'HS256' });
const sampleMainGuest = jwt.sign({ user: 'guest', role: 'user' }, mainKey, { algorithm: 'HS256', header: { kid: 'main' } });
const sampleRsGuest = jwt.sign({ user: 'guest', role: 'user' }, PRIV_PEM, { algorithm: 'RS256', header: { kid: 'rsa-main' } });
const expiredAdminToken = jwt.sign(
  { user: 'admin', role: 'admin', exp: Math.floor(Date.now() / 1000) - 3600 },
  WEAK_SECRET,
  { algorithm: 'HS256' }
);
const partnerToken = jwt.sign(
  { user: 'partner-admin', role: 'admin', aud: 'billing-service' },
  WEAK_SECRET,
  { algorithm: 'HS256' }
);

// ---------------------------------------------------------------- index page
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
  const rows = module.exports.vulns.map((v) => {
    const done = captured(req, 'jwt', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="${links[v.id]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  const briefHtml = `
    <p><b>What is a JWT?</b> A JSON Web Token is three base64url segments joined by
    dots: <code>header.payload.signature</code>. The header names the algorithm
    (<code>alg</code>) and the key (<code>kid</code>). The signature proves the
    token was minted by someone holding the secret.</p>
    <p><b>The goal in this module:</b> get the admin panel to accept a token with
    <code>role: "admin"</code>. Every challenge page shows you a legitimate token
    first; your job is to break the verification around it. Decode any token with
    <code>node -e</code> or a base64url decoder to see the claims.</p>
    <p><b>Tooling tip:</b> <code>jsonwebtoken</code> is installed, so you can mint
    and verify tokens locally with <code>node -e</code> one-liners.</p>`;

  res.send(page('JWT Attacks', `
    ${brief('Module briefing', briefHtml)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

// ------------------------------------------------------- v1: alg=none admin
router.get('/none', (req, res) => {
  const sample = b64u({ alg: 'none', typ: 'JWT' }) + '.' + b64u({ user: 'guest', role: 'user' }) + '.';
  res.send(page('Admin panel (alg=none)', `
    <h2>Admin panel</h2>
    <p>This endpoint checks the token's claims to decide if you are an admin.
    It supports <code>alg=none</code> for "internal" unsigned tokens.</p>
    ${tokenForm('/jwt/none', `
      <p class="note">An unsigned token looks like this (header, payload, empty
      signature): <code>${esc(sample)}</code>. Try changing the role.</p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

router.post('/none', (req, res) => {
  const d = decodeFull(req.body.token);
  // VULN: tokens with alg=none are trusted with no signature check at all.
  if (d && d.header.alg === 'none' && d.claims && d.claims.role === 'admin') {
    const flag = award(req, 'jwt', 'none-admin');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>An unsigned token with <code>role: "admin"</code> was accepted.</p>
      ${flagBox(flag)}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Token rejected. It must be a well-formed unsigned (alg=none) token with role "admin".'));
});

// --------------------------------------------------------- v2: weak secret
router.get('/weak', (req, res) => {
  res.send(page('Admin panel (weak secret)', `
    <h2>Admin panel</h2>
    <p>Tokens here are signed with <code>HS256</code>. The operations team swears
    the signing secret is strong. It is not.</p>
    ${tokenForm('/jwt/weak', `
      <p class="note">A legitimate guest token, signed by the server:
      <code>${esc(sampleWeakGuest)}</code><br />
      Decode it, then forge your own admin token offline once you guess the secret.</p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

router.post('/weak', (req, res) => {
  let claims = null;
  try {
    claims = jwt.verify(String(req.body.token || '').trim(), WEAK_SECRET, { algorithms: ['HS256'] });
  } catch (e) { /* bad signature */ }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'weak-secret');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>Your forged token verified against the real signing secret.</p>
      ${flagBox(flag)}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Signature invalid or role is not admin.'));
});

// -------------------------------------------------------------- v3: kid SQLi
router.get('/kid', (req, res) => {
  res.send(page('Admin panel (kid lookup)', `
    <h2>Admin panel</h2>
    <p>This endpoint picks the HMAC key from a key table using the token's
    <code>kid</code> header:</p>
    <pre><code>SELECT key FROM jwt_keys WHERE kid='&lt;kid from token&gt;'</code></pre>
    <p>One key is registered: <code>kid = "main"</code>.</p>
    ${tokenForm('/jwt/kid', `
      <p class="note">A legitimate guest token (kid "main"):
      <code>${esc(sampleMainGuest)}</code></p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

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
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'No key found for that kid, signature invalid, or role is not admin.'));
});

// ----------------------------------------------------------------- v4: jku
router.get('/jku', (req, res) => {
  const jkuUrl = `http://localhost:${PORT}/jwt/attacker-keys/jwks?kid=evil`;
  res.send(page('Admin panel (jku)', `
    <h2>Admin panel</h2>
    <p>This endpoint supports federated signers: if a token carries a
    <code>jku</code> header, the server fetches that URL, reads the JSON Web Key
    Set, and verifies the token with the published key. No allowlist.</p>
    ${tokenForm('/jwt/jku', `
      <p class="note">Run your own key server at
      <a href="/jwt/attacker-keys">/jwt/attacker-keys</a>, register a kid and
      secret, then point <code>jku</code> at e.g.
      <code>${esc(jkuUrl)}</code> and sign an admin token with your secret.</p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

// Attacker-controlled key server, living inside the lab for the exercise.
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

router.post('/jku', async (req, res) => {
  const token = String(req.body.token || '').trim();
  const d = decodeFull(token);
  let claims = null;
  if (d && typeof d.header.jku === 'string' && d.header.jku.length > 0) {
    try {
      // VULN: the jku URL is fetched with no allowlist, so the attacker can
      // point it at their own key server and supply the verifying key.
      const r = await fetch(d.header.jku);
      const jwks = await r.json();
      const entry = (jwks.keys || []).find((k) => k.kty === 'oct' && k.kid === d.header.kid);
      if (entry && entry.k) {
        const secret = Buffer.from(entry.k, 'base64url');
        claims = jwt.verify(token, secret, { algorithms: ['HS256'] });
      }
    } catch (e) { /* fetch or verification failed */ }
  }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'jku');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>The server fetched your <code>jku</code> URL and verified your token
      with the key you published.</p>
      ${flagBox(flag)}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'jku fetch failed, key not found, signature invalid, or role is not admin.'));
});

// -------------------------------------------------------- v5: alg confusion
router.get('/confusion', (req, res) => {
  res.send(page('Admin panel (alg confusion)', `
    <h2>Admin panel</h2>
    <p>This endpoint verifies tokens with <code>RS256</code> using the RSA public
    key below. It also "helpfully" accepts <code>HS256</code> tokens.</p>
    <p><a href="/jwt/confusion-pubkey">View the RSA public key</a></p>
    ${tokenForm('/jwt/confusion', `
      <p class="note">A legitimate RS256 guest token:
      <code>${esc(sampleRsGuest)}</code><br />
      Think about what the server uses as the HMAC secret when you send
      <code>alg: "HS256"</code>.</p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

router.get('/confusion-pubkey', (req, res) => {
  res.send(page('RSA public key', `
    <h2>RSA public key</h2>
    <p>Published for signature verification transparency (and exploited below):</p>
    <pre>${esc(PUB_PEM)}</pre>
    <p><a href="/jwt/confusion">Back to the challenge</a></p>
  `));
});

router.post('/confusion', (req, res) => {
  const token = String(req.body.token || '').trim();
  const d = decodeFull(token);
  let claims = null;
  if (d) {
    try {
      if (d.header.alg === 'HS256') {
        // VULN: the RSA *public* key bytes are used as the HMAC secret, so anyone
        // who can read the public key (it is public) can forge HS256 tokens.
        // createSecretKey mirrors the vulnerable pattern: raw key bytes as HMAC key.
        claims = jwt.verify(token, crypto.createSecretKey(Buffer.from(PUB_PEM)), { algorithms: ['HS256'] });
      } else {
        claims = jwt.verify(token, PUB_PEM, { algorithms: ['RS256'] });
      }
    } catch (e) { /* bad signature */ }
  }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'alg-confusion');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>Your <code>HS256</code> token verified: the public key worked as an HMAC secret.</p>
      ${flagBox(flag)}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Signature invalid or role is not admin.'));
});

// ------------------------------------------------------------- v6: no expiry
router.get('/noexpiry', (req, res) => {
  res.send(page('Admin panel (expiry)', `
    <h2>Admin panel</h2>
    <p>Tokens carry an <code>exp</code> claim. This one expired an hour ago, so it
    should be useless now. Should it?</p>
    ${tokenForm('/jwt/noexpiry', `
      <p class="note">The expired admin token, exactly as leaked:
      <code>${esc(expiredAdminToken)}</code></p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

router.post('/noexpiry', (req, res) => {
  let claims = null;
  try {
    // VULN: the exp claim is never enforced; expired tokens verify forever.
    claims = jwt.verify(String(req.body.token || '').trim(), WEAK_SECRET, {
      algorithms: ['HS256'],
      ignoreExpiration: true,
    });
  } catch (e) { /* bad signature */ }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'no-expiry');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>The expired token was accepted. Expiry is not enforced here.</p>
      ${flagBox(flag)}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Signature invalid or role is not admin.'));
});

// ------------------------------------------------------------ v7: aud bypass
router.get('/aud', (req, res) => {
  res.send(page('Admin panel (audience)', `
    <h2>Admin panel</h2>
    <p>This service accepts tokens minted for other services, as long as the
    signature is valid. Tokens carry an <code>aud</code> (audience) claim naming
    the intended service.</p>
    <h3>Token vending machine</h3>
    <form method="POST" action="/jwt/aud/mint">
      <input type="text" name="aud" placeholder="audience, e.g. billing-service" required />
      <button type="submit">Mint token for that audience</button>
    </form>
    <p class="note">A token minted for our partner <code>billing-service</code> (admin role):
    <code>${esc(partnerToken)}</code></p>
    <h3>Submit a token</h3>
    ${tokenForm('/jwt/aud/login')}
    <p><a href="/jwt">Back to the JWT module</a></p>
  `));
});

router.post('/aud/mint', (req, res) => {
  const aud = String(req.body.aud || '').slice(0, 80);
  if (!aud.trim()) {
    return res.status(400).send(page('Token vending machine', '<p>Audience is required.</p><p><a href="/jwt/aud">Back</a></p>'));
  }
  const token = jwt.sign({ user: 'guest', role: 'user', aud }, WEAK_SECRET, { algorithm: 'HS256' });
  res.send(page('Token vending machine', `
    <h2>Token minted</h2>
    <p>Audience: <code>${esc(aud)}</code></p>
    <p><code>${esc(token)}</code></p>
    <p><a href="/jwt/aud">Back to the challenge</a></p>
  `));
});

router.post('/aud/login', (req, res) => {
  let claims = null;
  try {
    // VULN: the aud claim is never checked, so a token meant for another
    // service is accepted here.
    claims = jwt.verify(String(req.body.token || '').trim(), WEAK_SECRET, { algorithms: ['HS256'] });
  } catch (e) { /* bad signature */ }
  if (claims && claims.role === 'admin') {
    const flag = award(req, 'jwt', 'aud-bypass');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>Token accepted even though its audience is
      <code>${esc(claims.aud || '(none)')}</code>, not this service.</p>
      ${flagBox(flag)}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Signature invalid or role is not admin.'));
});

// --------------------------------------------------------- v8: kid default
router.get('/kiddefault', (req, res) => {
  res.send(page('Admin panel (kid default)', `
    <h2>Admin panel</h2>
    <p>The key is chosen by the token's <code>kid</code> header. Tokens without a
    <code>kid</code> header are verified with the deployment default key.</p>
    ${tokenForm('/jwt/kiddefault', `
      <p class="note">A legitimate guest token (kid "main"):
      <code>${esc(sampleMainGuest)}</code><br />
      What is the default key? Think about what developers type when testing.</p>`)}
    <p><a href="/jwt">Back to the JWT module</a></p>
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
      <h2>Welcome, admin</h2>
      <p>Your kid-less token verified with the default key.</p>
      ${flagBox(flag)}
      <p><a href="/jwt">Back to the JWT module</a></p>`));
  }
  res.status(403).send(denied('Admin panel', 'Unknown kid, signature invalid, or role is not admin.'));
});

module.exports = {
  id: 'jwt',
  name: 'JWT Attacks',
  tagline: 'Break token verification: none-alg, weak secrets, kid tricks, jku, and alg confusion.',
  description: 'Eight ways JSON Web Token verification fails in the real world. Each challenge hands you a legitimate token and a flawed verifier; forge an admin token and take the flag.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'none-admin',
      name: 'alg=none Accepted',
      difficulty: 'Easy',
      hint: 'The verifier trusts tokens with "alg": "none" and never checks a signature. What stops you from writing your own claims?',
      how: 'Craft an unsigned token (header, payload, empty signature) with role "admin" and submit it.',
    },
    {
      id: 'weak-secret',
      name: 'Weak HMAC Secret',
      difficulty: 'Medium',
      hint: 'HS256 security is only as strong as the secret. This one is a classic default. Guess it, then sign your own token offline.',
      how: 'Recover the weak secret, mint an admin token with jsonwebtoken locally, and submit it.',
    },
    {
      id: 'kid-sqli',
      name: 'SQL Injection in kid Lookup',
      difficulty: 'Medium',
      hint: 'The kid header goes straight into a SQL query that picks the verifying key. Make the query return a key you control.',
      how: 'Inject SQL through the kid header so the lookup returns your own key, then sign an admin token with it.',
    },
    {
      id: 'jku',
      name: 'Untrusted jku Key Server',
      difficulty: 'Hard',
      hint: 'The server fetches whatever URL the jku header names and trusts the keys it finds. You run a key server in this lab.',
      how: 'Publish your own key on the in-lab attacker key server, point a token\'s jku header at it, sign as admin.',
    },
    {
      id: 'alg-confusion',
      name: 'RS256 / HS256 Algorithm Confusion',
      difficulty: 'Hard',
      hint: 'The server verifies RS256 but also accepts HS256. For HS256 it needs a shared secret. Which "secret" does it use, and who else can read it?',
      how: 'Take the published RSA public key, use it as the HMAC secret to sign an HS256 admin token, and submit it.',
    },
    {
      id: 'no-expiry',
      name: 'Expiry Never Checked',
      difficulty: 'Easy',
      hint: 'The leaked admin token expired an hour ago. The verifier never looks at the exp claim. Replay it.',
      how: 'Copy the expired admin token from the challenge page and submit it as-is.',
    },
    {
      id: 'aud-bypass',
      name: 'Audience Not Validated',
      difficulty: 'Medium',
      hint: 'A token minted for billing-service is still a validly signed token. This service never checks who the token was minted for.',
      how: 'Submit the partner token (aud "billing-service", admin role) to this service\'s login.',
    },
    {
      id: 'kid-default',
      name: 'Default Key for Missing kid',
      difficulty: 'Medium',
      hint: 'Tokens without a kid header fall back to a hardcoded default key. Developers pick very predictable defaults.',
      how: 'Guess the default key, sign a kid-less admin token with it, and submit it.',
    },
  ],
  router,
};
