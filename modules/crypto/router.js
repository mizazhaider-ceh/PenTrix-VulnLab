// PenTrix VulnLab module: Cryptographic Failures (crypto)
// Eight labs built only on Node's built-in crypto: weak randomness, an ECB
// oracle, CBC bit-flipping, SHA-256 length extension, MD5 password cracking,
// base64 "encryption", repeating-key XOR crib-dragging, and a key leaked in JS.
const express = require('express');
const crypto = require('crypto');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const BRIEF_HTML = `
<p><b>What fails here?</b> Not the ciphers themselves: AES, SHA-256 and friends
are fine. What fails is <i>how they are used</i>: predictable random numbers,
ECB mode leaking structure, malleable CBC cookies, MACs built as
<code>hash(secret || message)</code>, fast unsalted password hashes, base64
masquerading as encryption, short repeating XOR keys, and secret keys shipped
to the browser.</p>
<p><b>The goal in this module:</b> break each misuse with real technique. Every
challenge page shows you the exact attack surface: the oracle to query, the
cookie to forge, the hash to extend, the ciphertext to decrypt.</p>
<p>Keys and secrets are random per server boot, so restart the lab for a fresh game.</p>`;

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const done = captured(req, 'crypto', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="${v.path}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');
  res.send(page('Cryptographic Failures', `
    ${brief('Module briefing', BRIEF_HTML)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

// ------------------------------------------------- v1: predictable reset PIN
let resetPin = null;

router.get('/pin', (req, res) => {
  res.send(page('Predictable Reset PIN', `
    <h2>Password reset</h2>
    <p>Click below and we will text a 6-digit reset PIN to the demo account's
    (imaginary) phone. Then prove you received it.</p>
    <form method="POST" action="/crypto/pin/generate">
      <button type="submit">Generate reset PIN</button>
    </form>
    <p>PIN status: <b>${resetPin === null ? 'no PIN issued yet' : 'a PIN is active (it was "sent" to the phone)'}</b></p>
    <hr />
    <h3>Enter PIN</h3>
    <form method="POST" action="/crypto/pin/verify">
      <input name="pin" size="10" maxlength="6" placeholder="000000" />
      <button type="submit">Verify</button>
    </form>
    <p class="note">There is no rate limiting on purpose. A 6-digit space is only
    one million guesses: script it.</p>
  `));
});

router.post('/pin/generate', (req, res) => {
  // VULN: Math.random is not cryptographically secure, and 10^6 guesses with
  // no rate limiting is a trivially brute-forceable space.
  resetPin = String(Math.floor(Math.random() * 1e6)).padStart(6, '0');
  res.redirect('/crypto/pin');
});

router.post('/pin/verify', (req, res) => {
  const guess = (req.body.pin || '').toString().trim();
  if (resetPin !== null && guess === resetPin) {
    const flag = award(req, 'crypto', 'crypto-rand-pin');
    return res.send(page('PIN accepted', `
      <h2>Reset authorized</h2>
      <p>PIN <code>${esc(guess)}</code> accepted. You brute-forced the whole
      6-digit space.</p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.status(401).send(page('Wrong PIN', `
    <h2>Wrong PIN</h2>
    <p><code>${esc(guess) || '(empty)'}</code> is not the active PIN. Keep guessing:
    there is no lockout.</p>
    <p><a href="/crypto/pin">Back</a></p>
  `));
});

// ------------------------------------------------------ v2: ECB oracle
const ecbKey = crypto.randomBytes(16);
const ecbSecret = crypto.randomBytes(20).toString('base64'); // 28 printable chars
function ecbEncrypt(buf) {
  // VULN: AES-128-ECB on attacker_prefix || secret. ECB leaks block equality,
  // so a byte-at-a-time attack recovers the secret.
  const c = crypto.createCipheriv('aes-128-ecb', ecbKey, null);
  return Buffer.concat([c.update(buf), c.final()]);
}

router.get('/ecb', (req, res) => {
  const secretCt = ecbEncrypt(Buffer.alloc(0)).toString('hex');
  res.send(page('ECB Decryption Oracle', `
    <h2>Secret vault (AES-128-ECB)</h2>
    <p>The vault encrypts <b>your input followed by a secret</b> with AES-128-ECB
    under a random key, PKCS#7 padded. ECB encrypts identical plaintext blocks
    to identical ciphertext blocks.</p>
    <h3>Encryption oracle</h3>
    <form method="POST" action="/crypto/ecb/encrypt">
      <input name="input" size="50" placeholder="your prefix (printable text)" />
      <button type="submit">Encrypt</button>
    </form>
    <p class="note">Scripting? POST <code>input=...</code> (text, max 64 chars) or
    <code>inhex=...</code> (raw bytes as hex) to <code>/crypto/ecb/encrypt</code>;
    the hex ciphertext is in <code>&lt;code id="ct"&gt;</code>.</p>
    <h3>Secret ciphertext</h3>
    <p>Encryption of the secret alone (empty prefix):</p>
    <p><code>${secretCt}</code></p>
    <hr />
    <h3>Submit the recovered secret</h3>
    <form method="POST" action="/crypto/ecb/solve">
      <input name="plaintext" size="50" placeholder="decrypted secret" />
      <button type="submit">Claim flag</button>
    </form>
    <p class="note">Steps: find the block size, confirm ECB with a repeated block,
    then decrypt byte-at-a-time.</p>
  `));
});

router.post('/ecb/encrypt', (req, res) => {
  let buf;
  const hex = (req.body.inhex || '').toString().trim();
  if (hex) {
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0 || hex.length > 128) {
      return res.status(400).send('<p>Bad hex input.</p>');
    }
    buf = Buffer.from(hex, 'hex');
  } else {
    buf = Buffer.from((req.body.input || '').toString(), 'utf8');
  }
  if (buf.length > 64) return res.status(400).send('<p>Input too long (max 64 bytes).</p>');
  const ct = ecbEncrypt(Buffer.concat([buf, Buffer.from(ecbSecret, 'utf8')]));
  res.send(page('Oracle output', `
    <h2>Ciphertext</h2>
    <p><code id="ct">${ct.toString('hex')}</code></p>
    <p><a href="/crypto/ecb">Back to the oracle</a></p>
  `));
});

router.post('/ecb/solve', (req, res) => {
  const pt = (req.body.plaintext || '').toString();
  if (pt === ecbSecret) {
    const flag = award(req, 'crypto', 'crypto-ecb-oracle');
    return res.send(page('Secret recovered', `
      <h2>Byte-at-a-time decryption worked</h2>
      <p>You recovered the full secret: <code>${esc(pt)}</code></p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.status(400).send(page('Wrong secret', `
    <h2>Not the secret</h2>
    <p><code>${esc(pt) || '(empty)'}</code> does not match the vault secret.</p>
    <p><a href="/crypto/ecb">Back to the oracle</a></p>
  `));
});

// ------------------------------------------------------ v3: CBC bit-flipping
const cbcKey = crypto.randomBytes(16);
function mintRoleCookie() {
  const iv = crypto.randomBytes(16);
  // Layout: {"role":"guest","user":"guest"} (31 bytes). role sits in block 0,
  // so flipping IV bits flips the role plaintext. 'guest' -> 'admin' is 5:5.
  const pt = Buffer.from(JSON.stringify({ role: 'guest', user: 'guest' }), 'utf8');
  const c = crypto.createCipheriv('aes-128-cbc', cbcKey, iv);
  return Buffer.concat([iv, c.update(pt), c.final()]).toString('base64');
}
function readRoleCookie(b64) {
  const raw = Buffer.from(b64, 'base64');
  if (raw.length < 32 || raw.length % 16 !== 0) throw new Error('bad cookie length');
  const iv = raw.subarray(0, 16);
  const ct = raw.subarray(16);
  const d = crypto.createDecipheriv('aes-128-cbc', cbcKey, iv);
  return JSON.parse(Buffer.concat([d.update(ct), d.final()]).toString('utf8'));
}

router.get('/cbc', (req, res) => {
  let seen = null;
  try { seen = readRoleCookie(req.cookies.vlab_cbc || '').role; } catch (e) { /* no/invalid cookie */ }
  res.send(page('CBC Bit-Flipping', `
    <h2>Role cookie (AES-128-CBC)</h2>
    <p>Your session is <code>base64(iv || AES-128-CBC(iv, '{"role":"guest","user":"guest"}'))</code>.
    CBC decryption XORs each ciphertext block with the previous one, so flipping
    a bit in the IV (or in ciphertext block N) flips the same bit in plaintext
    block N+1. The role value lives in block 0, right under the IV.</p>
    <form method="POST" action="/crypto/cbc/login">
      <button type="submit">Mint a guest cookie</button>
    </form>
    <p>Server currently sees you as role: <b>${esc(seen === null ? '(no valid cookie)' : String(seen))}</b></p>
    <hr />
    <h3>Forge a cookie</h3>
    <p>Paste your bit-flipped cookie (base64). If it decrypts to valid JSON with
    <code>role === 'admin'</code>, you win.</p>
    <form method="POST" action="/crypto/cbc/check">
      <textarea name="cookie" rows="4" cols="70" placeholder="base64(iv || ciphertext)"></textarea><br /><br />
      <button type="submit">Submit forged cookie</button>
    </form>
    <p class="note">You know the full plaintext and the layout. XOR the IV bytes
    sitting over <code>"guest"</code> with <code>"guest" xor "admin"</code>.</p>
  `));
});

router.post('/cbc/login', (req, res) => {
  const v = mintRoleCookie();
  res.cookie('vlab_cbc', v, { httpOnly: false });
  res.send(page('Guest cookie minted', `
    <h2>Cookie minted</h2>
    <p>Your cookie (also set as <code>vlab_cbc</code>):</p>
    <p><code id="ck">${v}</code></p>
    <p>Now flip it: <a href="/crypto/cbc">back to the challenge</a>.</p>
  `));
});

router.post('/cbc/check', (req, res) => {
  const forged = (req.body.cookie || '').toString().trim();
  let data;
  try {
    // VULN: CBC malleability is not integrity: bit flips in the IV produce
    // predictable plaintext changes and the server still accepts the cookie.
    data = readRoleCookie(forged);
  } catch (e) {
    return res.status(400).send(page('Bad cookie', `
      <h2>Cookie rejected</h2>
      <p>Decryption failed: <code>${esc(e.message)}</code>. A flipped bit must
      not break the JSON structure or the padding.</p>
      <p><a href="/crypto/cbc">Back</a></p>
    `));
  }
  if (data && data.role === 'admin') {
    const flag = award(req, 'crypto', 'crypto-cbc-bitflip');
    return res.send(page('Admin cookie accepted', `
      <h2>Forged cookie accepted</h2>
      <p>The server decrypted your cookie and sees <code>role = 'admin'</code>.
      IV bit-flipping worked.</p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.send(page('Cookie accepted', `
    <h2>Valid cookie, wrong role</h2>
    <p>The server decrypted your cookie and sees <code>role = ${esc(String(data && data.role))}</code>.
    You need <code>admin</code>.</p>
    <p><a href="/crypto/cbc">Back</a></p>
  `));
});

// ------------------------------------------------------ v4: hash length extension
const macSecret = crypto.randomBytes(16); // 16 bytes; the hint states the length
function macOf(buf) {
  // VULN: MAC = SHA-256(secret || message). Merkle-Damgard hashes leak their
  // internal state in the digest, so the MAC can be extended to new messages.
  return crypto.createHash('sha256').update(macSecret).update(buf).digest('hex');
}

router.get('/mac', (req, res) => {
  res.send(page('Hash Length Extension', `
    <h2>Signed downloads (SHA-256(secret || message))</h2>
    <p>The server authenticates messages with <code>SHA-256(secret || message)</code>,
    where <code>secret</code> is a <b>16-byte</b> server-side key you never see.
    The signing endpoint refuses any message containing <code>admin</code>.</p>
    <h3>Signing oracle</h3>
    <form method="GET" action="/crypto/mac/sign">
      <input name="msg" size="40" value="role=user" />
      <button type="submit">Sign</button>
    </form>
    <p class="note">Scripting: <code>GET /crypto/mac/sign?msg=...</code> returns
    <code>{"msg": "...", "mac": "..."}</code>.</p>
    <hr />
    <h3>Verify a forged MAC</h3>
    <p>Submit the <b>hex-encoded</b> full message (original + padding + suffix)
    and the forged MAC. The message must contain <code>;admin=1</code> and the
    MAC must verify.</p>
    <form method="POST" action="/crypto/mac/verify">
      <input name="msghex" size="70" placeholder="hex of role=user || padding || ;admin=1" /><br /><br />
      <input name="mac" size="70" placeholder="forged sha256 hex" /><br /><br />
      <button type="submit">Verify</button>
    </form>
    <p class="note">Implement SHA-256 length extension in pure code: take the MAC
    of <code>role=user</code> as your compression state, append the glue padding
    for (16 + len) bytes, then hash <code>;admin=1</code> on top.</p>
  `));
});

router.get('/mac/sign', (req, res) => {
  const msg = (req.query.msg || '').toString().slice(0, 200);
  if (msg.includes('admin')) {
    return res.status(400).json({ error: 'signing messages containing "admin" is not allowed' });
  }
  res.json({ msg, mac: macOf(Buffer.from(msg, 'utf8')) });
});

router.post('/mac/verify', (req, res) => {
  const msgHex = (req.body.msghex || '').toString().trim().toLowerCase();
  const mac = (req.body.mac || '').toString().trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(msgHex) || msgHex.length % 2 !== 0 || !/^[0-9a-f]{64}$/.test(mac)) {
    return res.status(400).send(page('Bad input', '<p>msghex must be even-length hex and mac 64 hex chars.</p><p><a href="/crypto/mac">Back</a></p>'));
  }
  const msgBuf = Buffer.from(msgHex, 'hex');
  const good = macOf(msgBuf) === mac;
  const isAdmin = msgBuf.includes(Buffer.from(';admin=1', 'utf8'));
  if (good && isAdmin) {
    const flag = award(req, 'crypto', 'crypto-hash-ext');
    return res.send(page('MAC forged', `
      <h2>Length extension worked</h2>
      <p>Your MAC verifies for a message containing <code>;admin=1</code> that
      was never signed. The Merkle-Damgard state leaked through the digest.</p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.status(400).send(page('MAC rejected', `
    <h2>Not accepted</h2>
    <p>MAC valid: <b>${good}</b>. Message contains <code>;admin=1</code>: <b>${isAdmin}</b>.
    You need both.</p>
    <p><a href="/crypto/mac">Back</a></p>
  `));
});

// ------------------------------------------------------ v5: MD5 password cracking
const MD5_WORDLIST = [
  'password', '123456', '123456789', 'qwerty', 'abc123', 'letmein', 'welcome',
  'monkey', 'dragon', 'sunshine', 'princess', 'football', 'charlie', 'aa123456',
  'donald', 'password1', 'qwerty123', 'michael', 'shadow', 'master', 'jennifer',
  'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger',
  'sunset', 'superman', 'qazwsx', 'maggie', 'ferrari', 'jordan', 'mustang',
  'pepper', 'joshua', 'ginger', 'solo', 'summer', 'trustno1', 'michelle',
  'butter', 'corvette', 'thunder', 'ranger', 'thomas', 'taylor',
];
const MD5_PASSWORD = 'sunshine'; // deliberately in the wordlist
const md5Target = crypto.createHash('md5').update(MD5_PASSWORD).digest('hex');

router.get('/md5/wordlist.txt', (req, res) => {
  res.type('text/plain').send(MD5_WORDLIST.join('\n') + '\n');
});

router.get('/md5', (req, res) => {
  res.send(page('Crack the MD5', `
    <h2>Leaked password hash</h2>
    <p>An old backup leaked this unsalted MD5 hash of the demo account password:</p>
    <p><code id="hash">${md5Target}</code></p>
    <p>The password is weak and comes from our
    <a href="/crypto/md5/wordlist.txt">in-lab wordlist</a>. Crack it, then log in.</p>
    <hr />
    <h3>Login</h3>
    <form method="POST" action="/crypto/md5/login">
      <input name="username" value="demo" readonly /><br /><br />
      <input name="password" type="password" placeholder="cracked password" /><br /><br />
      <button type="submit">Log in</button>
    </form>
  `));
});

router.post('/md5/login', (req, res) => {
  const pw = (req.body.password || '').toString();
  // VULN: unsalted, fast MD5 of a dictionary password: crackable offline.
  if (crypto.createHash('md5').update(pw).digest('hex') === md5Target) {
    const flag = award(req, 'crypto', 'crypto-md5-crack');
    return res.send(page('Logged in', `
      <h2>Welcome back</h2>
      <p>Password <code>${esc(pw)}</code> matches the leaked hash. Dictionary
      attack successful.</p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.status(401).send(page('Login failed', `
    <h2>Login failed</h2>
    <p>That password does not match the leaked hash.</p>
    <p><a href="/crypto/md5">Back</a></p>
  `));
});

// ------------------------------------------------------ v6: base64 "encryption"
router.get('/b64', (req, res) => {
  let seen = null;
  try {
    seen = JSON.parse(Buffer.from(req.cookies.vlab_b64 || '', 'base64').toString('utf8'));
  } catch (e) { /* no/invalid cookie */ }
  res.send(page('Base64 "Encryption"', `
    <h2>Encrypted session cookie</h2>
    <p>For performance, sessions are "encrypted" into a cookie. Take a look:</p>
    <form method="POST" action="/crypto/b64/login">
      <button type="submit">Get a session cookie</button>
    </form>
    <p>Server decodes your current cookie as: <code>${esc(seen === null ? '(no valid cookie)' : JSON.stringify(seen))}</code></p>
    <hr />
    <h3>Forge a session</h3>
    <p>Paste a modified cookie. If it decodes to JSON with
    <code>role === 'admin'</code>, you win.</p>
    <form method="POST" action="/crypto/b64/check">
      <textarea name="cookie" rows="3" cols="70" placeholder="base64 session cookie"></textarea><br /><br />
      <button type="submit">Submit forged cookie</button>
    </form>
  `));
});

router.post('/b64/login', (req, res) => {
  // VULN: the "encryption" is just base64: decode it, edit the JSON, re-encode.
  const v = Buffer.from(JSON.stringify({ user: 'guest', role: 'user' }), 'utf8').toString('base64');
  res.cookie('vlab_b64', v, { httpOnly: false });
  res.send(page('Session issued', `
    <h2>Session cookie issued</h2>
    <p>Your "encrypted" session (also set as <code>vlab_b64</code>):</p>
    <p><code id="ck">${v}</code></p>
    <p><a href="/crypto/b64">Back to the challenge</a></p>
  `));
});

router.post('/b64/check', (req, res) => {
  const c = (req.body.cookie || '').toString().trim();
  let data;
  try {
    data = JSON.parse(Buffer.from(c, 'base64').toString('utf8'));
  } catch (e) {
    return res.status(400).send(page('Bad cookie', `
      <h2>Cookie rejected</h2>
      <p>Not valid base64 JSON: <code>${esc(e.message)}</code></p>
      <p><a href="/crypto/b64">Back</a></p>
    `));
  }
  if (data && data.role === 'admin') {
    const flag = award(req, 'crypto', 'crypto-b64-cookie');
    return res.send(page('Admin session accepted', `
      <h2>Welcome, admin</h2>
      <p>You decoded the cookie, flipped <code>role</code> to
      <code>admin</code>, and re-encoded it. There was never any encryption.</p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.send(page('Session checked', `
    <h2>Valid session, wrong role</h2>
    <p>Decoded session: <code>${esc(JSON.stringify(data))}</code>. You need
    <code>role = 'admin'</code>.</p>
    <p><a href="/crypto/b64">Back</a></p>
  `));
});

// ------------------------------------------------------ v7: XOR crib-dragging
const xorKey = crypto.randomBytes(8); // short repeating key: the whole flaw
const xorPt = `{"user":"guest","token":"${crypto.randomBytes(8).toString('hex')}"}`;
const xorCt = Buffer.from(xorPt, 'utf8').map((b, i) => b ^ xorKey[i % xorKey.length]);

router.get('/xor', (req, res) => {
  res.send(page('XOR Crib Dragging', `
    <h2>Repeating-key XOR vault</h2>
    <p>A secret JSON document was encrypted with a <b>short repeating XOR key</b>
    (key length is between 1 and 12 bytes). Ciphertext:</p>
    <p><code id="ct">${xorCt.toString('hex')}</code></p>
    <p>You know every JSON document here starts with the header
    <code>{"user":"</code>. XOR the known header against the ciphertext to
    recover key bytes (crib-dragging), then decrypt the rest.</p>
    <hr />
    <h3>Submit the recovered plaintext</h3>
    <form method="POST" action="/crypto/xor/solve">
      <input name="plaintext" size="70" placeholder='{"user":"guest",...}' />
      <button type="submit">Claim flag</button>
    </form>
    <p class="note">Try each key length 1..12: derive the key from the crib, decrypt,
    keep the one that yields valid JSON.</p>
  `));
});

router.post('/xor/solve', (req, res) => {
  const pt = (req.body.plaintext || '').toString();
  // VULN: repeating-key XOR with a short key falls to known-plaintext crib-dragging.
  if (pt === xorPt) {
    const flag = award(req, 'crypto', 'crypto-xor-crib');
    return res.send(page('Plaintext recovered', `
      <h2>Key recovered, message decrypted</h2>
      <p>Full plaintext: <code>${esc(pt)}</code></p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.status(400).send(page('Wrong plaintext', `
    <h2>Not the plaintext</h2>
    <p><code>${esc(pt) || '(empty)'}</code> does not match the vault document.</p>
    <p><a href="/crypto/xor">Back</a></p>
  `));
});

// ------------------------------------------------------ v8: key in JavaScript
const JS_KEY = 'PenTrixKey2026!!'; // 16 bytes, hardcoded in the served JS: the flaw
const jsIv = crypto.randomBytes(16);
const JS_MSG = 'Vault combination: 04-17-2026. Do not share.';
const jsCt = (() => {
  const c = crypto.createCipheriv('aes-128-cbc', Buffer.from(JS_KEY, 'utf8'), jsIv);
  return Buffer.concat([jsIv, c.update(Buffer.from(JS_MSG, 'utf8')), c.final()]).toString('hex');
})();

router.get('/keyjs/app.js', (req, res) => {
  res.type('application/javascript').send(
`// dashboard.js - frontend bundle v2.4.1
// Notes are encrypted client-side before upload, so the server never sees them.
const ENCRYPTION_KEY = '${JS_KEY}'; // VULN: AES key shipped to every browser
const API_BASE = '/api/v2';

function saveNote(text) {
  // (demo) encrypt with AES-128-CBC, random IV, prepend IV to ciphertext
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  return { iv: iv, note: text, keyHint: 'see ENCRYPTION_KEY' };
}

function renderDashboard(user) {
  document.title = 'Dashboard - ' + user;
}
`);
});

router.get('/keyjs', (req, res) => {
  res.send(page('Key in JavaScript', `
    <h2>Client-side encrypted vault note</h2>
    <p>The frontend encrypts vault notes with AES-128-CBC before uploading them.
    The IV is prepended to the ciphertext. Here is one encrypted note:</p>
    <p><code id="ct">${jsCt}</code></p>
    <p>The encryption key must live somewhere the frontend can use it. Check the
    served JavaScript: <a href="/crypto/keyjs/app.js"><code>/crypto/keyjs/app.js</code></a></p>
    <hr />
    <h3>Submit the decrypted note</h3>
    <form method="POST" action="/crypto/keyjs/solve">
      <input name="plaintext" size="70" placeholder="decrypted note text" />
      <button type="submit">Claim flag</button>
    </form>
  `));
});

router.post('/keyjs/solve', (req, res) => {
  const pt = (req.body.plaintext || '').toString();
  if (pt === JS_MSG) {
    const flag = award(req, 'crypto', 'crypto-key-in-js');
    return res.send(page('Note decrypted', `
      <h2>Decrypted offline</h2>
      <p>Note: <code>${esc(pt)}</code></p>
      <p>A key the browser can read is a key the attacker can read.</p>
      ${flagBox(flag)}
      <p><a href="/crypto">Back to the module</a></p>
    `));
  }
  res.status(400).send(page('Wrong plaintext', `
    <h2>Not the note</h2>
    <p><code>${esc(pt) || '(empty)'}</code> is not the decrypted note.</p>
    <p><a href="/crypto/keyjs">Back</a></p>
  `));
});

module.exports = {
  id: 'crypto',
  name: 'Cryptographic Failures',
  tagline: 'Break real crypto misuses: weak randomness, ECB oracles, CBC bit-flipping, length extension, and more.',
  description: 'The ciphers are fine; their usage is not. Eight hands-on labs built only on Node built-in crypto: brute-force a Math.random PIN, decrypt byte-at-a-time through an ECB oracle, flip CBC bits to forge an admin cookie, extend a SHA-256 MAC, crack an MD5 password, peel base64 "encryption", crib-drag a repeating XOR key, and steal an AES key from served JavaScript.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'crypto-rand-pin',
      name: 'Predictable Reset PIN',
      difficulty: 'Easy',
      hint: 'The 6-digit PIN comes from Math.random and nothing stops you from guessing. One million guesses is a script, not a chore.',
      how: 'Generate a PIN, then brute-force all 000000-999999 against the verify endpoint.',
      path: '/crypto/pin',
    },
    {
      id: 'crypto-ecb-oracle',
      name: 'ECB Decryption Oracle',
      difficulty: 'Hard',
      hint: 'Identical plaintext blocks give identical ciphertext blocks. Align your input so the unknown byte sits at the end of a block, then try all 256 values.',
      how: 'Find the block size, confirm ECB, then decrypt the secret byte-at-a-time and submit it.',
      path: '/crypto/ecb',
    },
    {
      id: 'crypto-cbc-bitflip',
      name: 'CBC Bit-Flipping',
      difficulty: 'Hard',
      hint: 'CBC decryption XORs each block with the previous ciphertext (or IV). You know the full plaintext and the layout: role sits in block 0, under the IV.',
      how: 'XOR the IV bytes over "guest" with ("guest" xor "admin") and submit the forged cookie.',
      path: '/crypto/cbc',
    },
    {
      id: 'crypto-hash-ext',
      name: 'Hash Length Extension',
      difficulty: 'Hard',
      hint: 'SHA-256(secret || message) leaks its internal state in the digest. The secret is 16 bytes: rebuild the glue padding and continue the hash with ";admin=1".',
      how: 'Get a MAC for "role=user", forge a MAC for the extended message in pure code, and submit msghex + mac.',
      path: '/crypto/mac',
    },
    {
      id: 'crypto-md5-crack',
      name: 'Crack the MD5',
      difficulty: 'Easy',
      hint: 'Unsalted MD5 of a weak password. The password is in the in-lab wordlist: hash every candidate until one matches.',
      how: 'Crack the hash with the wordlist, then log in with the password.',
      path: '/crypto/md5',
    },
    {
      id: 'crypto-b64-cookie',
      name: 'Base64 "Encryption"',
      difficulty: 'Easy',
      hint: 'Look closely at the "encrypted" cookie. Does it look random, or does it look like something you can decode?',
      how: 'Decode the cookie, change role to admin in the JSON, re-encode, and submit it.',
      path: '/crypto/b64',
    },
    {
      id: 'crypto-xor-crib',
      name: 'XOR Crib Dragging',
      difficulty: 'Medium',
      hint: 'The key repeats every few bytes and you know the plaintext header {"user":". XOR crib against ciphertext to recover the key, trying lengths 1-12.',
      how: 'Recover the repeating key with the known header, decrypt the full ciphertext, and submit the plaintext.',
      path: '/crypto/xor',
    },
    {
      id: 'crypto-key-in-js',
      name: 'Key in JavaScript',
      difficulty: 'Easy',
      hint: 'The frontend encrypts, so the frontend must know the key. Read the served JavaScript file.',
      how: 'Find the hardcoded AES key in app.js, decrypt the ciphertext offline, and submit the note.',
      path: '/crypto/keyjs',
    },
  ],
  router,
};
