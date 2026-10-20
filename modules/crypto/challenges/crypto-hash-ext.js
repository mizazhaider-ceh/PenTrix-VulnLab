'use strict';
// Hash length extension: MAC = SHA-256(secret || message). The Merkle-Damgard
// state leaks through the digest, so a signed MAC can be extended to
// ";admin=1" without ever knowing the 16-byte secret.
const express = require('express');
const crypto = require('crypto');
const { page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

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
      <div class="clay-field">
        <label for="msg">Message to sign</label>
        <input class="clay-input" id="msg" name="msg" size="40" value="role=user" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Sign</button>
    </form>
    <p class="note">Scripting: <code>GET /crypto/mac/sign?msg=...</code> returns
    <code>{"msg": "...", "mac": "..."}</code>.</p>
    <hr />
    <h3>Verify a forged MAC</h3>
    <p>Submit the <b>hex-encoded</b> full message (original + padding + suffix)
    and the forged MAC. The message must contain <code>;admin=1</code> and the
    MAC must verify.</p>
    <form method="POST" action="/crypto/mac/verify">
      <div class="clay-field">
        <label for="msghex">Extended message (hex)</label>
        <input class="clay-input" id="msghex" name="msghex" size="70" placeholder="hex of your extended message" />
      </div>
      <div class="clay-field">
        <label for="mac">Forged MAC</label>
        <input class="clay-input" id="mac" name="mac" size="70" placeholder="forged sha256 hex" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Verify</button>
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
      ${fixPanel('crypto', 'crypto-hash-ext')}
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

module.exports = {
  vuln: {
    id: 'crypto-hash-ext',
    name: 'Hash Length Extension',
    difficulty: 'Hard',
    est: '25-45 minutes',
    hint: 'SHA-256(secret || message) leaks its internal state in the digest. The secret is 16 bytes: rebuild the glue padding and continue the hash with ";admin=1".',
    hints: ["The MAC is SHA-256(secret || message). In Burp, proxy the sign request for role=user: the returned digest IS the leaked Merkle-Damgard internal state.", "Nudge: rebuild the glue padding yourself for 16 + len(message) bytes (0x80, zero bytes, then the total bit length as 64-bit big-endian). Burp Decoder will not do this step for you.", "Send the extended request in Repeater: restore the digest as your compression state, continue the hash with ;admin=1 in a tiny script, then submit the full message as hex plus the forged MAC to POST /crypto/mac/verify."],
    tools: 'BZ, P',
    how: 'The MAC is a plain hash of secret-then-message. A Merkle-Damgard hash can be continued from its own output, if you can rebuild what sits in the middle.',
    link: '/crypto#crypto-hash-ext',
    start: 'In Burp Proxy, browse to /crypto/mac and submit the signing form with msg=role=user. Capture the response in Repeater, then build the forged request to POST /crypto/mac/verify there.',
  },
  router,
};
