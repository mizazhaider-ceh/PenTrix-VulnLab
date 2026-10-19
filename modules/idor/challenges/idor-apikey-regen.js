'use strict';
// API Key Regeneration IDOR: regeneration trusts a client-supplied user_id.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../../lib/db');
const { esc, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { deny, requireUser, shopPage } = require('../shared');

const router = express.Router();

router.get('/apikey', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const mine = getDb().prepare('SELECT api_key FROM idor_apikeys WHERE user_id = ?').get(u.id);
  res.send(shopPage(u, 'API keys', `
    ${payloadBlock('Your API key', mine.api_key)}
    <form class="clay-card" method="POST" action="/idor/apikey/regen">
      <div class="card-top"><b>Regenerate key</b></div>
      <p class="dim">Rotating your key invalidates the old one immediately.</p>
      <input type="hidden" name="user_id" value="${Number(u.id)}">
      <button type="submit" class="clay-btn clay-btn-primary">Regenerate my key</button>
    </form>
    <form class="clay-card" method="GET" action="/idor/apikey/use">
      <div class="card-top"><b>Check a key</b></div>
      <div class="clay-field">
        <label for="key">API key</label>
        <input class="clay-input" id="key" name="key" type="text" placeholder="idor_..." required>
      </div>
      <button type="submit" class="clay-btn clay-btn-secondary">Check key</button>
    </form>
    ${hintLadder(module.exports.vuln)}
  `));
});

router.post('/apikey/regen', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const targetId = parseInt(req.body.user_id, 10);
  const target = getDb().prepare('SELECT id, username FROM users WHERE id = ?').get(targetId);
  if (!target) {
    return deny(res, 400, 'Bad request',
      '<p class="muted">A valid account is required.</p><p><a href="/idor/apikey">Back to API keys</a></p>');
  }
  // VULN: key regeneration takes a client-supplied user_id and never checks
  // that it belongs to the caller, so you can rotate anyone's key and then
  // use the fresh value yourself.
  const fresh = 'idor_' + crypto.randomBytes(12).toString('hex');
  const db = getDb();
  db.prepare(
    'INSERT INTO idor_apikeys (user_id, api_key) VALUES (?,?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET api_key = excluded.api_key'
  ).run(target.id, fresh);
  db.prepare('INSERT OR REPLACE INTO idor_apikey_rotations (api_key, via_idor, by_user_id) VALUES (?,?,?)')
    .run(fresh, target.id !== u.id ? 1 : 0, u.id);
  res.send(shopPage(u, 'Key regenerated', `
    <div class="note"><p>New API key for <strong>${esc(target.username)}</strong> (id ${Number(target.id)}):</p></div>
    ${payloadBlock('New API key', fresh)}
    <p>
      <a class="clay-btn clay-btn-primary clay-btn-sm" href="/idor/apikey/use?key=${encodeURIComponent(fresh)}">Use this key</a>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/idor/apikey">Back to API keys</a>
    </p>
  `));
});

router.get('/apikey/use', (req, res) => {
  const u = requireUser(req, res);
  if (!u) return;
  const key = String(req.query.key || '');
  const row = getDb().prepare(
    'SELECT k.user_id, u.username FROM idor_apikeys k JOIN users u ON u.id = k.user_id WHERE k.api_key = ?'
  ).get(key);
  if (!row) {
    return deny(res, 401, 'Unknown API key',
      '<p class="muted">That key is not valid.</p><p><a href="/idor/apikey">Back to API keys</a></p>');
  }
  let flagHtml = '';
  // Award: authenticating with another user's key that YOU rotated for them
  // through the IDOR. Reusing a key you were merely shown (or that someone
  // else rotated and shared with you) does not count.
  const rotation = getDb().prepare('SELECT via_idor, by_user_id FROM idor_apikey_rotations WHERE api_key = ?').get(key);
  if (row.user_id !== u.id && u.role !== 'admin' && rotation && rotation.via_idor === 1 && rotation.by_user_id === u.id) {
    flagHtml = flagBox(award(req, 'idor', 'idor-apikey-regen')) + fixPanel('idor', 'idor-apikey-regen');
  }
  res.send(shopPage(u, 'API key check', `
    <div class="note"><p>This key belongs to <strong>${esc(row.username)}</strong> (id ${Number(row.user_id)}).</p></div>
    ${flagHtml}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/idor/apikey">Back to API keys</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'idor-apikey-regen',
    name: 'API Key Regeneration IDOR',
    difficulty: 'Medium',
    hint: 'The regenerate form on /idor/apikey trusts the user_id you submit. Regenerate admin\'s key (id 1), then authenticate with the fresh key at /idor/apikey/use?key=....',
    hints: [
      'You can regenerate YOUR api key. The request carries an account id. Whose key could you regenerate?',
      'The regenerate endpoint trusts the submitted user_id. Rotate the admin\'s key, then use the fresh value.',
      'POST /idor/apikey/regen with another account\'s user_id, then open /idor/apikey/use?key=<new-key> with the key it returns.',
    ],
    tools: 'B, C',
    how: 'Regenerate another user\'s API key via their id, then use the new key at /idor/apikey/use.',
    link: '/idor#idor-apikey-regen',
    start: 'curl -s -c jar -L http://localhost:3000/idor/login/alice\ncurl -s -b jar http://localhost:3000/idor/apikey',
  },
  router,
};
