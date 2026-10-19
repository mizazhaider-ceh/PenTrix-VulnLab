'use strict';
// Avatar overwrite: avatar filenames are predictable ("avatar-<user>.png")
// and anyone may write any user's file, so another user's avatar can be
// overwritten. Bob already has an avatar; replace his bytes with yours to
// capture the flag. Shared storage config and the raw-body uploader live in
// ../shared.js (created by the module finisher).
const express = require('express');
const fs = require('fs');
const { award } = require('../../../lib/flags');
const {
  appShell, brief, esc, fixPanel, flagBox, hintLadder, page, payloadBlock, toolsPill,
} = require('../../../lib/page');
const { avatarPath, AVATAR_ORIGINAL, AVATAR_VICTIM, rawUpload } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'upload-overwrite',
  name: 'Avatar overwrite',
  difficulty: 'Medium',
  hint: 'Avatar paths are predictable (avatar-<user>.png) and the endpoint never checks that you own the target user. Bob already has an avatar.',
  hints: [
    "Avatars are stored at a predictable path per user. Can you write to someone else's path?",
    "Capture the avatar upload in Burp Proxy, send it to Repeater, and change the target username in the query string.",
    "KEY INSIGHT: the avatar storage path is derived from the username with no ownership check. In Repeater, craft the request so the stored name collides with the victim's existing avatar path, replacing their avatar with your content.",
  ],
  tools: 'BZ, C',
  how: 'Send your bytes to POST /upload/avatar?user=bob (Burp Repeater is the natural fit) so the victim avatar URL /upload/avatar/bob serves attacker content.',
  link: '/upload#upload-overwrite',
  start: 'In Burp Repeater: POST to /upload/avatar?user=bob with a raw body of your choosing (your own avatar bytes or markup), then GET /upload/avatar/bob to confirm the victim avatar now serves your bytes.',
};

const APP_NAME = 'PixelPortraits';
const APP_NAV = ['My Profile', 'Friends', 'Gallery'];

// Fetch-based upload widget (raw request body, same as the module's curl
// form), so the page works like the real avatar service it pretends to be.
const uploadWidget = `
<div class="clay-card">
  <h3>Upload an avatar</h3>
  <form id="avatarForm">
    <div class="clay-field">
      <label for="userInput">Username</label>
      <input class="clay-input" id="userInput" name="user" value="${esc(AVATAR_VICTIM)}" maxlength="20" autocomplete="off" />
    </div>
    <div class="clay-field">
      <label for="fileInput">Avatar file</label>
      <input class="clay-input" id="fileInput" type="file" />
    </div>
    <button class="clay-btn clay-btn-primary" type="submit">Save avatar</button>
  </form>
  <div id="uploadOut"></div>
</div>
<script>
document.getElementById('avatarForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = document.getElementById('uploadOut');
  const file = document.getElementById('fileInput').files[0];
  const user = document.getElementById('userInput').value;
  if (!file) { out.innerHTML = '<p class="clay-err">Pick a file first.</p>'; return; }
  try {
    const r = await fetch('/upload/avatar?user=' + encodeURIComponent(user), { method: 'POST', body: file });
    out.innerHTML = await r.text();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (err) { out.innerHTML = '<p class="clay-err">Upload failed: ' + err.message + '</p>'; }
});
</script>`;

function failPage(title, heading, messageHtml) {
  return page(title, appShell(APP_NAME, `
    <div class="clay-card">
      <h2>${esc(heading)}</h2>
      <p class="dim">${messageHtml}</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to module</a></p>
    </div>`, { crumb: 'Avatars / ' + vuln.name, nav: APP_NAV }));
}

// POST /upload/avatar -> the result page for this challenge.
function avatarResultPage(user, flagHtml) {
  const body = `
    ${brief('Avatar service', `
      <p><b>${esc(APP_NAME)}</b> hosts profile avatars. Every avatar is served
      from <code>/upload/avatar/&lt;user&gt;</code> to anyone who opens the
      profile. The victim's current avatar, served live:</p>
      <p><img src="/upload/avatar/${encodeURIComponent(AVATAR_VICTIM)}" alt="Victim avatar" class="clay-well" style="max-width:160px" /></p>`)}
    ${uploadWidget}
    <div class="clay-card">
      <h2>Avatar stored</h2>
      <p>Saved avatar for <code>${esc(user)}</code>.</p>
      ${flagHtml}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/upload">Back to module</a></p>
    </div>
    ${payloadBlock('Starting point', vuln.start)}
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}`;
  return page(vuln.name, appShell(APP_NAME, body, { crumb: 'Avatars / ' + vuln.name, nav: APP_NAV }));
}

// POST /upload/avatar -> v8: predictable avatar filenames, no ownership check.
router.post('/avatar', rawUpload, (req, res) => {
  const user = String(req.query.user || '').toLowerCase();
  if (!/^[a-z0-9]{1,20}$/.test(user)) {
    return res.status(400).send(failPage('Upload failed', 'Upload failed',
      'Provide <code>?user=</code> (letters and digits, max 20).'));
  }
  if (!req.body || !Buffer.isBuffer(req.body) || req.body.length === 0) {
    return res.status(400).send(failPage('Upload failed', 'Empty file',
      'No request body received.'));
  }
  // VULN: avatar filenames are predictable ("avatar-<user>.png") and anyone
  // may write any user's file, so another user's avatar can be overwritten.
  fs.writeFileSync(avatarPath(user), req.body);
  let flagHtml = '';
  if (user === AVATAR_VICTIM && !fs.readFileSync(avatarPath(user)).equals(AVATAR_ORIGINAL)) {
    flagHtml = flagBox(award(req, 'upload', 'upload-overwrite')) + fixPanel('upload', 'upload-overwrite') + `<p class="dim">Bob's avatar now serves your bytes: <a href="/upload/avatar/bob">/upload/avatar/bob</a>.</p>`;
  } else {
    flagHtml = `<p class="dim">Stored. The victim's avatar is <a href="/upload/avatar/bob">/upload/avatar/bob</a> (user <code>bob</code>).</p>`;
  }
  res.send(avatarResultPage(user, flagHtml));
});

// GET /upload/avatar/:user -> serves the stored avatar bytes. Content is
// sniffed instead of fixed, so a replaced "avatar" that starts with "<" is
// served as HTML.
router.get('/avatar/:user', (req, res) => {
  const user = String(req.params.user || '').toLowerCase();
  if (!/^[a-z0-9]{1,20}$/.test(user)) return res.status(404).send('no such avatar');
  const fp = avatarPath(user);
  if (!fs.existsSync(fp)) return res.status(404).send('no such avatar');
  const buf = fs.readFileSync(fp);
  // VULN: content sniffing instead of a fixed image type, so a replaced
  // "avatar" that starts with "<" is served as HTML.
  if (buf.length && buf[0] === 0x3c) res.type('text/html');
  else res.type('image/png');
  res.send(buf);
});

module.exports = { vuln, router };
