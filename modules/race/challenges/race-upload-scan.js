'use strict';
// Beat the AV Scan (TOCTOU): uploaded files are served immediately, but a
// simulated AV scan deletes them 2 seconds later. Fetch the file URL in the
// window between the upload and the deletion.
const express = require('express');
const { page, esc, appShell, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();
// Router-scoped form parsing (same as the original race router).
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'race-upload-scan',
  name: 'Beat the AV Scan (TOCTOU)',
  difficulty: 'Hard',
  hint: 'Uploaded files are served immediately, but a simulated AV scan deletes them 2 seconds later. The file exists in a window where it should not.',
  hints: ["The upload is scanned for 2 seconds, then deleted if bad, but the file is live during the scan. Upload through the form with Burp Proxy running.", "TOCTOU: capture the upload POST in Burp Proxy, note the file URL, and send it to Burp Repeater.", "Fetch the file URL in Repeater quickly after the upload, inside the 2-second scan window, before the scanner deletes it."],
  tools: 'BZ, B',
  how: 'Upload a file at /race/upload, then fetch /race/files/<name> with Burp Repeater inside the 2-second scan window, before the scanner deletes it.',
  link: '/race#race-upload-scan',
  start: 'Burp Proxy: upload a file with the form, send the file URL to Burp Repeater, and fetch it before the 2-second scan deletes it.',
};

// Challenge-local presentation: a clay app shell for the file vault screens.
function vault(crumb, body) {
  return appShell('PenTrix Vault', body, { crumb, mark: '◈', nav: ['Home', 'Files', 'Sharing', 'Settings'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race/reset">Reset lab state</a></p>`;
}

router.get('/upload', (req, res) => {
  const files = shared.state().files;
  const live = Object.keys(files).map((n) => `<li><a href="/race/files/${encodeURIComponent(n)}">${esc(n)}</a></li>`).join('')
    || '<li><i>no live files (the AV scan deletes uploads after 2 seconds)</i></li>';
  res.send(page('File vault upload', vault('Upload', `
    <section class="clay-card">
      <h2>Upload a file</h2>
      <p class="dim">Every upload is AV-scanned. Anything suspicious is
      <b>deleted 2 seconds after upload</b>. While the scan runs, the file is already served.</p>
      <form method="POST" action="/race/upload">
        <div class="clay-field">
          <label for="filename">Filename</label>
          <input class="clay-input" type="text" id="filename" name="filename" value="secret.txt" />
        </div>
        <div class="clay-field">
          <label for="content">File content</label>
          <textarea class="clay-input" id="content" name="content" rows="4" cols="60">top secret lab data</textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Upload</button>
      </form>
    </section>
    <section class="clay-card">
      <h2>Live files</h2>
      <ul>${live}</ul>
    </section>
    <section class="clay-card">
      <h2>Try it yourself</h2>
      <p>Upload, then fetch the file URL within 2 seconds, before the scan deletes it:</p>
      ${payloadBlock('Burp Repeater', '1. Send the upload POST to Repeater (Ctrl+R) and send it.\n2. Immediately open a second Repeater tab and GET the file URL before the scan deletes it.')}
    </section>
    ${hintLadder(vuln)}
    ${backLinks()}
  `)));
});

router.post('/upload', (req, res) => {
  const filename = String(req.body.filename || 'upload.txt').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 60) || 'upload.txt';
  const content = String(req.body.content || '').slice(0, 5000);
  const R = shared.state();
  if (R.files[filename]) clearTimeout(R.files[filename].timer);
  // VULN (TOCTOU): the file is servable the instant it is stored; the "scan"
  // that deletes it only runs 2 seconds later, leaving a fetchable window.
  // The timer re-reads the live state at fire time, exactly like the original
  // router, so a lab reset between upload and scan clears the file.
  R.files[filename] = {
    content,
    timer: setTimeout(() => { delete shared.state().files[filename]; }, 2000),
  };
  res.send(page('File uploaded', vault('Upload', `
    <section class="clay-card">
      <h2>Uploaded: ${esc(filename)}</h2>
      <p>The file is live <b>now</b>. The AV scan deletes it in 2 seconds.</p>
      <p><a class="clay-btn clay-btn-primary" href="/race/files/${encodeURIComponent(filename)}">Fetch it before the scan</a></p>
      ${backLinks()}
    </section>
  `)));
});

router.get('/files/:name', (req, res) => {
  const name = String(req.params.name || '').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 60);
  const f = shared.state().files[name];
  if (!f) {
    return res.status(404).send(page('File gone', vault('Files', `
      <section class="clay-card">
        <h2>404: file not found</h2>
        <p>It was never uploaded, or the AV scan already deleted it. Upload again
        and fetch faster.</p>
        ${backLinks()}
      </section>
    `)));
  }
  // Fetching a live file means you beat the scan: the TOCTOU window was real.
  const flag = award(req, 'race', 'race-upload-scan');
  res.send(page('File: ' + name, vault('Files', `
    <section class="clay-card">
      <h2>${esc(name)}</h2>
      <p><b>You fetched the file before the AV scan deleted it.</b> For 2 seconds
      it was served even though policy says it should not exist.</p>
      <pre>${esc(f.content)}</pre>
      ${flagBox(flag)}
      ${fixPanel('race', 'race-upload-scan')}
      ${backLinks()}
    </section>
  `)));
});

module.exports = { vuln, router };
