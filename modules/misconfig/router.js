// modules/misconfig/router.js
// Security Misconfiguration: verbose debug error pages, exposed backup dumps,
// and directory listings that leak files which were never meant to be public.

const express = require('express');
const fs = require('fs');
const path = require('path');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();

const FILES_DIR = path.join(__dirname, 'public-files');
const BACKUP_PATH = path.join(__dirname, 'backup.sql');

const VULNS = [
  {
    id: 'debug',
    name: 'Verbose Debug Errors',
    difficulty: 'Easy',
    hint: 'The debug page behaves differently when the err query parameter is set. Try appending ?err=1 to the URL.',
    how: 'Request /misconfig/debug?err=1 to trigger a verbose stack trace with a config dump.',
    link: '/misconfig/debug',
  },
  {
    id: 'backup',
    name: 'Exposed Database Backup',
    difficulty: 'Easy',
    hint: 'Admins sometimes leave database dumps where the web server can serve them. Guess the filename.',
    how: 'Download /misconfig/backup.sql and read the dump for plaintext credentials and tokens.',
    link: '/misconfig/backup.sql',
  },
  {
    id: 'listing',
    name: 'Directory Listing Leak',
    difficulty: 'Easy',
    hint: 'The file browser lists everything in public-files, including files that were never meant to be seen.',
    how: 'Open /misconfig/files/ and read secret.txt.',
    link: '/misconfig/files/',
  },
];

// ---------- module index ----------
router.get('/', (req, res) => {
  const rows = VULNS.map(
    (v) => `<tr>
      <td><b>${esc(v.name)}</b><br><span class="dim">${esc(v.how)}</span></td>
      <td>${esc(v.difficulty)}</td>
      <td>${hintBox(esc(v.hint))}</td>
      <td><a class="btn" href="${esc(v.link)}">Open</a></td>
    </tr>`
  ).join('');
  res.send(
    page(
      'Security Misconfiguration',
      brief(
        'Security Misconfiguration',
        `Defaults kill. This module collects the classics: <b>debug mode left on</b> in a
        deployed app, a <b>database backup</b> sitting where the web server can serve it,
        and a <b>directory listing</b> that hands out files nobody was supposed to see.
        Three flags, one lesson: <span class="dim">harden every environment like it is production.</span>`
      ) +
        `<table class="tbl"><tr><th>Vulnerability</th><th>Difficulty</th><th>Hint</th><th></th></tr>${rows}</table>`
    )
  );
});

// ---------- v1: verbose debug error page ----------
router.get('/debug', (req, res) => {
  if (req.query.err === '1') {
    // VULN: verbose error page leaks a full stack trace and internal config (secrets) to any visitor
    const flag = award(req, 'misconfig', 'debug');
    const stack = `Error: ENOENT: no such file or directory, open '/app/config/secrets.json'
    at Object.openSync (node:fs:596:3)
    at Object.readFileSync (node:fs:464:35)
    at loadConfig (/app/server.js:42:19)
    at Object.<anonymous> (/app/server.js:118:14)
    at Module._compile (node:internal/modules/cjs/loader:1378:14)
    at Module._extensions..js (node:internal/modules/cjs/loader:1437:10)
    at Module.load (node:internal/modules/cjs/loader:1212:32)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:174:12) {
  errno: -2,
  code: 'ENOENT',
  syscall: 'open',
  path: '/app/config/secrets.json'
}

--- app config (debug build) ---
env: staging
node: v22.9.0
config: { dbPassword: 'Sup3rS3cretDb!', debugToken: '${flag}', apiKey: 'pk_live_9f2c41aa77' }
sessionSecret: 'keyboard-cat-do-not-use-in-prod'`;
    res.send(
      page(
        'Debug error',
        `<h2>Debug output</h2>
        <p class="dim">Something broke and the app told you everything. Never ship this.</p>
        <pre>${esc(stack)}</pre>
        ${flagBox(flag)}`
      )
    );
    return;
  }
  res.send(
    page(
      'Debug page',
      `<h2>Debug page</h2>
      <p>Debug mode is <b>off</b>. The application is running with safe defaults and errors are hidden from visitors.</p>
      ${hintBox(esc(VULNS[0].hint))}
      <p><a class="btn ghost" href="/misconfig/debug?err=1">Simulate an error</a></p>`
    )
  );
});

// ---------- v2: exposed database backup ----------
router.get('/backup.sql', (req, res) => {
  // VULN: sensitive database backup stored inside the web-accessible tree and served to anyone who asks
  award(req, 'misconfig', 'backup');
  res.type('text/plain');
  res.sendFile(BACKUP_PATH);
});

// ---------- v3: manual directory listing + file serving ----------
function renderListing(res) {
  // VULN: hand-rolled directory listing exposes every file in the folder, including secret.txt
  let entries = [];
  try {
    entries = fs.readdirSync(FILES_DIR);
  } catch (e) {
    return res.status(500).send(page('Files', '<p>Could not read the directory.</p>'));
  }
  const rows = entries
    .map((name) => {
      const full = path.join(FILES_DIR, name);
      let size = 0;
      try {
        size = fs.statSync(full).size;
      } catch (e) {
        size = 0;
      }
      return `<tr><td><a href="/misconfig/files/${encodeURIComponent(name)}">${esc(name)}</a></td><td class="dim">${size} bytes</td></tr>`;
    })
    .join('');
  res.send(
    page(
      'Public files',
      `<h2>Index of /misconfig/files/</h2>
      <p class="dim">Everything in this folder is served as-is. Probably fine, right?</p>
      <table class="tbl"><tr><th>Name</th><th>Size</th></tr>${rows}</table>
      ${hintBox(esc(VULNS[2].hint))}`
    )
  );
}

function serveFile(name, req, res) {
  const base = path.basename(String(name || ''));
  const full = path.join(FILES_DIR, base);
  if (!base || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
    return res.status(404).send(page('Not found', `<h2>404</h2><p>File <code>${esc(base)}</code> not found.</p>`));
  }
  if (base === 'secret.txt') {
    // VULN: the listing exposed secret.txt and it is served raw to anyone who requests it
    award(req, 'misconfig', 'listing');
  }
  res.type('text/plain');
  res.sendFile(full);
}

router.get('/files', (req, res) => {
  if (req.query.f) return serveFile(req.query.f, req, res);
  renderListing(res);
});
router.get('/files/', (req, res) => {
  if (req.query.f) return serveFile(req.query.f, req, res);
  renderListing(res);
});
router.get('/files/:name', (req, res) => serveFile(req.params.name, req, res));

module.exports = {
  id: 'misconfig',
  name: 'Security Misconfiguration',
  tagline: 'Debug pages, backup dumps, and directory listings that give away the keys.',
  description:
    'The vulnerability is not in the code logic but in how the app is deployed: verbose error pages, backups left under the web root, and directory listings that expose internal files. Three easy flags for the sharp-eyed.',
  difficulty: 'Beginner',
  vulns: VULNS.map((v) => ({ id: v.id, name: v.name, difficulty: v.difficulty, hint: v.hint, how: v.how })),
  router,
};
