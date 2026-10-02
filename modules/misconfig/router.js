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

// Filenames written through the unauthenticated PUT endpoint. Reading one back
// via GET proves the arbitrary write and captures the flag.
const uploadedFiles = new Set();

// Fake commit hash for the exposed .git lab.
const GIT_COMMIT = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4';

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
  {
    id: 'git',
    name: 'Exposed .git Directory',
    difficulty: 'Medium',
    hint: 'The repository metadata is served over HTTP. Start at /.git/HEAD, follow the ref, then walk the object store to the commit.',
    how: 'Read .git/HEAD, resolve refs/heads/main, then fetch the commit object and read the leaked secret.',
    link: '/misconfig/.git/HEAD',
  },
  {
    id: 'swp',
    name: 'Vim Swap File Leak',
    difficulty: 'Easy',
    hint: 'Editors leave backup artifacts next to the files they edit. The running app is app.js; what would its swap file be called?',
    how: 'Download /misconfig/app.js.swp and read the recovered source for secrets.',
    link: '/misconfig/app.js.swp',
  },
  {
    id: 'trace',
    name: 'HTTP TRACE Enabled (XST)',
    difficulty: 'Easy',
    hint: 'TRACE echoes the request back to the sender. Browsers cannot send it, but curl can: curl -X TRACE.',
    how: 'Send a TRACE request to /misconfig/trace and read the reflected request.',
    link: '/misconfig/trace',
  },
  {
    id: 'env',
    name: 'Exposed .env File',
    difficulty: 'Medium',
    hint: 'Twelve-factor apps keep secrets in environment files. One of them ended up web-accessible.',
    how: 'Download /misconfig/.env and read the secrets inside.',
    link: '/misconfig/.env',
  },
  {
    id: 'debug-param',
    name: 'Debug Mode via Query Param',
    difficulty: 'Easy',
    hint: 'The info page has a hidden debug switch. The parameter name is the obvious one.',
    how: 'Request /misconfig/info?debug=1 to render a stack trace with config.',
    link: '/misconfig/info',
  },
  {
    id: 'manager',
    name: 'Default Credentials',
    difficulty: 'Easy',
    hint: 'The manager panel uses HTTP Basic auth and the vendor default was never changed. Try the most common pair there is.',
    how: 'Log in to /misconfig/manager with admin:admin.',
    link: '/misconfig/manager',
  },
  {
    id: 'robots',
    name: 'Robots.txt Disclosure',
    difficulty: 'Easy',
    hint: 'robots.txt tells crawlers what not to fetch. Attackers read it as a treasure map.',
    how: 'Read /misconfig/robots.txt, then download the disallowed backup.zip.',
    link: '/misconfig/robots.txt',
  },
  {
    id: 'put',
    name: 'Unauthenticated HTTP PUT',
    difficulty: 'Medium',
    hint: 'The file endpoint accepts PUT with no authentication at all. Upload a file with a raw content type (curl -H "Content-Type: text/plain" --data-binary), then fetch it back with GET to prove the write.',
    how: 'PUT a file to /misconfig/files/<name> with Content-Type: text/plain, then read it back via GET.',
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
        a <b>directory listing</b> that hands out files nobody was supposed to see,
        plus an exposed <b>.git directory</b>, a <b>vim swap file</b>, an enabled
        <b>TRACE method</b>, a public <b>.env</b>, a debug query switch, <b>default
        credentials</b>, a chatty <b>robots.txt</b>, and an unauthenticated <b>PUT</b>
        upload. Eleven flags, one lesson: <span class="dim">harden every environment like it is production.</span>`
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
  if (uploadedFiles.has(base)) {
    // VULN: this file arrived via the unauthenticated PUT and is served back raw;
    // reading it back proves the arbitrary write succeeded
    award(req, 'misconfig', 'put');
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

// ---------- v4: exposed .git directory ----------
router.get('/.git/HEAD', (req, res) => {
  // VULN: version-control metadata is served over HTTP; HEAD reveals the branch ref
  res.type('text/plain').send('ref: refs/heads/main\n');
});

router.get('/.git/refs/heads/main', (req, res) => {
  // VULN: refs are readable, leaking the latest commit hash
  res.type('text/plain').send(GIT_COMMIT + '\n');
});

router.get('/.git/objects/', (req, res) => {
  // VULN: the object store is browsable, so loose objects can be enumerated
  res.send(
    page(
      'Index of /.git/objects/',
      `<h2>Index of /.git/objects/</h2>
      <p class="dim">Loose objects, one directory per hash prefix.</p>
      <ul><li><a href="/misconfig/.git/objects/${GIT_COMMIT.slice(0, 2)}/">${GIT_COMMIT.slice(0, 2)}/</a></li></ul>
      ${hintBox('The directory name is the first two hex characters of the commit hash. Open it.')}`
    )
  );
});

router.get('/.git/objects/:dir/', (req, res) => {
  if (req.params.dir !== GIT_COMMIT.slice(0, 2)) {
    return res.status(404).send(page('Not found', '<h2>404</h2><p>No such object directory.</p>'));
  }
  const rest = GIT_COMMIT.slice(2);
  res.send(
    page(
      `Index of /.git/objects/${esc(req.params.dir)}/`,
      `<h2>Index of /.git/objects/${esc(req.params.dir)}/</h2>
      <ul><li><a href="/misconfig/.git/objects/${esc(req.params.dir)}/${rest}">${rest}</a></li></ul>
      ${hintBox('That file is the commit object. Fetch it and read the diff.')}`
    )
  );
});

router.get('/.git/objects/:dir/:file', (req, res) => {
  if (req.params.dir + req.params.file !== GIT_COMMIT) {
    return res.status(404).send(page('Not found', '<h2>404</h2><p>No such object.</p>'));
  }
  // VULN: the leaked commit object contains a production secret in its diff
  const flag = award(req, 'misconfig', 'git');
  res.type('text/plain').send(
    `commit 312\n` +
    `tree 8f2e41aa77c09d31\n` +
    `author deploy <deploy@pentrix.lab> 1790000000 +0000\n` +
    `committer deploy <deploy@pentrix.lab> 1790000000 +0000\n` +
    `\n` +
    `    rotate production secrets\n` +
    `\n` +
    `    diff --git a/config/prod.env b/config/prod.env\n` +
    `    -STRIPE_KEY=sk_live_OLDKEY\n` +
    `    +ADMIN_BACKUP_TOKEN=${flag}\n`
  );
});

// ---------- v5: vim swap file ----------
router.get('/app.js.swp', (req, res) => {
  // VULN: editor backup artifact left in the web root, recoverable source included
  const flag = award(req, 'misconfig', 'swp');
  res.type('text/plain').send(
    `b0VIM 9.0  swap file for "app.js" - recovered, do not delete\n` +
    `# local dev notes - DO NOT COMMIT\n` +
    `const db = connect(process.env.DB_URL); // postgres://app:Sup3rS3cretDb!@db.internal:5432/app\n` +
    `const STRIPE_KEY = 'sk_live_9f2c41aa77';\n` +
    `// TODO: rotate before prod - backup token ${flag}\n`
  );
});

// ---------- v6: HTTP TRACE enabled (XST demo) ----------
router.get('/trace', (req, res) => {
  res.send(
    page(
      'TRACE endpoint',
      `<h2>TRACE is enabled here</h2>
      <p>A <code>TRACE</code> request to this URL gets the full request reflected
      back, headers included. That is the setup for a cross-site tracing (XST)
      attack: trick a victim's browser into sending one, and the reflected
      <code>Cookie</code> header leaks their session.</p>
      <p class="dim">Browsers cannot send TRACE; use curl:</p>
      <pre><code>curl -X TRACE http://localhost:3000/misconfig/trace -H "Cookie: session=abc123"</code></pre>
      ${hintBox('Send the TRACE request and watch your headers come back at you.')}`
    )
  );
});

router.trace('/trace', (req, res) => {
  // VULN: TRACE is enabled and reflects the entire request, the classic XST primitive
  const flag = award(req, 'misconfig', 'trace');
  const head = Object.entries(req.headers)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
    .join('\n');
  res.send(
    page(
      'TRACE reflection',
      `<h2>TRACE /misconfig/trace</h2>
      <p class="dim">The server reflected your exact request. Note the
      <code>Cookie</code> header coming straight back: that is what XST steals.</p>
      <pre>TRACE /misconfig/trace HTTP/1.1\n${esc(head)}</pre>
      ${flagBox(flag)}`
    )
  );
});

// ---------- v7: exposed .env ----------
router.get('/.env', (req, res) => {
  // VULN: environment file with production secrets served to anyone who asks
  const flag = award(req, 'misconfig', 'env');
  res.type('text/plain').send(
    `# production environment - DO NOT COMMIT\n` +
    `NODE_ENV=production\n` +
    `DB_URL=postgres://app:Sup3rS3cretDb!@db.internal:5432/app\n` +
    `STRIPE_SECRET_KEY=sk_live_9f2c41aa77\n` +
    `SESSION_SECRET=keyboard-cat-do-not-use-in-prod\n` +
    `ADMIN_API_TOKEN=${flag}\n`
  );
});

// ---------- v8: debug mode via query parameter ----------
router.get('/info', (req, res) => {
  if (req.query.debug === '1') {
    // VULN: a query parameter flips on verbose debug output, stack trace and secrets included
    const flag = award(req, 'misconfig', 'debug-param');
    const trace =
`Error: connect ECONNREFUSED 10.0.4.12:5432
    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1555:16)
    at Pool.acquire (/app/db/pool.js:88:11)
    at App.boot (/app/server.js:64:19)

--- app config (debug=1) ---
env: production
node: v22.9.0
config: { dbPassword: 'Sup3rS3cretDb!', debugToken: '${flag}', apiKey: 'pk_live_9f2c41aa77' }`;
    return res.send(
      page(
        'App info (debug)',
        `<h2>Debug info</h2>
        <p class="dim">Debug mode was enabled by the query string. Never ship this.</p>
        <pre>${esc(trace)}</pre>
        ${flagBox(flag)}`
      )
    );
  }
  res.send(
    page(
      'App info',
      `<h2>Application info</h2>
      <p>PenTrix VulnLab build 4.2.0. All systems nominal.</p>
      ${hintBox('The info page behaves differently when the debug query parameter is set. The parameter name is the obvious one.')}`
    )
  );
});

// ---------- v9: manager panel behind default credentials ----------
router.get('/manager', (req, res) => {
  const hdr = req.headers.authorization || '';
  const m = /^Basic (.+)$/.exec(hdr);
  let ok = false;
  if (m) {
    try {
      ok = Buffer.from(m[1], 'base64').toString('utf8') === 'admin:admin';
    } catch (e) {
      ok = false;
    }
  }
  // VULN: the management panel is protected only by the vendor default credential admin:admin
  if (!ok) {
    res.set('WWW-Authenticate', 'Basic realm="VulnLab Manager"');
    return res
      .status(401)
      .send(page('Manager', '<h2>401 Unauthorized</h2><p>This management panel requires authentication.</p>'));
  }
  const flag = award(req, 'misconfig', 'manager');
  res.send(
    page(
      'Manager panel',
      `<h2>Manager panel</h2>
      <p>Welcome, admin. Server status: <b>running</b>. Deploys today: 3.</p>
      <p class="dim">Default credentials still in place. Change them.</p>
      ${flagBox(flag)}`
    )
  );
});

// ---------- v10: robots.txt points at a backup zip ----------
// Minimal stored (uncompressed) single-file ZIP builder. No dependencies.
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function zipSingle(name, data) {
  const nameBuf = Buffer.from(name, 'utf8');
  const crc = crc32(data);
  const local = Buffer.alloc(30 + nameBuf.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0x21, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);
  local.writeUInt16LE(0, 28);
  nameBuf.copy(local, 30);
  const central = Buffer.alloc(46 + nameBuf.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt16LE(0, 12);
  central.writeUInt16LE(0x21, 14);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBuf.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);
  nameBuf.copy(central, 46);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length + data.length, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([local, data, central, end]);
}

router.get('/robots.txt', (req, res) => {
  // VULN: robots.txt advertises a sensitive backup path to anyone who reads it
  res.type('text/plain').send('User-agent: *\nDisallow: /misconfig/backup.zip\n');
});

router.get('/backup.zip', (req, res) => {
  // VULN: backup archive left downloadable; robots.txt pointed right at it
  const flag = award(req, 'misconfig', 'robots');
  const inner =
    `PenTrix nightly backup - admin credentials\n` +
    `username: admin\n` +
    `password: Sup3rS3cretDb!\n` +
    `backup token: ${flag}\n`;
  res.type('application/zip');
  res.send(zipSingle('backup.txt', Buffer.from(inner, 'utf8')));
});

// ---------- v11: unauthenticated HTTP PUT file write ----------
router.put('/files/:name', express.raw({ type: '*/*', limit: '1mb' }), (req, res) => {
  const name = path.basename(String(req.params.name || ''));
  if (!name || !Buffer.isBuffer(req.body)) {
    return res.status(400).type('text/plain')
      .send('bad upload: send a raw body, e.g. curl -X PUT -H "Content-Type: text/plain" --data-binary @file\n');
  }
  // VULN: arbitrary file write with no authentication; the file lands in the served folder
  const full = path.join(FILES_DIR, name);
  try {
    fs.writeFileSync(full, req.body);
  } catch (e) {
    return res.status(500).type('text/plain').send('write failed: ' + e.message + '\n');
  }
  uploadedFiles.add(name);
  res
    .status(201)
    .type('text/plain')
    .send(`uploaded ${name} (${req.body.length} bytes) - GET /misconfig/files/${encodeURIComponent(name)} to read it back\n`);
});

module.exports = {
  id: 'misconfig',
  name: 'Security Misconfiguration',
  tagline: 'Debug pages, backup dumps, and directory listings that give away the keys.',
  description:
    'The vulnerability is not in the code logic but in how the app is deployed: verbose error pages, backups left under the web root, directory listings that expose internal files, an exposed .git directory, swap files, TRACE, .env leaks, default credentials, robots.txt disclosure, and unauthenticated PUT uploads. Eleven flags for the sharp-eyed.',
  difficulty: 'Beginner',
  vulns: VULNS.map((v) => ({ id: v.id, name: v.name, difficulty: v.difficulty, hint: v.hint, how: v.how })),
  router,
};
