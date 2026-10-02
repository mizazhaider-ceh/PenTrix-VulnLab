// LFI module: Path Traversal / Local File Inclusion.
// Two classic variants: unfiltered traversal (v1) and a naive
// single-pass "../" blacklist (v2).

const express = require('express');
const fs = require('fs');
const path = require('path');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));
const docsDir = path.join(__dirname, 'docs');
const SECRET_MARKER = 'LFI-SECRET-8830';

// ---- planted files for the new labs (created once, never overwritten) ----
const CONFIG_PATH = path.join(__dirname, 'lfi_secret.conf');
const CONFIG_MARKER = 'LFI-CONFIG-SECRET-5521';
try {
  if (!fs.existsSync(CONFIG_PATH)) {
    fs.writeFileSync(CONFIG_PATH,
      '# Internal service config - do NOT expose via the document viewer\n' +
      'db_host = 10.0.4.12\n' +
      'db_user = svc_docs\n' +
      'api_key = "' + CONFIG_MARKER + '"\n');
  }
} catch (e) { /* lab still boots; the config-read challenge will report the error */ }

const LANG_DIR = path.join(docsDir, 'lang');
try {
  if (!fs.existsSync(path.join(LANG_DIR, 'en.txt'))) {
    fs.mkdirSync(LANG_DIR, { recursive: true });
    fs.writeFileSync(path.join(LANG_DIR, 'en.txt'), 'Welcome to the document viewer.\n');
    fs.writeFileSync(path.join(LANG_DIR, 'fr.txt'), 'Bienvenue dans la visionneuse de documents.\n');
  }
} catch (e) { /* same as above */ }

// Access log for the log-poisoning chain. Every /lfi/log-demo visit appends the
// raw User-Agent header here with no filtering.
const LOG_PATH = path.join(__dirname, 'lfi_access.log');
const LOG_MARKER = 'PENTRIX-LOG-MARKER';

// /proc/self/environ only reflects the initial process environment (variables
// added later via setenv do not appear there), so the reliable tell that the
// real environ was read is a ubiquitous initial entry like PATH=.
const PROC_TELL = 'PATH=';

// The raw (still percent-encoded) value of a query parameter, taken straight
// from the request line before Express decodes anything. Needed for the
// encoding-bypass labs, where the filter and the decoder see different values.
function rawParam(req, name) {
  const m = new RegExp('[?&]' + name + '=([^&]*)').exec(req.originalUrl || '');
  return m ? m[1] : '';
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch (e) { return s; }
}

// List the benign docs so the surface is discoverable from the pages.
function listDocs() {
  try {
    return fs.readdirSync(docsDir).filter((f) => f.endsWith('.txt')).sort();
  } catch (e) {
    return [];
  }
}

function docLinks(base) {
  const files = listDocs();
  if (files.length === 0) return '<p><i>No documents found.</i></p>';
  return '<ul>' + files
    .map((f) => `<li><a href="${esc(base)}?file=${encodeURIComponent(f)}">${esc(f)}</a></li>`)
    .join('') + '</ul>';
}

// Shared read helper: naive readFile with no validation of any kind.
function readTarget(file) {
  // VULN: user-controlled path joined to docsDir and read with no checks.
  const target = path.join(docsDir, file);
  try {
    const data = fs.readFileSync(target, 'utf8');
    return { ok: true, target, data };
  } catch (e) {
    return { ok: false, target, error: e.message };
  }
}

function showCaptured(req, vulnId) {
  return captured(req, 'lfi', vulnId)
    ? flagBox(`PENTRIX{lfi_${vulnId}}`)
    : '';
}

// ---- v1: plain traversal, no filtering at all ----
router.get('/view', (req, res) => {
  const file = req.query.file || '';
  let body = `
    <h1>Document Viewer</h1>
    <p>Pick a document to read, or pass <code>?file=</code> yourself:</p>
    ${docLinks('/lfi/view')}
    ${showCaptured(req, 'traversal')}
  `;

  if (file) {
    const r = readTarget(file);
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      // Real success only: the secret is displayed through a traversal payload.
      if (r.data.includes(SECRET_MARKER) && (file.includes('..') || path.isAbsolute(file))) {
        const flag = award(req, 'lfi', 'traversal');
        body += flagBox(flag);
      }
      // Log-poison chain: the marker only reaches lfi_access.log via a crafted
      // User-Agent on /lfi/log-demo, so seeing it here proves injection + LFI.
      if (r.data.includes(LOG_MARKER) && file.includes('..')) {
        const flag = award(req, 'lfi', 'log-poison');
        body += flagBox(flag);
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Document Viewer', body));
});

// ---- v2: naive filter that strips "../" exactly once ----
router.get('/download', (req, res) => {
  const raw = req.query.file || '';
  // VULN: single-pass blacklist; stripping once can create new "../" sequences.
  const file = raw.replace('../', '');
  let body = `
    <h1>Document Download</h1>
    <p>Pick a document to download, or pass <code>?file=</code> yourself.
       Traversal sequences are filtered, so this one should be safe.</p>
    ${docLinks('/lfi/download')}
    ${showCaptured(req, 'filter-bypass')}
  `;

  if (file) {
    const r = readTarget(file);
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      // Real success only: the secret shows while the raw param carried "..".
      if (r.data.includes(SECRET_MARKER) && raw.includes('..')) {
        const flag = award(req, 'lfi', 'filter-bypass');
        body += flagBox(flag);
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Document Download', body));
});

// ---- v3: absolute path, no traversal needed ----
router.get('/abs', (req, res) => {
  const p = req.query.page || 'readme.txt';
  // VULN: absolute paths are used verbatim; reads are not confined to docs/.
  const target = path.isAbsolute(p) ? p : path.join(docsDir, p);
  let body = `
    <h1>Page Reader</h1>
    <p>Read a help page, or pass <code>?page=</code> yourself. Try the classics:</p>
    <ul>
      <li><a href="/lfi/abs?page=readme.txt">readme.txt</a></li>
      <li><a href="/lfi/abs?page=/etc/hostname">/etc/hostname</a></li>
    </ul>
    ${showCaptured(req, 'absolute')}
  `;
  try {
    const data = fs.readFileSync(target, 'utf8');
    body += `<h2>Contents of <code>${esc(p)}</code></h2><pre>${esc(data)}</pre>`;
    // Real success only: a real system file was read via an absolute path.
    if (path.isAbsolute(p) && data.includes('root:')) {
      const flag = award(req, 'lfi', 'absolute');
      body += flagBox(flag);
    }
  } catch (e) {
    body += `<h2>Error reading <code>${esc(p)}</code></h2><pre>${esc(e.message)}</pre>`;
  }
  res.send(page('LFI - Absolute Path', body));
});

// ---- v4: double-encoding bypass (filter decodes once, use decodes twice) ----
router.get('/double', (req, res) => {
  const raw = rawParam(req, 'page');
  let body = `
    <h1>Double-Decode Viewer</h1>
    <p>Traversal sequences are rejected after decoding your input once.
       This one should be safe.</p>
    ${docLinks('/lfi/double')}
    ${showCaptured(req, 'double-encode')}
  `;
  if (raw) {
    const checked = safeDecode(raw);
    if (checked.includes('..')) {
      body += `<p><b>Blocked:</b> traversal sequence detected in your input.</p>`;
    } else {
      // VULN: the value is decoded a second time after the check, so
      // %252e%252e%252f sails through the filter and becomes ../ on use.
      const file = safeDecode(checked);
      const r = readTarget(file);
      if (r.ok) {
        body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
        if (r.data.includes(SECRET_MARKER)) {
          const flag = award(req, 'lfi', 'double-encode');
          body += flagBox(flag);
        }
      } else {
        body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
      }
    }
  }
  res.send(page('LFI - Double Encoding', body));
});

// ---- v5: nested bypass of a global one-pass "../" strip ----
router.get('/nested', (req, res) => {
  const raw = req.query.page || '';
  // VULN: every "../" is stripped, but only in a single pass, so ....// regenerates ../.
  const file = raw.split('../').join('');
  let body = `
    <h1>Nested Filter Viewer</h1>
    <p>All <code>../</code> sequences are stripped from your input before reading.
       Nothing can survive that... right?</p>
    ${docLinks('/lfi/nested')}
    ${showCaptured(req, 'nested-deep')}
  `;
  if (raw) {
    const r = readTarget(file);
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      if (r.data.includes(SECRET_MARKER) && raw.includes('..')) {
        const flag = award(req, 'lfi', 'nested-deep');
        body += flagBox(flag);
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Nested Filter', body));
});

// ---- v6: lang parameter traversal ----
router.get('/lang', (req, res) => {
  const lang = req.query.lang || 'en';
  // VULN: the lang parameter is concatenated into a filesystem path with no validation.
  const target = path.join(docsDir, 'lang', lang + '.txt');
  let body = `
    <h1>Localized Viewer</h1>
    <p>Choose your language:</p>
    <ul>
      <li><a href="/lfi/lang?lang=en">English</a></li>
      <li><a href="/lfi/lang?lang=fr">Francais</a></li>
    </ul>
    ${showCaptured(req, 'lang')}
  `;
  try {
    const data = fs.readFileSync(target, 'utf8');
    body += `<h2>Language file <code>${esc(lang)}</code></h2><pre>${esc(data)}</pre>`;
    // Real success only: the secret was reached through the lang parameter.
    if (data.includes(SECRET_MARKER) && lang.includes('..')) {
      const flag = award(req, 'lfi', 'lang');
      body += flagBox(flag);
    }
  } catch (e) {
    body += `<h2>Error reading language <code>${esc(lang)}</code></h2><pre>${esc(e.message)}</pre>`;
  }
  res.send(page('LFI - Language File', body));
});

// ---- v7: log poisoning chain ----
router.get('/log-demo', (req, res) => {
  const ua = req.get('User-Agent') || '-';
  try {
    // VULN: the raw User-Agent header is appended to the access log with no filtering.
    fs.appendFileSync(LOG_PATH, new Date().toISOString() + ' ' + (req.ip || '-') +
      ' "' + ua.replace(/[\r\n"]/g, "'") + '"\n');
  } catch (e) { /* render the page anyway */ }
  let tail = '(log is empty so far)';
  try {
    const lines = fs.readFileSync(LOG_PATH, 'utf8').trim().split('\n');
    tail = lines.slice(-10).join('\n');
  } catch (e) { /* keep placeholder */ }
  res.send(page('LFI - Access Log Demo', `
    <h1>Access Log Demo</h1>
    <p>Every visit here appends your <code>User-Agent</code> header to the server's
    access log, exactly as sent. The log lives at <code>lfi_access.log</code> next to
    this module, and the document viewer can read it with a traversal payload.</p>
    <p>Your marker for this lab: <code>${esc(LOG_MARKER)}</code>. Plant it in your
    User-Agent (e.g. with <code>curl -A</code>), then read the log back through
    <a href="/lfi/view?file=readme.txt">the document viewer</a> with
    <code>?file=../lfi_access.log</code>. The flag is awarded when your marker
    shows up in the file the LFI returns.</p>
    <h2>Recent log lines</h2>
    <pre>${esc(tail)}</pre>
    ${showCaptured(req, 'log-poison')}
  `));
});

// ---- v8: /proc/self/environ ----
router.get('/procinfo', (req, res) => {
  const f = req.query.f || 'status';
  // VULN: the filename is appended to /proc/self/ with no validation, and
  // environ exposes the process environment, including secrets.
  const target = path.join('/proc/self', f);
  let body = `
    <h1>Process Info</h1>
    <p>Inspect this process. Pick a file:</p>
    <ul>
      <li><a href="/lfi/procinfo?f=status">status</a></li>
      <li><a href="/lfi/procinfo?f=cmdline">cmdline</a></li>
    </ul>
    ${showCaptured(req, 'proc-self')}
  `;
  try {
    const data = fs.readFileSync(target, 'utf8');
    body += `<h2>/proc/self/${esc(f)}</h2><pre>${esc(data)}</pre>`;
    // Real success only: the actual process environment was read.
    if (data.includes(PROC_TELL)) {
      const flag = award(req, 'lfi', 'proc-self');
      body += flagBox(flag);
    }
  } catch (e) {
    body += `<h2>Error reading <code>/proc/self/${esc(f)}</code></h2><pre>${esc(e.message)}</pre>`;
  }
  res.send(page('LFI - Process Info', body));
});

// ---- v9: encoded-separator bypass (filter checks before decoding) ----
router.get('/enc', (req, res) => {
  const raw = rawParam(req, 'page');
  let body = `
    <h1>Encoded Filter Viewer</h1>
    <p>Inputs containing <code>..</code> or <code>/</code> are rejected outright.
       Encoded input should be harmless.</p>
    ${docLinks('/lfi/enc')}
    ${showCaptured(req, 'enc-slash')}
  `;
  if (raw) {
    if (raw.includes('..') || raw.includes('/')) {
      body += `<p><b>Blocked:</b> dots and slashes are not allowed.</p>`;
    } else {
      // VULN: the check runs on the still-encoded value; decoding happens after
      // it, so %2e%2e%2f becomes ../ too late for the filter.
      const file = safeDecode(raw);
      const r = readTarget(file);
      if (r.ok) {
        body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
        if (r.data.includes(SECRET_MARKER)) {
          const flag = award(req, 'lfi', 'enc-slash');
          body += flagBox(flag);
        }
      } else {
        body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
      }
    }
  }
  res.send(page('LFI - Encoded Separator', body));
});

// ---- v10: planted secret config ----
router.get('/config', (req, res) => {
  const file = req.query.file || 'readme.txt';
  // VULN: no validation at all; a secret config file sits one directory up.
  const r = readTarget(file);
  let body = `
    <h1>Config Viewer</h1>
    <p>Read a config doc, or pass <code>?file=</code> yourself:</p>
    ${docLinks('/lfi/config')}
    ${showCaptured(req, 'config-read')}
  `;
  if (file) {
    if (r.ok) {
      body += `<h2>Contents of <code>${esc(file)}</code></h2><pre>${esc(r.data)}</pre>`;
      // Real success only: the planted config was reached via traversal.
      if (r.data.includes(CONFIG_MARKER) && file.includes('..')) {
        const flag = award(req, 'lfi', 'config-read');
        body += flagBox(flag);
      }
    } else {
      body += `<h2>Error reading <code>${esc(file)}</code></h2><pre>${esc(r.error)}</pre>`;
    }
  }
  res.send(page('LFI - Config File', body));
});

// ---- module index ----
router.get('/', (req, res) => {
  const vulns = [
    {
      id: 'traversal', name: 'Basic Path Traversal', difficulty: 'Easy',
      hint: 'The viewer joins your input to the docs path with no checks at all. What happens if you ask for a file in the parent directory, like <code>..%2F..%2Fsecret.txt</code>? Adjust the depth until you find it.',
      how: 'Use ../ sequences to escape docs/ and read secret.txt.',
      link: '/lfi/view?file=readme.txt',
    },
    {
      id: 'filter-bypass', name: 'Naive Filter Bypass', difficulty: 'Medium',
      hint: 'The download endpoint strips <code>../</code> only once. Craft an input where removing the inner <code>../</code> leaves a fresh traversal sequence behind, e.g. <code>....//</code> collapses to <code>../</code> after one strip.',
      how: 'Bypass the single-pass filter with ....//....//secret.txt.',
      link: '/lfi/download?file=about.txt',
    },
    {
      id: 'absolute', name: 'Absolute Path Read', difficulty: 'Easy',
      hint: 'The page reader uses absolute paths verbatim instead of confining reads to the docs folder. No <code>../</code> needed: just name the file, e.g. <code>?page=/etc/passwd</code>.',
      how: 'Read /etc/passwd with an absolute path via /lfi/abs.',
      link: '/lfi/abs',
    },
    {
      id: 'double-encode', name: 'Double-Encoding Bypass', difficulty: 'Medium',
      hint: 'The filter decodes your input once and rejects it if it sees <code>..</code>. But the value is decoded a second time after the check. Encode the dots and slashes twice, e.g. <code>%252e%252e%252f</code>.',
      how: 'Slip %252e%252e%252f past the one-decode filter on /lfi/double.',
      link: '/lfi/double',
    },
    {
      id: 'nested-deep', name: 'Deep Nesting Bypass', difficulty: 'Easy',
      hint: 'This filter strips every <code>../</code> in one pass, but it never looks at the result again. Nest your dots so stripping creates a fresh traversal, e.g. <code>....///</code> collapses toward <code>../</code>.',
      how: 'Beat the one-pass global strip on /lfi/nested with nested dots.',
      link: '/lfi/nested',
    },
    {
      id: 'lang', name: 'Language Parameter Traversal', difficulty: 'Easy',
      hint: 'The <code>lang</code> parameter picks a file from <code>docs/lang/</code> with no validation. It is just another filename: <code>?lang=../secret</code>.',
      how: 'Traverse out of docs/lang/ via the lang parameter on /lfi/lang.',
      link: '/lfi/lang?lang=en',
    },
    {
      id: 'log-poison', name: 'Log Poisoning Chain', difficulty: 'Hard',
      hint: 'Two steps: first, visit <code>/lfi/log-demo</code> with the marker string in your User-Agent header so it lands in the access log. Then read that log back through the document viewer with <code>?file=../lfi_access.log</code>.',
      how: 'Poison the access log via User-Agent, then read it through /lfi/view.',
      link: '/lfi/log-demo',
    },
    {
      id: 'proc-self', name: 'Process Environ Leak', difficulty: 'Medium',
      hint: 'The process-info page appends your filename to <code>/proc/self/</code> with no checks. Most files there are boring, but one of them holds the whole environment, secrets included. Its entries are NUL-separated.',
      how: 'Read /proc/self/environ through /lfi/procinfo.',
      link: '/lfi/procinfo',
    },
    {
      id: 'enc-slash', name: 'Encoded Separator Bypass', difficulty: 'Medium',
      hint: 'The filter rejects any input containing literal <code>..</code> or <code>/</code>, but it checks before decoding. Percent-encode the dots and the slash, e.g. <code>%2e%2e%2f</code>.',
      how: 'Slip %2e%2e%2f past the pre-decode filter on /lfi/enc.',
      link: '/lfi/enc',
    },
    {
      id: 'config-read', name: 'Secret Config Read', difficulty: 'Easy',
      hint: 'A config file with secrets sits one directory above the docs folder, and the config viewer filters nothing. <code>?file=../lfi_secret.conf</code>.',
      how: 'Read the planted lfi_secret.conf via /lfi/config.',
      link: '/lfi/config',
    },
  ];

  const rows = vulns.map((v) => `
    <section class="vuln">
      <h3><a href="${esc(v.link)}">${esc(v.name)}</a>
        <span class="badge">${esc(v.difficulty)}</span></h3>
      <p><b>Goal:</b> ${esc(v.how)}</p>
      ${hintBox(v.hint)}
    </section>`).join('');

  res.send(page('Path Traversal / LFI', `
    ${brief('Path Traversal / LFI',
      `Files are read from disk using a name taken straight from the URL.
       One endpoint filters nothing at all; the other one filters once and
       hopes for the best. Find <code>${esc('secret.txt')}</code> and read its
       contents to capture the flags.`)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

module.exports = {
  id: 'lfi',
  name: 'Path Traversal / LFI',
  tagline: 'Break out of the docs folder and read the secret file.',
  description: 'A document viewer and downloader that hand your filename straight to the filesystem. One endpoint has no filtering at all, the other strips "../" exactly once. Reach the hidden secret.txt to capture both flags. Eight more labs deepen the craft: absolute paths, double-encoding, nested filters, log poisoning, /proc leaks, and a planted secret config.',
  difficulty: 'Mixed',
  vulns: [
    { id: 'traversal', name: 'Basic Path Traversal', difficulty: 'Easy',
      hint: 'No filtering is applied; ../ sequences escape the docs directory.',
      how: 'Read secret.txt with a ../ traversal payload via /lfi/view.' },
    { id: 'filter-bypass', name: 'Naive Filter Bypass', difficulty: 'Medium',
      hint: 'The single ../ strip can be bypassed with ....// sequences.',
      how: 'Collapse ....// into ../ to beat the one-shot filter on /lfi/download.' },
    { id: 'absolute', name: 'Absolute Path Read', difficulty: 'Easy',
      hint: 'Absolute paths are used verbatim; no traversal needed.',
      how: 'Read /etc/passwd with ?page=/etc/passwd via /lfi/abs.' },
    { id: 'double-encode', name: 'Double-Encoding Bypass', difficulty: 'Medium',
      hint: 'The filter decodes once before checking, but the value is decoded again on use.',
      how: 'Slip %252e%252e%252f past the one-decode filter on /lfi/double.' },
    { id: 'nested-deep', name: 'Deep Nesting Bypass', difficulty: 'Easy',
      hint: 'The global ../ strip runs in a single pass; nested dots regenerate the sequence.',
      how: 'Beat the one-pass global strip on /lfi/nested with nested dots.' },
    { id: 'lang', name: 'Language Parameter Traversal', difficulty: 'Easy',
      hint: 'The lang parameter is concatenated into a path with no validation.',
      how: 'Traverse out of docs/lang/ via ?lang=../secret on /lfi/lang.' },
    { id: 'log-poison', name: 'Log Poisoning Chain', difficulty: 'Hard',
      hint: 'Poison the access log through User-Agent, then read it back via LFI.',
      how: 'Plant the marker with curl -A on /lfi/log-demo, then read ../lfi_access.log via /lfi/view.' },
    { id: 'proc-self', name: 'Process Environ Leak', difficulty: 'Medium',
      hint: '/proc/self/ filenames are not validated; environ leaks process secrets.',
      how: 'Read /proc/self/environ through /lfi/procinfo.' },
    { id: 'enc-slash', name: 'Encoded Separator Bypass', difficulty: 'Medium',
      hint: 'The filter checks for .. and / before decoding the input.',
      how: 'Slip %2e%2e%2f past the pre-decode filter on /lfi/enc.' },
    { id: 'config-read', name: 'Secret Config Read', difficulty: 'Easy',
      hint: 'A secret config file sits one directory above docs/ with no filter in the way.',
      how: 'Read the planted lfi_secret.conf via ?file=../lfi_secret.conf on /lfi/config.' },
  ],
  router,
};
