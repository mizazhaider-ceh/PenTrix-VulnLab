// LFI module: Path Traversal / Local File Inclusion.
// Two classic variants: unfiltered traversal (v1) and a naive
// single-pass "../" blacklist (v2).

const express = require('express');
const fs = require('fs');
const path = require('path');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
const docsDir = path.join(__dirname, 'docs');
const SECRET_MARKER = 'LFI-SECRET-8830';

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
  description: 'A document viewer and downloader that hand your filename straight to the filesystem. One endpoint has no filtering at all, the other strips "../" exactly once. Reach the hidden secret.txt to capture both flags.',
  difficulty: 'Mixed',
  vulns: [
    { id: 'traversal', name: 'Basic Path Traversal', difficulty: 'Easy',
      hint: 'No filtering is applied; ../ sequences escape the docs directory.',
      how: 'Read secret.txt with a ../ traversal payload via /lfi/view.' },
    { id: 'filter-bypass', name: 'Naive Filter Bypass', difficulty: 'Medium',
      hint: 'The single ../ strip can be bypassed with ....// sequences.',
      how: 'Collapse ....// into ../ to beat the one-shot filter on /lfi/download.' },
  ],
  router,
};
