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

const VULN_IDS = ['reflected', 'stored', 'dom'];

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
        <h3><a href="/xss/${v.id === 'reflected' ? 'search' : v.id === 'stored' ? 'guestbook' : 'dom'}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  const collector = captured(req, 'xss', 'reflected') || captured(req, 'xss', 'stored') || captured(req, 'xss', 'dom')
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
    (<code>v</code> = reflected, stored, or dom).</p>
    <p>The intended payload:</p>
    <pre><code>${esc(EXFIL_PAYLOAD)}</code></pre>
  `));
});

module.exports = {
  id: 'xss',
  name: 'Cross-Site Scripting',
  tagline: 'Inject JavaScript, steal the session cookie, capture three flags.',
  description: 'Three classic cross-site scripting flaws: a reflected search box, a stored guestbook, and a DOM-based fragment sink. Learn the cookie-exfiltration payload pattern and fire it through each one.',
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
  ],
  router,
};
