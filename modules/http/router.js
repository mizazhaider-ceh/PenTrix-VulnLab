// PenTrix VulnLab module: HTTP Layer Flaws (http)
// Six labs below the application logic: CRLF log injection, HTTP method
// override, verb tampering, X-Forwarded-For trust, cache deception, and
// Referer-based authorization.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// VULN: the app honors a _method body parameter to rewrite the HTTP verb, so a
// plain POST can reach routes that only listen for DELETE.
router.use((req, res, next) => {
  if (req.body && typeof req.body._method === 'string' && req.body._method.trim()) {
    req.httpOverride = req.body._method.trim();
    req.method = req.httpOverride.toUpperCase();
  }
  next();
});

const db = getDb();
db.exec(`CREATE TABLE IF NOT EXISTS http_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT, ref TEXT, ts TEXT
)`);
db.exec(`CREATE TABLE IF NOT EXISTS http_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT
)`);
db.exec(`CREATE TABLE IF NOT EXISTS http_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  msg TEXT, ts TEXT
)`);

function seedItems() {
  const n = db.prepare('SELECT COUNT(*) AS c FROM http_items').get().c;
  if (n === 0) {
    db.prepare("INSERT INTO http_items (name) VALUES ('Demo laptop'), ('Demo phone'), ('Demo router')").run();
  }
}
seedItems();

// ---------------------------------------------------------------- index page
const CHALLENGES = [
  ['track', 'crlf-log'],
  ['items', 'method-override'],
  ['feedback', 'verb-tamper'],
  ['internal', 'xff-admin'],
  ['cache', 'cache-deception'],
  ['hidden', 'referer-auth'],
];

router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const ch = CHALLENGES.find((c) => c[1] === v.id);
    const done = captured(req, 'http', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/http/${ch[0]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('HTTP Layer Flaws', `
    ${brief('Module briefing', `
      <p><b>What lives at the HTTP layer?</b> Before your application code even runs,
      the request passes through verbs, headers, and caches. This module attacks those:
      response splitting and log forging with CR/LF bytes, verb confusion
      (<code>_method</code> overrides, GET-vs-POST), trusting client-controlled headers
      like <code>X-Forwarded-For</code> and <code>Referer</code>, and a naive cache
      keyed on the URL path alone.</p>
      <p><b>Heads up:</b> a few flags here are returned in an <code>X-Flag</code>
      response header (the response is CSS, JavaScript, or a file download, not HTML),
      and every capture is also saved to your scoreboard.</p>`)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

// ------------------------------------------------- v1: CRLF log injection
router.get('/track', (req, res) => {
  const ref = (req.query.ref || '').toString().slice(0, 500);
  const ip = req.ip || 'unknown';
  const ts = new Date().toISOString();
  db.prepare('INSERT INTO http_log (ip, ref, ts) VALUES (?, ?, ?)').run(ip, ref, ts);
  let extra = '';
  // VULN: the raw ref, CR/LF bytes included, is written to the access log with
  // no sanitization, so %0d%0a forges extra log lines (and HTML in the viewer).
  if (/[\r\n]/.test(ref)) {
    const flag = award(req, 'http', 'crlf-log');
    extra = `<h3>Log injection landed</h3>
      <p>Your CR/LF bytes were written straight into the access log.</p>
      ${flagBox(flag)}`;
  }
  res.send(page('Tracker', `
    <h2>Visit tracked</h2>
    <p>Logged this visit from <code>${esc(ip)}</code> at <code>${esc(ts)}</code>.</p>
    ${extra}
    <p><a href="/http/admin/log">View the access log</a> &middot;
    <a href="/http">Module index</a></p>
    <p class="note">Try <code>/http/track?ref=homepage%0d%0a${esc('2026-10-02 FAKE admin login from 10.9.9.9')}</code>
    and then open the log viewer.</p>
  `));
});

router.get('/admin/log', (req, res) => {
  const rows = db.prepare('SELECT ip, ref, ts FROM http_log ORDER BY id DESC LIMIT 100').all();
  // VULN: log lines are rendered raw; injected CR/LF splits lines and any HTML
  // in the ref value is parsed by the browser.
  const lines = rows.map((r) => `${r.ts} ${r.ip} ref=${r.ref}`).join('\n');
  res.send(page('Access log', `
    <h2>Access log (admin view)</h2>
    <p>Raw log, newest first. No output encoding is applied here.</p>
    <pre>${lines}</pre>
    <p><a href="/http">Module index</a></p>
  `));
});

// --------------------------------------------- v2: HTTP method override
router.get('/items', (req, res) => {
  const items = db.prepare('SELECT id, name FROM http_items ORDER BY id').all();
  const rows = items.map((it) => `
    <div class="comment">
      <b>#${it.id} ${esc(it.name)}</b>
      <form method="POST" action="/http/items/${it.id}/delete" style="display:inline; margin-left:1em;">
        <button type="submit">Delete (needs admin approval)</button>
      </form>
    </div>`).join('\n') || '<p><i>All items deleted.</i></p>';
  res.send(page('Inventory', `
    <h2>Inventory</h2>
    <p>Deleting an item requires admin approval: the button below only
    <i>requests</i> deletion. Nothing here can delete directly.</p>
    ${rows}
    <p><a href="/http/items/reset">Reset demo items</a> &middot;
    <a href="/http">Module index</a></p>
    <p class="note">This app honors the <code>_method</code> body parameter.
    What happens if a POST to <code>/http/items/&lt;id&gt;</code> carries
    <code>_method=DELETE</code>?</p>
  `));
});

router.post('/items/:id/delete', (req, res) => {
  res.send(page('Deletion requested', `
    <h2>Request logged</h2>
    <p>Your deletion request for item #${esc(req.params.id)} was logged.
    An admin must approve it. <b>Nothing was deleted.</b></p>
    <p><a href="/http/items">Back to inventory</a></p>
  `));
});

router.delete('/items/:id', (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT id, name FROM http_items WHERE id = ?').get(id);
  if (!row) {
    return res.status(404).send(page('Not found', '<h2>404</h2><p>No such item.</p><p><a href="/http/items">Back</a></p>'));
  }
  db.prepare('DELETE FROM http_items WHERE id = ?').run(id);
  let extra = '';
  if (req.httpOverride) {
    const flag = award(req, 'http', 'method-override');
    extra = `<h3>Method override worked</h3>
      <p>Your POST with <code>_method=${esc(req.httpOverride)}</code> was treated as
      <code>DELETE</code> and item <b>${esc(row.name)}</b> is gone. The UI never
      offered you this.</p>${flagBox(flag)}`;
  }
  res.send(page('Item deleted', `
    <h2>Item #${row.id} deleted</h2>
    ${extra}
    <p><a href="/http/items">Back to inventory</a> &middot;
    <a href="/http/items/reset">Reset demo items</a></p>
  `));
});

router.get('/items/reset', (req, res) => {
  db.exec('DELETE FROM http_items');
  seedItems();
  res.redirect('/http/items');
});

// ------------------------------------------------ v3: verb tampering
function feedbackSubmit(req, res) {
  const msg = (req.method === 'GET' ? req.query.msg : req.body.msg || '').toString().slice(0, 500);
  if (!msg.trim()) {
    return res.status(400).send(page('Feedback', '<p>Message is required.</p><p><a href="/http/feedback">Back</a></p>'));
  }
  db.prepare('INSERT INTO http_feedback (msg, ts) VALUES (?, ?)').run(msg, new Date().toISOString());
  let extra = '';
  // VULN: documented POST-only, but the GET route runs the same handler, so a
  // state-changing action fires over GET (bookmarkable, loggable, CSRF-able).
  if (req.method === 'GET') {
    const flag = award(req, 'http', 'verb-tamper');
    extra = `<h3>Verb tampering worked</h3>
      <p>This endpoint is documented as POST-only, but your GET request submitted
      feedback anyway.</p>${flagBox(flag)}`;
  }
  res.send(page('Feedback', `
    <h2>Thanks</h2>
    <p>Your feedback was recorded.</p>
    ${extra}
    <p><a href="/http/feedback">Back</a></p>
  `));
}

router.get('/feedback', (req, res) => {
  if (req.query.msg === undefined) {
    return res.send(page('Feedback', `
      <h2>Feedback (POST-only endpoint)</h2>
      <p>Per the API docs, feedback is accepted <b>only via POST</b>.</p>
      <form method="POST" action="/http/feedback">
        <textarea name="msg" rows="3" cols="50" placeholder="your feedback" required></textarea><br /><br />
        <button type="submit">Send via POST</button>
      </form>
      <p><a href="/http">Module index</a></p>
    `));
  }
  feedbackSubmit(req, res);
});
router.post('/feedback', feedbackSubmit);

// --------------------------------------------- v4: X-Forwarded-For admin
router.get('/internal', (req, res) => {
  const xff = (req.get('X-Forwarded-For') || '').split(',')[0].trim();
  // VULN: admin access is granted from the client-controlled X-Forwarded-For
  // header, which any client can set to 127.0.0.1.
  if (xff === '127.0.0.1' || xff === '::1') {
    const flag = award(req, 'http', 'xff-admin');
    return res.send(page('Internal admin', `
      <h2>Internal admin panel</h2>
      <p>Welcome, local admin. Recognized internal address:
      <code>${esc(xff)}</code>.</p>
      <p>Internal note: rotate the deploy keys before Friday.</p>
      ${flagBox(flag)}
      <p><a href="/http">Module index</a></p>
    `));
  }
  res.status(403).send(page('Forbidden', `
    <h2>403 Forbidden</h2>
    <p>Internal use only. Your address is not recognized as local.</p>
    <p class="note">This check trusts the <code>X-Forwarded-For</code> header,
    which proxies add. Can you set headers yourself?</p>
    <p><a href="/http">Module index</a></p>
  `));
});

// -------------------------------------------- v5: cache deception
const CDN = {}; // path -> { user, body }: naive cache keyed on path only
const CDN_SECRETS = { alice: 'ALICE-CDN-SECRET-9d2f', bob: 'BOB-CDN-SECRET-41ab' };

router.get('/cache', (req, res) => {
  const me = req.session.httpUser || 'guest';
  const done = captured(req, 'http', 'cache-deception');
  const keys = Object.keys(CDN);
  res.send(page('CDN cache demo', `
    <h2>CDN cache deception demo</h2>
    <p>A naive in-module "CDN" caches <code>/http/account.css</code> keyed on the
    <b>path only</b>, ignoring who asked. The stylesheet is personalized and sent
    with <code>Cache-Control: public, max-age=3600</code>.</p>
    <p>You are browsing as: <b>${esc(me)}</b>
      ${me === 'guest'
        ? '(<a href="/http/cache-login?user=alice">log in as alice</a> &middot; <a href="/http/cache-login?user=bob">log in as bob</a>)'
        : '(<a href="/http/cache-logout">log out</a>)'}</p>
    <ol>
      <li>As the <b>victim</b>: log in as alice, then open
        <a href="/http/account.css" target="_blank"><code>/http/account.css</code></a>.
        The CDN caches her personalized response.</li>
      <li>As the <b>attacker</b>: in a fresh session (private window, or
        <code>curl</code> without her cookie), request the same URL.</li>
    </ol>
    <p>Cached paths: ${keys.length ? keys.map((k) => `<code>${esc(k)}</code>`).join(', ') : '<i>empty</i>'}
    &middot; <a href="/http/cache-purge">purge cache</a></p>
    ${done ? '<p><b>Flag captured.</b> Check your scoreboard.</p>'
           : '<p class="note">When you pull someone else\'s cached stylesheet, the flag is returned in the <code>X-Flag</code> response header and saved to your scoreboard.</p>'}
    <p><a href="/http">Module index</a></p>
  `));
});

router.get('/cache-login', (req, res) => {
  const u = (req.query.user || '').toString();
  if (CDN_SECRETS[u]) req.session.httpUser = u;
  res.redirect('/http/cache');
});
router.get('/cache-logout', (req, res) => {
  delete req.session.httpUser;
  res.redirect('/http/cache');
});
router.get('/cache-purge', (req, res) => {
  for (const k of Object.keys(CDN)) delete CDN[k];
  res.redirect('/http/cache');
});

router.get('/account.css', (req, res) => {
  const me = req.session.httpUser || 'guest';
  const key = req.path;
  const hit = CDN[key];
  if (hit) {
    res.set('X-Cache', 'HIT');
    res.type('text/css');
    // VULN: the cache key is the path only, so the victim's personalized
    // response is served to the attacker, leaking the victim's data.
    if (hit.user !== me && hit.user !== 'guest') {
      const flag = award(req, 'http', 'cache-deception');
      res.set('X-Flag', flag);
    }
    return res.send(hit.body);
  }
  const body = `/* personalized stylesheet for ${me} */\n.account-secret { content: "${CDN_SECRETS[me] || 'none'}"; }\n`;
  CDN[key] = { user: me, body };
  res.set({ 'Cache-Control': 'public, max-age=3600', 'X-Cache': 'MISS' });
  res.type('text/css');
  res.send(body);
});

// ---------------------------------------------- v6: Referer-based auth
router.get('/trusted', (req, res) => {
  res.send(page('Trusted partner', `
    <h2>Trusted partner page</h2>
    <p>You arrived from the trusted partner network. Continue to the partner portal:</p>
    <p><a href="/http/hidden"><b>Enter the partner portal</b></a></p>
    <p><a href="/http">Module index</a></p>
  `));
});

router.get('/hidden', (req, res) => {
  const referer = req.get('Referer') || '';
  // VULN: authorization is based on the client-controlled Referer header; any
  // client can send Referer: https://partner.example/trusted.
  if (referer.includes('/trusted')) {
    const flag = award(req, 'http', 'referer-auth');
    return res.send(page('Partner portal', `
      <h2>Partner portal</h2>
      <p>Welcome, trusted partner. Referer seen:
      <code>${esc(referer)}</code>.</p>
      <p>Partner secret: the Q4 discount code is <code>PENTRIX-PARTNER-77</code>.</p>
      ${flagBox(flag)}
      <p><a href="/http">Module index</a></p>
    `));
  }
  res.status(403).send(page('Forbidden', `
    <h2>403 Forbidden</h2>
    <p>This hidden page is only reachable from the trusted partner page.</p>
    <p class="note">The check looks at your <code>Referer</code> header. Browsers
    send it automatically, but nothing stops you from sending your own.</p>
    <p><a href="/http">Module index</a></p>
  `));
});

module.exports = {
  id: 'http',
  name: 'HTTP Layer Flaws',
  tagline: 'Verbs, headers, and caches: attack the protocol before the app.',
  description: 'Six flaws in the HTTP layer itself: CRLF log injection, _method verb overriding, GET-vs-POST verb tampering, trusting X-Forwarded-For for admin access, cache deception via a path-only cache key, and Referer-based authorization.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'crlf-log',
      name: 'CRLF Log Injection',
      difficulty: 'Medium',
      hint: 'The ?ref= value is written raw into the access log. What do %0d and %0a become after URL decoding?',
      how: 'Send CR/LF bytes in ref so a forged line appears in the admin log view.',
    },
    {
      id: 'method-override',
      name: 'HTTP Method Override',
      difficulty: 'Medium',
      hint: 'The app rewrites the HTTP verb from a _method body parameter. The UI never sends DELETE, but the route exists.',
      how: 'POST to /http/items/<id> with _method=DELETE to delete without approval.',
    },
    {
      id: 'verb-tamper',
      name: 'Verb Tampering',
      difficulty: 'Easy',
      hint: 'The docs say POST-only. Try the exact same request as a GET.',
      how: 'Submit feedback with GET instead of POST.',
    },
    {
      id: 'xff-admin',
      name: 'X-Forwarded-For Trust',
      difficulty: 'Easy',
      hint: 'The admin check reads a header that proxies add, but clients can also send.',
      how: 'Send X-Forwarded-For: 127.0.0.1 to /http/internal.',
    },
    {
      id: 'cache-deception',
      name: 'Cache Deception',
      difficulty: 'Medium',
      hint: 'The cache key is the path only. Cache the victim\'s personalized CSS, then fetch it as someone else.',
      how: 'As alice, visit /http/account.css; then fetch it again in a fresh session to read her data.',
    },
    {
      id: 'referer-auth',
      name: 'Referer-Based Auth',
      difficulty: 'Easy',
      hint: 'Access is granted when the Referer header contains /trusted. Headers are yours to set.',
      how: 'Request /http/hidden with a Referer header containing /trusted.',
    },
  ],
  router,
};
