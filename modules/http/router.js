// PenTrix VulnLab module: HTTP Layer Flaws (http)
// Three labs below the application logic: CRLF log injection, verb tampering,
// and cache deception via a path-only cache key.
const express = require('express');
const { getDb } = require('../../lib/db');
const { brief, esc, fixPanel, flagBox, hintBox, hintLadder, page, toolsPill, trackBanner } = require('../../lib/page');
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
  ['feedback', 'verb-tamper'],
  ['cache', 'cache-deception'],
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
        ${hintLadder(v)}
      ${toolsPill(v)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('HTTP Layer Flaws', `
    ${brief('Module briefing', `
      <p><b>What lives at the HTTP layer?</b> Before your application code even runs,
      the request passes through verbs, headers, and caches. This module attacks those:
      log forging with CR/LF bytes (confirmed in the log viewer, not on input),
      verb confusion (GET-vs-POST), and a naive cache keyed on the URL path alone.</p>
      <p><b>Heads up:</b> the cache-deception flag is returned in an <code>X-Flag</code>
      response header (the response is CSS, not HTML),
      and every capture is also saved to your scoreboard.</p>`)}
    ${trackBanner(module.exports)}
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
  // VULN: the raw ref, CR/LF bytes included, is written to the access log with
  // no sanitization, so %0d%0a forges extra log lines (and HTML in the viewer).
  // No flag here: the award lands in the log viewer, only when the forged line
  // is actually observed there (evidence-based, not input-pattern-based).
  if (/[\r\n]/.test(ref)) {
    req.session.crlf_probe = ref;
  }
  res.send(page('Tracker', `
    <h2>Visit tracked</h2>
    <p>Logged this visit from <code>${esc(ip)}</code> at <code>${esc(ts)}</code>.</p>
    ${/[\r\n]/.test(ref) ? '<p class="note">CR/LF bytes were written straight into the access log. <a href="/http/admin/log"><b>Open the log viewer</b></a> and confirm your forged line appears there.</p>' : ''}
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
  let extra = '';
  // Evidence-based award (M7): the flag lands only when THIS session's injected
  // ref is present in the log AND the injection actually forged extra lines
  // (rendered lines outnumber stored rows). Visiting the viewer without a
  // successful injection earns nothing.
  const probe = req.session.crlf_probe;
  if (!captured(req, 'http', 'crlf-log') && probe &&
      rows.some((r) => r.ref === probe) &&
      lines.split('\n').length > rows.length) {
    const flag = award(req, 'http', 'crlf-log');
    extra = `<h3>Forged log line confirmed</h3>
      <p>Your injected CR/LF bytes split the log: the viewer renders
      <b>${lines.split('\n').length}</b> lines from <b>${rows.length}</b> stored
      entries. The forged entry is really in there.</p>
      ${flagBox(flag)}${fixPanel('http', 'crlf-log')}`;
  }
  res.send(page('Access log', `
    <h2>Access log (admin view)</h2>
    <p>Raw log, newest first. No output encoding is applied here.</p>
    <pre>${lines}</pre>
    ${extra}
    <p><a href="/http">Module index</a></p>
  `));
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
      feedback anyway.</p>${flagBox(flag)}${fixPanel('http', 'verb-tamper')}`;
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

module.exports = {
  id: 'http',
  name: 'HTTP Layer Flaws',
  tagline: 'Verbs, headers, and caches: attack the protocol before the app.',
  description: 'Three flaws in the HTTP layer itself: CRLF log injection with a forged line confirmed in the log viewer, GET-vs-POST verb tampering, and cache deception via a path-only cache key.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['misconfig'],
  vulns: [
    {
      id: 'crlf-log',
      name: 'CRLF Log Injection',
      difficulty: 'Medium',
      hint: 'The ?ref= value is written raw into the access log. What do %0d and %0a become after URL decoding?',
      hints: ["The ?ref= parameter is logged raw. What are %0d and %0a?", "CR/LF bytes. They split the log line and forge new entries.", "Try /http/track?ref=x%0d%0aFAKE log line, then open /http/admin/log and confirm your forged line is there."],
      tools: "C",
      how: 'Send CR/LF bytes in ref so a forged line appears in the admin log view.',
    },
    {
      id: 'verb-tamper',
      name: 'Verb Tampering',
      difficulty: 'Easy',
      hint: 'The docs say POST-only. Try the exact same request as a GET.',
      hints: ["The docs say POST-only. But what happens if you send a GET?", "The GET route runs the same handler. The action fires.", "Open /http/feedback?msg=hi as a GET. The feedback is recorded."],
      tools: "B",
      how: 'Submit feedback with GET instead of POST.',
    },
    {
      id: 'cache-deception',
      name: 'Cache Deception',
      difficulty: 'Medium',
      hint: 'The cache key is the path only. Cache the victim\'s personalized CSS, then fetch it as someone else.',
      hints: ["The CDN caches /http/account.css by path only. The CSS is personalized. What happens?", "Log in as alice, visit the CSS (caches her version), then fetch it as someone else. You get her data.", "As alice: GET /http/account.css. Then in a fresh session: GET it again. Her secret is in the X-Flag header."],
      tools: "B, C",
      how: 'As alice, visit /http/account.css; then fetch it again in a fresh session to read her data.',
    },
  ],
  router,
};
