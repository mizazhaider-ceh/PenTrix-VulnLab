'use strict';
// Callback Filter Bypass: the "alert" blocklist fails against runtime string
// concatenation. The response embeds a per-session token; the injected script
// must echo it back to /jsonp/beacon-xss to claim the flag.
const express = require('express');
const { page, appShell, payloadBlock } = require('../../../lib/page');
// Provided by the module shared helper (../shared.js) the finisher wires up:
// per-session, per-vuln JSONP nonce used by the reflection beacon.
const { jsonpNonce } = require('../shared');

const router = express.Router();

// The claim flow for this lab: input alone earns nothing, only an executed
// payload that echoes the per-session token back to /jsonp/beacon-xss counts.
function claimInfo() {
  return `<div class="clay-card claim-card">
    <div class="card-top"><b>How to claim this flag</b></div>
    <ol>
      <li>Craft a callback that rebuilds the blocked word at runtime (string
      concatenation instead of typing it), reads the <code>token</code> field
      from the response data, and beacons it.</li>
      <li>Load the JSONP URL as a <code>&lt;script&gt;</code> tag on a page you
      control so the payload really executes. A token-less beacon earns
      nothing.</li>
      <li>A valid beacon to <code>/jsonp/beacon-xss</code> awards the flag, and
      the scoreboard marks it captured.</li>
    </ol>
    <p><b>Payload pattern:</b></p>
    ${payloadBlock('Payload pattern', `<script src="/jsonp/filtered?callback=(d=>top['fe'+'tch']('/jsonp/beacon-xss?v=filter-bypass&n='+d.token))//"></script>`)}
  </div>`;
}

// GET /jsonp/filtered -> the JSONP feed with a naive callback blocklist.
router.get('/filtered', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  if (/alert/i.test(cb)) {
    return res.status(400).send(page('Callback blocked', `
      ${appShell('WidgetForge', `
        <h2>Callback blocked</h2>
        <p>The word "alert" is not allowed in callback names.</p>
        <div class="callout"><b>Developer note:</b> blocklists fail when the
        dangerous string can be rebuilt at runtime. JavaScript string
        concatenation still works inside a callback.</div>
        ${claimInfo()}
        <p><a class="clay-btn clay-btn-secondary" href="/jsonp#filter-bypass">Challenge card</a>
        <a class="clay-btn clay-btn-secondary" href="/jsonp">Module index</a></p>
      `, { mark: '◈', nav: ['Docs', 'Feeds', 'Support'] })}
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

module.exports = {
  vuln: {
    id: 'filter-bypass',
    name: 'Callback Filter Bypass',
    difficulty: 'Medium',
    hint: 'Only the literal word "alert" is blocked. JavaScript can build strings at runtime. Your payload must also echo the per-session token from the response data back to /jsonp/beacon-xss.',
    hints: ["In Repeater, send /jsonp/filtered?callback=alert(1) and read the 400: the blocklist is literal, it only bans the typed word.", "Rebuild the banned word at runtime by joining string pieces, so the filter never sees the literal text; watch the 200 come back in Repeater.", "The 200 response embeds a per-session token. Extract it in Repeater and beacon it to /jsonp/beacon-xss?v=filter-bypass&n=<token> to claim the flag."],
    tools: "BZ, B",
    how: 'Defeat the naive blocklist in Repeater by rebuilding the banned word with runtime string concatenation, so the filter never sees the literal text. Read the per-session token from the 200 response and beacon it to /jsonp/beacon-xss?v=filter-bypass&n=<token>; the beacon response awards the flag.',
    link: '/jsonp#filter-bypass',
    start: 'Browse to /jsonp/filtered?callback=test through Burp Proxy, send the request to Repeater, and confirm the feed reflects the callback. Then probe the filter: try the banned word, read the 400, and find a way to rebuild it at runtime.',
  },
  router,
};
