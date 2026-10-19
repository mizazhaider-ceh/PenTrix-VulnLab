'use strict';
// Cache deception: GET /http/account.css serves a personalized stylesheet
// through a naive cache keyed on the path only, so the victim's cached
// response is served to a stranger. The flag is returned in the X-Flag
// response header (the response is CSS, not HTML).
const express = require('express');
const { award, captured, flagFor } = require('../../../lib/flags');
const { page, esc, flagBanner, fixPanel, hintLadder, toolsPill,
  difficultyPill, payloadBlock, appShell, brief } = require('../../../lib/page');

const router = express.Router();

// path -> { user, body }: naive cache keyed on path only. Lives in this
// challenge file so the module split keeps it private to this challenge.
const CDN = {};
const CDN_SECRETS = { alice: 'ALICE-CDN-SECRET-9d2f', bob: 'BOB-CDN-SECRET-41ab' };

const vuln = {
  id: 'cache-deception',
  name: 'Cache Deception',
  difficulty: 'Medium',
  hint: 'The cache key is the path only. Cache the victim\'s personalized CSS, then fetch it as someone else.',
  hints: ["The CDN caches /http/account.css by path only. The CSS is personalized. What happens?", "Log in as alice, visit the CSS (caches her version), then fetch it as someone else. You get her data.", "Prime the cache with alice's version of the stylesheet, then request the same path from a fresh session that is not logged in. The key insight: the cache key is the path alone, so the second request is served her personalized copy, and the flag rides in its response headers, not the body."],
  tools: 'B, C',
  how: 'As alice, visit /http/account.css; then fetch it again in a fresh session to read her data.',
  link: '/http#cache-deception',
  start: 'curl -s -c alice.jar http://localhost:3000/http/cache-login?user=alice\ncurl -s -b alice.jar -c alice.jar http://localhost:3000/http/account.css\ncurl -s -i http://localhost:3000/http/account.css | grep -i x-flag',
};

// GET /cache -> the CDN demo dashboard: who you are, the two-step attack
// walkthrough, live cache state, and the capture status.
router.get('/cache', (req, res) => {
  const me = req.session.httpUser || 'guest';
  const done = captured(req, 'http', 'cache-deception');
  const keys = Object.keys(CDN);

  const head = `<div class="card">
    <div class="card-top"><span class="orb" aria-hidden="true">🧪</span><b>${esc(vuln.name)}</b></div>
    <div class="cta-row">${difficultyPill(vuln.difficulty)}${toolsPill(vuln)}</div>
    ${hintLadder(vuln)}
  </div>`;

  const sessionCard = me === 'guest'
    ? `<div class="card">
        <div class="card-top"><b>Your session</b></div>
        <p>You are browsing as <b>guest</b>. Log in as the victim first, then attack from a fresh session.</p>
        <div class="cta-row">
          <a class="clay-btn clay-btn-primary" href="/http/cache-login?user=alice">Log in as alice</a>
          <a class="clay-btn clay-btn-secondary" href="/http/cache-login?user=bob">Log in as bob</a>
        </div>
      </div>`
    : `<div class="card">
        <div class="card-top"><b>Your session</b></div>
        <p>You are browsing as <b>${esc(me)}</b>.</p>
        <div class="cta-row"><a class="clay-btn clay-btn-secondary" href="/http/cache-logout">Log out</a></div>
      </div>`;

  const stepsCard = `<div class="card">
    <div class="card-top"><b>Attack walkthrough</b></div>
    <p>A naive edge "CDN" caches <code>/http/account.css</code> keyed on the <b>path only</b>,
    ignoring who asked. The stylesheet is personalized and sent with
    <code>Cache-Control: public, max-age=3600</code>.</p>
    <ol>
      <li>As the <b>victim</b>: log in as alice, then open
        <a href="/http/account.css" target="_blank" rel="noopener"><code>/http/account.css</code></a>.
        The CDN caches her personalized response.</li>
      <li>As the <b>attacker</b>: in a fresh session (private window, or <code>curl</code>
        without her cookie), request the same URL.</li>
    </ol>
    ${payloadBlock('Attack flow (curl)', 'curl -s -c alice.jar http://localhost:3000/http/cache-login?user=alice\ncurl -s -b alice.jar -c alice.jar http://localhost:3000/http/account.css\ncurl -s -i http://localhost:3000/http/account.css | grep -i x-flag')}
  </div>`;

  const cacheCard = `<div class="card">
    <div class="card-top"><b>Cache state</b></div>
    <p>Cached paths: ${keys.length ? keys.map((k) => `<code>${esc(k)}</code>`).join(', ') : '<i>empty</i>'}</p>
    <div class="cta-row"><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/http/cache-purge">Purge cache</a></div>
  </div>`;

  const doneBlock = done
    ? flagBanner(flagFor('http', 'cache-deception')) + fixPanel('http', 'cache-deception')
    : `<div class="card">
        <div class="card-top"><b>Capture</b></div>
        <p class="note">When you pull someone else's cached stylesheet, the flag is returned in the
        <code>X-Flag</code> response header and saved to your scoreboard. (The response is CSS, not HTML,
        so the header only shows in devtools or with <code>curl -i</code>.)</p>
      </div>`;

  res.send(page('CDN cache demo', appShell('SpeedEdge CDN', `
    ${brief('Edge node demo', 'A tiny CDN sits in front of the account service. It caches whole responses, but its cache key is only the URL path.')}
    ${head}
    ${sessionCard}
    ${stepsCard}
    ${cacheCard}
    ${doneBlock}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/http">Module index</a></p>
  `, { crumb: 'Edge demo / cache deception', mark: '⚡' })));
});

// GET /cache-login -> "log in" as alice or bob (demo users for the CDN story).
router.get('/cache-login', (req, res) => {
  const u = (req.query.user || '').toString();
  if (CDN_SECRETS[u]) req.session.httpUser = u;
  res.redirect('/http/cache');
});

// GET /cache-logout -> drop the demo login.
router.get('/cache-logout', (req, res) => {
  delete req.session.httpUser;
  res.redirect('/http/cache');
});

// GET /cache-purge -> empty the edge cache.
router.get('/cache-purge', (req, res) => {
  for (const k of Object.keys(CDN)) delete CDN[k];
  res.redirect('/http/cache');
});

// GET /account.css -> personalized stylesheet served through the naive
// path-only cache. First visit (MISS) caches the personalized body; a later
// visit from a different user (HIT) gets the cached body. When the cached
// entry belongs to someone else, the flag goes out in the X-Flag header.
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

module.exports = { vuln, router };
