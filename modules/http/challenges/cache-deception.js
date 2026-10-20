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
// challenge file so the module split keeps it private to this challenge,
// and scoped per session (P1-1): each browser session gets its own edge
// cache, so one student's primed victim response is never served to another
// student. The solo attack still works: prime the cache as the victim, then
// come back "as someone else" in the same session (log out, or switch to
// the other demo user) and fetch the same path.
const { createSessionState } = require('../../../lib/session-state');
const CDNS = createSessionState(() => ({}));
const CDN_SECRETS = { alice: 'ALICE-CDN-SECRET-9d2f', bob: 'BOB-CDN-SECRET-41ab' };

const vuln = {
  id: 'cache-deception',
  name: 'Cache Deception',
  difficulty: 'Medium',
  hint: 'The cache remembers responses by path alone, but the response depends on who asked. Who else can collect what the cache stored?',
  hints: ["The CDN caches /http/account.css by path only, and the CSS is personalized. In Burp Repeater, request the CSS under two different identities and compare the raw responses.", "Prime, then collect: fetch the personalized resource while signed in as one user so the cache stores it, then fetch the same path as someone else (signed out, or another demo user). Notice what the cache never checks between the two visits.", "Shape: two requests for one path, the first as the victim so a personalized response is stored, the second as a stranger. Read the second response in full, headers included: a cache that keys on path alone cannot tell the two of you apart."],
  tools: 'BZ, B, C',
  est: 'about 10 to 20 minutes',
  how: 'A cache that keys on the URL path alone will hand one user a personalized response that was stored for somebody else.',
  link: '/http#cache-deception',
  start: 'Send your browser through Burp Proxy. 1) Sign in as one demo user and fetch the personalized stylesheet, so the cache stores a response. 2) Return as a different identity (signed out, or the other demo user) and request the same path again. 3) Compare the two responses in full in Repeater.',
};

// GET /cache -> the CDN demo dashboard: who you are, the two-step attack
// walkthrough, live cache state, and the capture status.
router.get('/cache', (req, res) => {
  const me = req.session.httpUser || 'guest';
  const done = captured(req, 'http', 'cache-deception');
  const CDN = CDNS.get(req);
  const keys = Object.keys(CDN);

  const head = `<div class="card">
    <div class="card-top"><span class="orb" aria-hidden="true">🧪</span><b>${esc(vuln.name)}</b></div>
    <div class="cta-row">${difficultyPill(vuln.difficulty)}${toolsPill(vuln)}</div>
    ${hintLadder(vuln)}
  </div>`;

  const sessionCard = me === 'guest'
    ? `<div class="card">
        <div class="card-top"><b>Your session</b></div>
        <p>You are browsing as <b>guest</b>. Log in as the victim first, prime the cache, then attack as a different identity.</p>
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
    <p>Think in two visits: one visit stores a response, a later visit collects
    whatever was stored. The session card above lets you switch identities;
    Burp Proxy history shows what the cache served each identity, and the
    cache state card below shows what is currently stored.</p>
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
        <p class="note">When you pull someone else's cached stylesheet, the capture is
        saved to your scoreboard. The response is a stylesheet, not a page, so inspect
        the full response in Burp, headers included.</p>
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

// GET /cache-purge -> empty this session's edge cache.
router.get('/cache-purge', (req, res) => {
  const CDN = CDNS.get(req);
  for (const k of Object.keys(CDN)) delete CDN[k];
  res.redirect('/http/cache');
});

// GET /account.css -> personalized stylesheet served through the naive
// path-only cache. First visit (MISS) caches the personalized body; a later
// visit from a different user (HIT) gets the cached body. When the cached
// entry belongs to someone else, the flag goes out in the X-Flag header.
router.get('/account.css', (req, res) => {
  const me = req.session.httpUser || 'guest';
  const CDN = CDNS.get(req);
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
