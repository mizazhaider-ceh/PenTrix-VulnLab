'use strict';
// Race module: every challenge must be solvable by the documented parallel
// burst technique, and must NOT award for the benign sequential action.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// Fire n parallel POSTs and return the concatenated response bodies.
async function burstN(c, url, form, n) {
  const jobs = [];
  for (let i = 0; i < n; i++) jobs.push(c.post(url, form));
  const resps = await Promise.all(jobs);
  return resps.map((r) => r.text).join('\n');
}

function noFlag(text, why) {
  assert.equal((text.match(FLAG_RE) || []).length, 0, why);
}

test('race module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'race', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/race');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/race/coupon', '/race/transfer', '/race/vote', '/race/referral', '/race/register', '/race/upload', '/race/ratelimit', '/race/stock']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('race reset is POST-only (P1-2): a GET wipes nothing', async () => {
    const c = client(srv.base);
    const r = await c.get('/race/reset');
    assert.equal(r.status, 404, 'GET /race/reset must not exist anymore');
  });

  await t.test('race-coupon: one redeem earns nothing, parallel redeems earn the flag', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    const solo = await c.post('/race/coupon/redeem');
    noFlag(solo.text, 'a single redeem must not award');
    const again = await c.post('/race/coupon/redeem');
    assert.ok(again.text.includes('Already redeemed'));
    noFlag(again.text, 'a second sequential redeem must not award');
    await c.post('/race/reset');
    const texts = await burstN(c, '/race/coupon/redeem', undefined, 20);
    assert.ok(texts.includes(flagOf('race-coupon')), 'parallel redeems must award');
    assert.ok((await capturedSet(c)).includes('race:Single-Use Coupon Redeemed Twice'));
  });

  await t.test('race-balance: one transfer is safe, parallel transfers double-spend', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    const solo = await c.post('/race/transfer', { to: 'attacker', amount: '100' });
    noFlag(solo.text, 'one transfer must not award');
    await c.post('/race/reset');
    const texts = await burstN(c, '/race/transfer', { to: 'attacker', amount: '100' }, 20);
    assert.ok(texts.includes(flagOf('race-balance')), 'parallel transfers must award');
    assert.ok((await capturedSet(c)).includes('race:Double-Spend the Balance'));
  });

  await t.test('race-vote: sequential votes stay unique, parallel votes duplicate', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    const solo = await c.post('/race/vote', { name: 'voter1' });
    noFlag(solo.text, 'one vote must not award');
    const again = await c.post('/race/vote', { name: 'voter1' });
    assert.ok(again.text.includes('Already voted'));
    noFlag(again.text, 'a second sequential vote must not award');
    await c.post('/race/reset');
    const texts = await burstN(c, '/race/vote', { name: 'voter1' }, 6);
    assert.ok(texts.includes(flagOf('race-vote')), 'parallel votes must award');
    assert.ok((await capturedSet(c)).includes('race:Vote Counted Twice'));
  });

  await t.test('race-referral: one claim is fine, parallel claims double the bonus', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    const solo = await c.post('/race/referral', { code: 'REF2026' });
    noFlag(solo.text, 'one claim must not award');
    const bad = await c.post('/race/referral', { code: 'NOPE' });
    assert.ok(bad.text.includes('Invalid code'));
    noFlag(bad.text, 'an invalid code must not award');
    await c.post('/race/reset');
    const texts = await burstN(c, '/race/referral', { code: 'REF2026' }, 10);
    assert.ok(texts.includes(flagOf('race-referral')), 'parallel claims must award');
    assert.ok((await capturedSet(c)).includes('race:Referral Bonus Claimed Twice'));
  });

  await t.test('race-register: sequential signups stay unique, parallel signups duplicate the name', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    const solo = await c.post('/race/register', { username: 'racer', password: 'hunter2' });
    noFlag(solo.text, 'one signup must not award');
    const dup = await c.post('/race/register', { username: 'racer', password: 'hunter2' });
    assert.ok(dup.text.includes('Username taken'));
    noFlag(dup.text, 'a duplicate sequential signup must not award');
    await c.post('/race/reset');
    const texts = await burstN(c, '/race/register', { username: 'racer', password: 'hunter2' }, 5);
    assert.ok(texts.includes(flagOf('race-register')), 'parallel signups must award');
    assert.ok((await capturedSet(c)).includes('race:Duplicate Username Registration'));
  });

  await t.test('race-upload-scan: a missing file 404s, a live file serves and awards', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    assert.equal((await c.get('/race/files/never-uploaded.txt')).status, 404);
    await c.post('/race/upload', { filename: 'secret.txt', content: 'top secret lab data' });
    const live = await c.get('/race/files/secret.txt');
    assert.equal(live.status, 200);
    assert.ok(live.text.includes('top secret lab data'));
    assert.ok(live.text.includes(flagOf('race-upload-scan')), 'fetching before the scan must award');
    assert.ok((await capturedSet(c)).includes('race:Beat the AV Scan (TOCTOU)'));
  });

  await t.test('race-upload-scan: the AV scan deletes the file after 2 seconds', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    await c.post('/race/upload', { filename: 'gone.txt', content: 'x' });
    await new Promise((r) => setTimeout(r, 2300));
    const gone = await c.get('/race/files/gone.txt');
    assert.equal(gone.status, 404);
    noFlag(gone.text, 'a deleted file must not award');
  });

  await t.test('race-ratelimit: five sequential hits pass, a sixth is rejected, a burst gets through', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    for (let i = 0; i < 5; i++) {
      const r = await c.post('/race/ratelimit/hit');
      assert.equal(r.status, 200);
      noFlag(r.text, 'a request under the limit must not award');
    }
    assert.equal((await c.post('/race/ratelimit/hit')).status, 429);
    await c.post('/race/reset');
    const texts = await burstN(c, '/race/ratelimit/hit', undefined, 20);
    assert.ok(texts.includes(flagOf('race-ratelimit')), 'a parallel burst must award');
    assert.ok((await capturedSet(c)).includes('race:Burst Through the Rate Limit'));
  });

  await t.test('race-stock: one order of 5 stays in stock, parallel orders oversell', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    const solo = await c.post('/race/stock/buy', { qty: '5' });
    assert.ok(solo.text.includes('Total sold: <b>5</b>'));
    noFlag(solo.text, 'one full-stock order must not award');
    await c.post('/race/reset');
    const texts = await burstN(c, '/race/stock/buy', { qty: '5' }, 10);
    assert.ok(texts.includes(flagOf('race-stock')), 'parallel orders must award');
    assert.ok((await capturedSet(c)).includes('race:Oversell the Stock'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    await burstN(c, '/race/coupon/redeem', undefined, 20);
    await c.post('/race/reset');
    await burstN(c, '/race/transfer', { to: 'attacker', amount: '100' }, 20);
    await c.post('/race/reset');
    await burstN(c, '/race/vote', { name: 'voter9' }, 6);
    await c.post('/race/reset');
    await burstN(c, '/race/referral', { code: 'REF2026' }, 10);
    await c.post('/race/reset');
    await burstN(c, '/race/register', { username: 'racer9', password: 'x' }, 5);
    await c.post('/race/upload', { filename: 'flag9.txt', content: 'data' });
    await c.get('/race/files/flag9.txt');
    await c.post('/race/reset');
    await burstN(c, '/race/ratelimit/hit', undefined, 20);
    await c.post('/race/reset');
    await burstN(c, '/race/stock/buy', { qty: '5' }, 10);
    const got = (await capturedSet(c)).filter((s) => s.startsWith('race:'));
    assert.equal(got.length, 8);
    assert.equal(new Set(got).size, 8);
  });

  // P5-6 concurrency guard: two students bursting DIFFERENT challenges at
  // the same moment must both capture, and neither session may pick up the
  // other's flag.
  await t.test('concurrency: two clients bursting different challenges in parallel both capture, sessions stay isolated', async () => {
    const a = client(srv.base);
    const b = client(srv.base);
    await a.post('/race/reset');
    // B primes a session first (a real student has one from browsing); with
    // per-session state (P1-1) a cookie-less parallel burst would fragment
    // across throwaway sessions and could never oversell.
    await b.post('/race/reset');
    const [aTexts, bTexts] = await Promise.all([
      burstN(a, '/race/coupon/redeem', undefined, 20),
      burstN(b, '/race/stock/buy', { qty: '5' }, 10),
    ]);
    assert.ok(aTexts.includes(flagOf('race-coupon')), 'client A must capture the coupon flag');
    assert.ok(bTexts.includes(flagOf('race-stock')), 'client B must capture the stock flag');
    const aGot = (await capturedSet(a)).filter((s) => s.startsWith('race:'));
    const bGot = (await capturedSet(b)).filter((s) => s.startsWith('race:'));
    assert.deepEqual(aGot, ['race:Single-Use Coupon Redeemed Twice'], 'A must hold only its own capture');
    assert.deepEqual(bGot, ['race:Oversell the Stock'], 'B must hold only its own capture');
  });

  // P5-6 concurrency guard: captures are session state, so one client's
  // scoreboard must survive another client's resets and bursts untouched
  // (regression guard for the session-fragility reports, P1-6).
  await t.test('concurrency: one client\'s captures survive another client\'s resets and parallel bursts', async () => {
    const a = client(srv.base);
    const b = client(srv.base);
    await a.post('/race/reset');
    const texts = await burstN(a, '/race/coupon/redeem', undefined, 20);
    assert.ok(texts.includes(flagOf('race-coupon')), 'setup: client A captures the coupon flag');
    const before = (await capturedSet(a)).filter((s) => s.startsWith('race:'));
    assert.deepEqual(before, ['race:Single-Use Coupon Redeemed Twice']);

    // Client B churns the shared lab: resets and bursts other challenges.
    await b.post('/race/reset');
    await burstN(b, '/race/transfer', { to: 'attacker', amount: '100' }, 20);
    await b.post('/race/reset');
    await burstN(b, '/race/vote', { name: 'voter-other' }, 6);

    const after = (await capturedSet(a)).filter((s) => s.startsWith('race:'));
    assert.deepEqual(after, before, 'A\'s captures must survive B\'s activity');
  });
});
