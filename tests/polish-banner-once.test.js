'use strict';
// P1A regression: the capture banner renders exactly once per capture.
// A parallel burst (or a sequential repeat) that re-satisfies an award
// condition in the same session must not re-render the banner, capture
// counts must stay correct, a different capture must still get its own
// banner, and the flag must stay viewable through the already-captured
// flagFor display path on module pages.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, scoreOf } = require('./helpers');

const BANNER_RE = /class="flag-banner"/g;
const banners = (text) => (text.match(BANNER_RE) || []).length;

async function burstGets(c, url, n) {
  const jobs = [];
  for (let i = 0; i < n; i++) jobs.push(c.get(url));
  return Promise.all(jobs);
}

test('polish banner once per capture', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (mod, id) => flagFromDb(dataDir, mod, id);

  await t.test('parallel burst on an unguarded award path renders one banner total', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    await c.post('/race/upload', { filename: 'secret.txt', content: 'top secret lab data' });
    const resps = await burstGets(c, '/race/files/secret.txt', 20);
    const total = resps.reduce((n, r) => n + banners(r.text), 0);
    assert.equal(total, 1, 'exactly one banner across the whole burst');
    const withFlag = resps.filter((r) => r.text.includes(flagOf('race', 'race-upload-scan')));
    assert.equal(withFlag.length, 1, 'exactly one burst response carries the flag banner');
    assert.equal((await scoreOf(c)).got, 1, 'scoreboard counts the capture once');
    assert.deepEqual(
      (await capturedSet(c)).filter((s) => s.startsWith('race:')),
      ['race:Beat the AV Scan (TOCTOU)'],
    );
  });

  await t.test('sequential repeats of the same capture render no new banner', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    await c.post('/race/upload', { filename: 'one.txt', content: 'x' });
    const first = await c.get('/race/files/one.txt');
    assert.equal(banners(first.text), 1, 'the first genuine award shows the banner');
    assert.ok(first.text.includes(flagOf('race', 'race-upload-scan')));
    await c.post('/race/upload', { filename: 'two.txt', content: 'x' });
    let total = 0;
    for (let i = 0; i < 3; i++) total += banners((await c.get('/race/files/two.txt')).text);
    assert.equal(total, 0, 're-satisfying the same award condition renders no banner again');
    assert.equal((await scoreOf(c)).got, 1, 'capture count is still one');
  });

  await t.test('a second, different capture in the same session still shows its own banner', async () => {
    const c = client(srv.base);
    await c.post('/race/reset');
    await c.post('/race/upload', { filename: 'first.txt', content: 'x' });
    const first = await c.get('/race/files/first.txt');
    assert.equal(banners(first.text), 1);
    await c.post('/race/reset');
    const jobs = [];
    for (let i = 0; i < 20; i++) jobs.push(c.post('/race/coupon/redeem'));
    const resps = await Promise.all(jobs);
    const total = resps.reduce((n, r) => n + banners(r.text), 0);
    assert.equal(total, 1, 'the coupon burst renders exactly one banner for its own capture');
    assert.ok(resps.some((r) => r.text.includes(flagOf('race', 'race-coupon'))));
    assert.equal((await scoreOf(c)).got, 2, 'both captures counted, once each');
  });

  await t.test('repeat exploit page holds one banner, and the flag stays viewable via the captured display', async () => {
    const c = client(srv.base);
    const url = '/lfi/view?file=' + encodeURIComponent('../docs/secret.txt');
    const first = await c.get(url);
    assert.equal(banners(first.text), 1, 'first traversal capture shows one banner');
    assert.ok(first.text.includes(flagOf('lfi', 'traversal')));
    const repeat = await c.get(url);
    assert.equal(banners(repeat.text), 1, 'repeat page must not stack the award banner on the captured display');
    assert.ok(repeat.text.includes(flagOf('lfi', 'traversal')), 'flag still visible on the repeat page');
    const benign = await c.get('/lfi/view?file=readme.txt');
    assert.equal(banners(benign.text), 1, 'already-captured display still renders on a benign page view');
    assert.ok(benign.text.includes(flagOf('lfi', 'traversal')), 'flag stays viewable and copyable after capture');
    assert.equal((await scoreOf(c)).got, 1);
  });
});
