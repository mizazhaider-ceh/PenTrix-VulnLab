'use strict';
// Race-coupon: the single-use coupon RACE10 is checked ("already used?") and
// marked used as two separate steps with an async gap between them, so
// parallel redeems all see used=false and the coupon is redeemed twice.
const express = require('express');
const { page, esc, appShell, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'race-coupon',
  name: 'Single-Use Coupon Redeemed Twice',
  difficulty: 'Medium',
  hint: 'The coupon is marked "used" only after an async gap. What happens when 20 requests check "is it used?" at the same moment?',
  hints: ["The coupon can be redeemed once. But what if two redeems happen at the same time?", "Check-then-act: both requests see 'unused' before either marks it used. Parallel redeems double-spend.", "Fire a burst of parallel redeems using the same coupon code, then count how many succeeded. More than one success means the coupon was double-spent."],
  tools: 'P, C',
  how: 'Fire parallel POSTs at /race/coupon/redeem so the coupon is redeemed more than once.',
  link: '/race#race-coupon',
  start: 'curl http://localhost:3000/race/coupon',
};

// Challenge-local presentation: a clay card hero for this shop screen.
function shop(crumb, body) {
  return appShell('PenTrix Shop', body, { crumb, mark: '◈', nav: ['Home', 'Catalog', 'Rewards', 'Cart'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race/reset">Reset lab state</a></p>`;
}

router.get('/coupon', (req, res) => {
  const c = shared.state().coupon;
  res.send(page('Single-use coupon', shop('Rewards', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>Rewards</b><span class="dim">Coupon RACE10</span></div>
      <h2>Coupon: RACE10 ($10 credit, one use only)</h2>
      <p>Coupon used: <b>${c.used}</b> · Redeemed: <b>${c.redeems}</b> time(s) · Credit issued: <b>$${c.credit}</b></p>
      <form method="POST" action="/race/coupon/redeem">
        <button type="submit" class="clay-btn clay-btn-primary">Redeem coupon</button>
      </form>
    </section>
    ${hintLadder(vuln)}
    <h2>Test it yourself</h2>
    <p>One click redeems it once. Twenty parallel requests redeem it more than once:</p>
    ${payloadBlock('Parallel redeems', 'seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/coupon/redeem')}
    ${backLinks()}
  `)));
});

router.post('/coupon/redeem', async (req, res) => {
  // VULN: the "already used?" check and the "mark used" write are separated by
  // an await, so parallel requests all see used=false before any write lands.
  if (shared.state().coupon.used) {
    return res.send(page('Coupon', shop('Rewards', `
      <section class="clay-card">
        <h2>Already redeemed</h2>
        <p>This coupon was already used. Reset the lab to try again.</p>
        ${backLinks()}
      </section>
    `)));
  }
  await shared.sleep(shared.WINDOW());
  const c = shared.state().coupon;
  c.used = true;
  c.redeems += 1;
  c.credit += 10;

  let flagHtml = '';
  if (c.redeems > 1 && !captured(req, 'race', 'race-coupon')) {
    flagHtml = flagBox(award(req, 'race', 'race-coupon'));
    flagHtml += fixPanel('race', 'race-coupon');
  }
  res.send(page('Coupon redeemed', shop('Rewards', `
    <section class="clay-card">
      <h2>Coupon redeemed</h2>
      <p>$10 credit issued. Total redemptions so far: <b>${c.redeems}</b>.</p>
      ${c.redeems > 1 ? '<p><b>The one-use coupon was redeemed more than once.</b> The check raced the write.</p>' : ''}
      ${flagHtml}
      ${backLinks()}
    </section>
  `)));
});

module.exports = { vuln, router };
