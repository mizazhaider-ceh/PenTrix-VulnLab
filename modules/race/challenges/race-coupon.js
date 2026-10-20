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
  hints: ["The coupon can be redeemed once. But what if two redeems happen at the same time?", "Check-then-act: both requests see 'unused' before either marks it used. The race tool in Burp Repeater is Send group in parallel: duplicate the request tab and fire the whole group at once. Community Intruder is throttled and cannot reliably land the burst inside the gap, so do not reach for it here.", "Send the redeem request to Repeater (Ctrl+R), duplicate the tab 20 times, select all the tabs and choose Send group in parallel. Count how many responses say redeemed: more than one success means the coupon was double-spent."],
  tools: 'BZ, P, C',
  est: 'about 10 minutes',
  how: 'Send POST /race/coupon/redeem to Repeater, duplicate the tab, and fire the group in parallel (Send group in parallel) so the one-use coupon is redeemed more than once.',
  link: '/race#race-coupon',
  start: 'Redeem the coupon once in the browser with Burp proxying, send POST /race/coupon/redeem to Repeater (Ctrl+R), duplicate the tab 20 times, then Send group in parallel.',
};

// Challenge-local presentation: a clay card hero for this shop screen.
function shop(crumb, body) {
  return appShell('PenTrix Shop', body, { crumb, mark: '◈', nav: ['Home', 'Catalog', 'Rewards', 'Cart'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <form method="POST" action="/race/reset" style="display:inline"><button type="submit" class="clay-btn clay-btn-secondary clay-btn-sm">Reset lab state</button></form></p>`;
}

router.get('/coupon', (req, res) => {
  const c = shared.state(req).coupon;
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
    <p>One click redeems it once. A burst of parallel Repeater requests redeems it more than once:</p>
    ${payloadBlock('Parallel redeems in Burp', '1. Redeem once in the browser with Burp proxying.\n2. In Proxy history, send the POST /race/coupon/redeem request to Repeater (Ctrl+R).\n3. Right-click the Repeater tab, choose Duplicate tab, and repeat until you have 20 tabs of the same request.\n4. Select all 20 tabs, right-click, and choose Send group in parallel.\n5. Count the "Coupon redeemed" responses: more than one means double-spend.')}
    ${backLinks()}
  `)));
});

router.post('/coupon/redeem', async (req, res) => {
  // VULN: the "already used?" check and the "mark used" write are separated by
  // an await, so parallel requests all see used=false before any write lands.
  if (shared.state(req).coupon.used) {
    return res.send(page('Coupon', shop('Rewards', `
      <section class="clay-card">
        <h2>Already redeemed</h2>
        <p>This coupon was already used. Reset the lab to try again.</p>
        ${backLinks()}
      </section>
    `)));
  }
  await shared.sleep(shared.WINDOW());
  const c = shared.state(req).coupon;
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
