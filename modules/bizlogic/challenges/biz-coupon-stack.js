'use strict';
// Coupon Stacking Past 100%: each "one per order" coupon's percentage is added
// to a single discount stack with no cap, so combined coupons can exceed 100%.
// NOTE: the finisher's shared.js (modules/bizlogic/shared.js) provides:
//   shop(req)        session shop state (balance, cart, orders)
//   money(n)         USD formatting helper
//   balLine(s)       store-balance line used by every shop page
//   backLink(s)      "Back to module / Reset shop" footer for shop pages
//   COUPONS          { SAVE50: 0.50, SAVE40: 0.40, SAVE30: 0.30 } coupon map
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');
const { shop, money, backLink, COUPONS } = shared;

const router = express.Router();
// Form parsing for this challenge's routes (mirrors router.js router-scoped use).
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'biz-coupon-stack',
  name: 'Coupon Stacking Past 100%',
  difficulty: 'Medium',
  hint: 'Each coupon claims "one per order", but the discount math just adds every valid code together. 50 + 40 + 30 = ?',
  hints: ["The coupon input says to separate multiple codes with commas or spaces, and the page lists three codes. What happens if you send more than one code? Try it in Burp Repeater.", "Each valid code's percentage is added to the same discount pile, with no cap. Percentages above 100% turn the total negative, and the shop owes you money.", "In Repeater, replay the POST /bizlogic/coupon-stack request and keep adding valid codes to the codes parameter until the discount crosses 100% and the receipt shows a negative total."],
  tools: 'BZ, B',
  how: 'Replay the checkout POST in Burp Repeater with multiple coupon codes in the codes field: the percentages add past 100%, the total drops to zero or below, and the flag is awarded.',
  link: '/bizlogic#biz-coupon-stack',
  start: 'Open the checkout page in the browser with Burp Proxy intercepting. Submit the coupon form once, send the POST /bizlogic/coupon-stack request to Repeater, then experiment with code combinations in the codes field until the discount stacks past 100%.',
};

router.get('/coupon-stack', (req, res) => {
  const s = shop(req);
  res.send(page('Checkout with coupons', `
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">🛒</span><b>PenTrix Shop</b><span class="dim">secure checkout</span></div>
      <h2>Cart: PenTrix Hoodie x1 = $50</h2>
      <p>Available coupons (each "<b>one per order</b>"): <code>SAVE50</code> (50%),
      <code>SAVE40</code> (40%), <code>SAVE30</code> (30%)</p>
      <form method="POST" action="/bizlogic/coupon-stack">
        <label class="field-label" for="codes">Coupon codes</label>
        <input class="clay-input" type="text" id="codes" name="codes" placeholder="SAVE50" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Apply coupons and pay</button></p>
      </form>
      <p class="note">Separate multiple codes with commas or spaces.</p>
    </div>
    ${backLink(s)}
  `));
});

router.post('/coupon-stack', (req, res) => {
  const s = shop(req);
  const subtotal = 50;
  const codes = String(req.body.codes || '').toUpperCase().split(/[^A-Z0-9]+/).filter(Boolean);
  const applied = [];
  let discount = 0;
  for (const c of codes) {
    // VULN: every valid code's percentage is added to a single stack with no
    // cap, so combined "one per order" coupons can exceed a 100% discount.
    if (COUPONS[c] && !applied.includes(c)) {
      applied.push(c);
      discount += COUPONS[c];
    }
  }
  const total = subtotal * (1 - discount);
  s.balance -= total;
  s.orders.push({ id: s.orderSeq++, items: 'PenTrix Hoodie x1', total, currency: 'USD', paid: true, note: `coupons: ${applied.join(', ') || 'none'}` });

  let flagHtml = '';
  if (total <= 0 && applied.length > 0 && !captured(req, 'bizlogic', 'biz-coupon-stack')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-coupon-stack'));
    flagHtml += fixPanel('bizlogic', 'biz-coupon-stack');
  }
  res.send(page('Order placed', `
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">🛒</span><b>PenTrix Shop</b><span class="dim">order receipt</span></div>
      <h2>Coupons applied: ${applied.length ? esc(applied.join(', ')) : 'none'}</h2>
      <p>Total discount: <b>${Math.round(discount * 100)}%</b> · You paid: <b>${money(total)}</b></p>
      ${total <= 0 ? '<p><b>Discount hit 100% or more.</b> The coupons stacked past free, and the shop owes you money.</p>' : ''}
      ${flagHtml}
    </div>
    ${backLink(s)}
  `));
});

module.exports = { vuln, router };
