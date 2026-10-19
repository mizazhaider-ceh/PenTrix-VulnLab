'use strict';
// Negative Quantity Credit: /bizlogic/negative-qty. The quantity field is
// never validated, so a negative qty makes the total negative and "charging"
// it credits the store balance instead.
const express = require('express');
const { flagBox, fixPanel, page } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();
// Router-scoped form parsing (mirrors the old module router).
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'biz-negative-qty',
  name: 'Negative Quantity Credit',
  difficulty: 'Easy',
  hint: 'The quantity field is never validated. What does "buying" -1 hoodies do to the total?',
  hints: ["The cart lets you set quantity. What if it's negative?", "Negative qty * price = negative total. The balance is credited.", "Set qty=-1 on an item and checkout. Balance increases."],
  tools: "B",
  how: 'Order a negative quantity at /bizlogic/negative-qty so the shop credits your balance instead of charging it.',
  link: '/bizlogic#biz-negative-qty',
  start: 'curl -s -X POST http://localhost:3000/bizlogic/negative-qty -d \'qty=-1\'',
};

router.get('/negative-qty', (req, res) => {
  const s = shared.shop(req);
  res.send(page('Quantity checkout', `
    <h2>Buy the PenTrix Hoodie ($50)</h2>
    <form method="POST" action="/bizlogic/negative-qty">
      <label>Quantity: <input type="text" name="qty" value="1" size="6" /></label>
      <button class="clay-btn clay-btn-primary" type="submit">Checkout</button>
    </form>
    <p class="note">Total is computed as <code>$50 x qty</code>. The quantity is
    never validated.</p>
    ${shared.backLink(s)}
  `));
});

router.post('/negative-qty', (req, res) => {
  const s = shared.shop(req);
  const qty = parseInt(req.body.qty, 10);
  if (!Number.isInteger(qty) || qty === 0) {
    return res.status(400).send(page('Checkout', `<p>Quantity must be a non-zero whole number.</p>${shared.backLink(s)}`));
  }
  // VULN: qty is never validated, so a negative quantity makes the total
  // negative and "charging" it credits the balance instead.
  const total = 50 * qty;
  s.balance -= total;

  let flagHtml = '';
  if (s.balance > shared.START_BALANCE && !captured(req, 'bizlogic', 'biz-negative-qty')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-negative-qty'));
    flagHtml += fixPanel('bizlogic', 'biz-negative-qty');
  }
  res.send(page('Checkout', `
    <h2>Order total: ${shared.money(total)}</h2>
    <p>Quantity ${qty} x $50. New balance: <b>${shared.money(s.balance)}</b></p>
    ${total < 0 ? '<p><b>The shop paid you.</b> A negative quantity turned the charge into a credit.</p>' : ''}
    ${flagHtml}
    ${shared.backLink(s)}
  `));
});

module.exports = { vuln, router };
