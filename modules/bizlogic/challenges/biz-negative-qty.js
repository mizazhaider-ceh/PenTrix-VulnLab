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
  hint: 'The quantity field is never validated. What happens to the total if you "buy" fewer than zero hoodies?',
  hints: ["Catch the checkout POST in Burp Proxy's intercept tab before it reaches the server.", "The request body carries qty=1. Think about what the server computes with a value below zero.", "Forward the modified request from the Proxy. If the shop ends up owing you money, it pays you instead."],
  tools: "BZ, B",
  how: 'At /bizlogic/negative-qty, intercept the checkout POST in Burp Proxy, change qty to a negative number, forward it, and the shop credits your balance instead of charging it.',
  link: '/bizlogic#biz-negative-qty',
  start: 'Browse to the Negative Quantity challenge with Burp Proxy intercepting. Submit the checkout form, catch the POST in the Proxy, edit qty to a negative value, and forward it.',
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
