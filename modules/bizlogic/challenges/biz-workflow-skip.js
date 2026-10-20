'use strict';
// Checkout Step Skipped: /bizlogic/workflow. The multi-step checkout is cart,
// then payment, then confirm. The confirm endpoint never verifies that the
// payment step actually ran, so POSTing to it directly creates an order that
// was never paid for.
const express = require('express');
const { esc, page, flagBox, fixPanel, appShell } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

router.get('/workflow', (req, res) => {
  const s = shared.shop(req);
  const cartRows = s.cart.map((it) => {
    const p = shared.productById(it.productId);
    return `<li>${esc(p ? p.name : it.productId)} x${it.qty}</li>`;
  }).join('') || '<li><i>cart is empty</i></li>';
  res.send(page('Multi-step checkout', `
    ${appShell('PenTrix Store', `
      <h2>Checkout: 3 steps</h2>
      <ol>
        <li><b>Cart</b>: add the hoodie below.</li>
        <li><b>Payment</b>: pay for what is in the cart.</li>
        <li><b>Confirm</b>: finalize the order.</li>
      </ol>
      <p>Cart (${shared.money(shared.cartTotal(s))}):</p><ul>${cartRows}</ul>
      <p>Payment done: <b>${s.paid}</b></p>
      <div class="steps-row">
        <form method="POST" action="/bizlogic/workflow/cart">
          <input type="hidden" name="product_id" value="hoodie" />
          <button class="clay-btn clay-btn-primary clay-btn-sm" type="submit">Step 1: add hoodie to cart</button>
        </form>
        <form method="POST" action="/bizlogic/workflow/pay">
          <button class="clay-btn clay-btn-primary clay-btn-sm" type="submit">Step 2: pay ${shared.money(shared.cartTotal(s))}</button>
        </form>
        <form method="POST" action="/bizlogic/workflow/confirm">
          <button class="clay-btn clay-btn-secondary clay-btn-sm" type="submit">Step 3: confirm order</button>
        </form>
      </div>
      <p class="note">Each step is just an endpoint. What happens if you call step 3 first?</p>
    `, { nav: ['Catalog', 'Cart', 'Checkout', 'Account'], crumb: 'Checkout' })}
    ${shared.backLink(s)}
  `));
});

router.post('/workflow/cart', (req, res) => {
  const s = shared.shop(req);
  const p = shared.productById(String(req.body.product_id || '')) || shared.PRODUCTS[0];
  s.cart.push({ productId: p.id, qty: 1 });
  res.redirect('/bizlogic/workflow');
});

router.post('/workflow/pay', (req, res) => {
  const s = shared.shop(req);
  const total = shared.cartTotal(s);
  if (total <= 0) {
    return res.send(page('Payment', `<p>Cart is empty, nothing to pay for.</p>${shared.backLink(s)}`));
  }
  if (s.balance < total) {
    return res.send(page('Payment', `<p>Insufficient balance for ${shared.money(total)}.</p>${shared.backLink(s)}`));
  }
  s.balance -= total;
  s.paid = true;
  res.send(page('Payment', `
    <h2>Paid ${shared.money(total)}</h2>
    <p>Now confirm the order to finish.</p>
    ${shared.backLink(s)}
  `));
});

router.post('/workflow/confirm', (req, res) => {
  const s = shared.shop(req);
  if (!s.cart.length) {
    return res.send(page('Confirm', `<p>Cart is empty. Add something first.</p>${shared.backLink(s)}`));
  }
  // VULN: confirm never checks that the payment step ran, so calling it
  // directly creates a paid-looking order for free.
  const total = shared.cartTotal(s);
  const items = s.cart.map((it) => {
    const p = shared.productById(it.productId);
    return `${p ? p.name : it.productId} x${it.qty}`;
  }).join(', ');
  const wasPaid = s.paid;
  s.orders.push({ id: s.orderSeq++, items, total, currency: 'USD', paid: wasPaid, note: '' });
  s.cart = [];
  s.paid = false;

  let flagHtml = '';
  if (!wasPaid && !captured(req, 'bizlogic', 'biz-workflow-skip')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-workflow-skip'));
    flagHtml += fixPanel('bizlogic', 'biz-workflow-skip');
  }
  res.send(page('Order confirmed', `
    ${appShell('PenTrix Store', `
      <h2>Order confirmed: ${esc(items)} (${shared.money(total)})</h2>
      <p>Payment step completed: <b>${wasPaid}</b></p>
      ${!wasPaid ? '<p><b>Free order.</b> The confirm endpoint never verified that payment happened.</p>' : ''}
      ${flagHtml}
    `, { nav: ['Catalog', 'Cart', 'Checkout', 'Account'], crumb: 'Checkout' })}
    ${shared.backLink(s)}
  `));
});

const vuln = {
  id: 'biz-workflow-skip',
  name: 'Checkout Step Skipped',
  difficulty: 'Medium',
  hint: 'Checkout is cart, then payment, then confirm. The confirm endpoint never verifies that payment actually happened.',
  hints: ["Checkout has steps: cart, pay, confirm. Proxy each step and send the confirm POST to Repeater.", "Does confirm check that the pay step ran? Replay the confirm request in Repeater and find out.", "Fill the cart first, then replay the confirm request on its own, skipping only the pay step. Confirm never verifies that payment happened."],
  tools: "BZ, B",
  how: 'Add the hoodie to the cart, then POST /bizlogic/workflow/confirm directly, skipping the pay step entirely.',
  link: '/bizlogic#biz-workflow-skip',
  start: 'Start Burp Proxy and open /bizlogic/workflow in your proxied browser. Add the hoodie to the cart, then send the confirm POST to Repeater and replay it before paying.',
};

module.exports = { vuln, router };
