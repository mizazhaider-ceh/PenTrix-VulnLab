'use strict';
// Tampered Refund Amount: /bizlogic/refund. The refund amount comes from a
// hidden form field and is never clamped to what was actually paid, so any
// amount, even more than the order total, is refunded to the store balance.
// NOTE: the finisher's shared.js (modules/bizlogic/shared.js) must provide:
//   shop(req)     session shop state (balance, cart, orders)
//   money(n)      USD formatting helper
//   backLink(s)   "Back to module / Reset shop" footer for shop pages
//   productById   catalog lookup used by the buy-first route
// NOTE: this file's POST routes need express.urlencoded({ extended: false })
// applied at the module level (index.js), exactly as router.js applies it to
// the module router today. Do not rely on app-level parsing.
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');
const { shop, money, backLink, productById } = shared;

const router = express.Router();

const vuln = {
  id: 'biz-refund',
  name: 'Tampered Refund Amount',
  difficulty: 'Medium',
  est: '10-20 minutes',
  hint: 'The refund form carries the amount in a hidden field. The server refunds whatever number you submit, even more than you paid.',
  hints: ["Open the refund page in your proxied browser and send the refund POST to Repeater. What parameters does the request carry?", "The amount comes from a hidden form field. Edit it in Repeater and re-send: is it clamped?", "Try an amount above the order total in Repeater and read the receipt: nothing clamps the refund to what you actually paid."],
  tools: 'BZ, B',
  how: 'The refund form suggests an amount, and the server treats that suggestion as your decision. What is a refund allowed to be, in this shop?',
  link: '/bizlogic#biz-refund',
  start: 'Start Burp Proxy and open /bizlogic/refund in your proxied browser. Buy the hoodie, then send the refund POST to Repeater and replay it with a larger amount.',
};

const cardTop = (label) => `
  <div class="card-top"><span class="orb" aria-hidden="true">💸</span><b>PenTrix Shop</b><span class="dim">${label}</span></div>`;

router.get('/refund', (req, res) => {
  const s = shop(req);
  const orderRows = s.orders.map((o) => `
    <tr>
      <td>#${o.id}</td><td>${esc(o.items)}</td><td>${money(o.total)}</td>
      <td>
        <form method="POST" action="/bizlogic/refund" style="display:inline">
          <input type="hidden" name="order_id" value="${o.id}" />
          <input type="hidden" name="amount" value="${o.total}" />
          <button class="clay-btn clay-btn-sm" type="submit">Refund ${money(o.total)}</button>
        </form>
      </td>
    </tr>`).join('') || '<tr><td colspan="4"><i>no orders yet: buy something first</i></td></tr>';
  res.send(page('Refunds', `
    <div class="card clay-card">
      ${cardTop('refunds')}
      <h2>Request a refund</h2>
      <form method="POST" action="/bizlogic/refund/buy">
        <input type="hidden" name="product_id" value="hoodie" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Buy the $50 hoodie first</button></p>
      </form>
      <h3>Your orders</h3>
      <div class="tbl-scroll"><table class="tbl"><tr><th>Order</th><th>Items</th><th>Paid</th><th></th></tr>${orderRows}</table></div>
      <p class="note">View the page source: the refund amount is a hidden field. Try it in Burp Repeater: click a Refund button with Proxy intercepting, send the request to Repeater with Ctrl+R, change <code>amount</code>, and send.</p>
      <div class="payload"><div class="payload-head"><span>Burp Repeater</span></div><pre class="payload-body">POST /bizlogic/refund HTTP/1.1
Host: <your-lab-address>
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

order_id=1&amp;amount=5000</pre></div>
    </div>
    ${backLink(s)}
  `));
});

router.post('/refund/buy', (req, res) => {
  const s = shop(req);
  const p = productById(String(req.body.product_id || '')) || { id: 'hoodie', name: 'PenTrix Hoodie', price: 50 };
  if (s.balance < p.price) {
    return res.send(page('Buy', `
      <div class="card clay-card">
        ${cardTop('refunds')}
        <h2>Insufficient balance</h2>
        <p>Insufficient balance for ${money(p.price)}.</p>
      </div>
      ${backLink(s)}
    `));
  }
  s.balance -= p.price;
  s.orders.push({ id: s.orderSeq++, items: `${p.name} x1`, total: p.price, currency: 'USD', paid: true, note: '' });
  res.redirect('/bizlogic/refund');
});

router.post('/refund', (req, res) => {
  const s = shop(req);
  const order = s.orders.find((o) => o.id === parseInt(req.body.order_id, 10));
  if (!order) {
    return res.status(404).send(page('Refund', `
      <div class="card clay-card">
        ${cardTop('refunds')}
        <h2>Order not found</h2>
        <p>Order not found.</p>
      </div>
      ${backLink(s)}
    `));
  }
  const amount = parseFloat(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).send(page('Refund', `
      <div class="card clay-card">
        ${cardTop('refunds')}
        <h2>Bad amount</h2>
        <p>Refund amount must be a positive number.</p>
      </div>
      ${backLink(s)}
    `));
  }
  // VULN: the refund amount comes from a hidden form field and is never clamped
  // to what was actually paid, so any amount can be refunded.
  s.balance += amount;

  let flagHtml = '';
  if (amount > order.total && !captured(req, 'bizlogic', 'biz-refund')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-refund'));
    flagHtml += fixPanel('bizlogic', 'biz-refund');
  }
  res.send(page('Refund processed', `
    <div class="card clay-card">
      ${cardTop('refunds')}
      <h2>Refunded ${money(amount)} on order #${order.id}</h2>
      <p>That order paid ${money(order.total)}. New balance: <b>${money(s.balance)}</b></p>
      ${amount > order.total ? '<p><b>Over-refunded.</b> The server refunded more than the order was ever worth.</p>' : ''}
      ${flagHtml}
    </div>
    ${backLink(s)}
  `));
});

module.exports = { vuln, router };
