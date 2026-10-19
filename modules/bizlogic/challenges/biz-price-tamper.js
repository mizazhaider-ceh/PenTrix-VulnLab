'use strict';
// Client-Side Price Tampering: /bizlogic/price-tamper. The price travels to
// the server in a hidden form field and the server honors it without ever
// re-checking it against the product catalog.
const express = require('express');
const { esc, flagBox, fixPanel, page } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();
// Router-scoped form parsing (mirrors the old module router).
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'biz-price-tamper',
  name: 'Client-Side Price Tampering',
  difficulty: 'Easy',
  hint: 'View the page source: the price travels to the server in a hidden form field. The server never re-checks it against the catalog.',
  hints: ["The price is in a hidden form field. Who controls hidden fields?", "You do. The server honors the submitted price as-is.", "The server charges whatever price the browser reports. Report a much smaller number than the catalog price and checkout."],
  tools: "BZ, B",
  how: 'Change the hidden price field at /bizlogic/price-tamper and buy the $50 hoodie for less.',
  link: '/bizlogic#biz-price-tamper',
  start: 'curl -s -X POST http://localhost:3000/bizlogic/price-tamper/buy -d \'product_id=hoodie&price=1\'',
};

router.get('/price-tamper', (req, res) => {
  const s = shared.shop(req);
  res.send(page('Buy it now', `
    <h2>PenTrix Hoodie: $50</h2>
    <form method="POST" action="/bizlogic/price-tamper/buy">
      <input type="hidden" name="product_id" value="hoodie" />
      <input type="hidden" name="price" value="50" />
      <button class="clay-btn clay-btn-primary" type="submit">Buy now for $50</button>
    </form>
    <p class="note">View the page source: the price is a hidden form field. Try it with curl:</p>
    <pre><code>curl -s -X POST http://localhost:3000/bizlogic/price-tamper/buy -d 'product_id=hoodie&price=1'</code></pre>
    ${shared.backLink(s)}
  `));
});

router.post('/price-tamper/buy', (req, res) => {
  const s = shared.shop(req);
  const p = shared.productById(String(req.body.product_id || '')) || shared.PRODUCTS[0];
  const price = parseFloat(req.body.price);
  // VULN: the price submitted by the browser is honored as-is; the server never
  // re-checks it against the product catalog.
  const total = Number.isFinite(price) ? price : p.price;
  if (total < 0) {
    return res.status(400).send(page('Buy', `<p>Price cannot be negative.</p>${shared.backLink(s)}`));
  }
  s.balance -= total;
  s.orders.push({ id: s.orderSeq++, items: `${p.name} x1`, total, currency: 'USD', paid: true, note: '' });

  let flagHtml = '';
  if (total < p.price && !captured(req, 'bizlogic', 'biz-price-tamper')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-price-tamper'));
    flagHtml += fixPanel('bizlogic', 'biz-price-tamper');
  }
  res.send(page('Order placed', `
    <h2>Order placed: ${esc(p.name)}</h2>
    <p>Catalog price: ${shared.money(p.price)} · You paid: <b>${shared.money(total)}</b></p>
    ${total < p.price ? '<p><b>Underpaid.</b> The server charged whatever price your browser sent.</p>' : ''}
    ${flagHtml}
    ${shared.backLink(s)}
  `));
});

module.exports = { vuln, router };
