'use strict';
// Oversell the Stock: the shop holds only 5 gadgets. The stock check and the
// decrement are separated by an async gap, so parallel orders each see the
// pre-sale stock level and the shop sells more than it owns.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, brief, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
// Module-level race plumbing lives in ../shared.js (see final report): the
// shared state getter, the check-to-use sleep window, and the back link.
const { sleep, WINDOW, raceState, backLink } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'race-stock',
  name: 'Oversell the Stock',
  difficulty: 'Easy',
  path: 'stock',
  hint: 'Only 5 items in stock. The stock check and the decrement are separated by a gap. Two orders of 5 at the same time...',
  hints: ["Only 5 items in stock. But buys aren't serialized. Confirm in Burp Repeater that one order of 5 works and shows the items sold count.", "Repeater sends one request at a time, and a race needs many at once. Duplicate the buy Repeater tab, select both tabs, and use Send group in parallel. Community Intruder is throttled and cannot reliably hit the gap, so the Repeater group is the race tool here.", "The await between the stock check and the decrement is the window. Fire both orders of 5 in parallel so every one passes the check against the same stock level, pushing total sold above 5."],
  tools: 'BZ, C',
  est: 'about 10 minutes',
  how: 'Stock is checked when an order arrives but decremented afterwards, so parallel orders can all be approved against the same last items.',
  link: '/race#race-stock',
  start: 'Capture one POST /race/stock/buy in Burp, send it to Repeater (Ctrl+R), duplicate the tab, then Send group in parallel.',
};

// GET /race/stock -> the gadget shop page.
router.get('/stock', (req, res) => {
  const R = raceState(req);
  res.send(page('Limited stock shop', `
    ${brief('The scenario', `
      <p>This shop sells a gadget with <b>only 5 units in stock</b>. When you
      order, the shop checks that enough stock exists, then waits briefly
      (simulating an async inventory write) before decrementing the count.</p>
      <p>Your goal: get the shop to sell <b>more than 5 units</b> total. One
      order at a time never oversells. Two orders of 5 fired at the exact same
      instant do.</p>`)}
    <section class="clay-card">
      <h2>Gadget (only 5 in stock)</h2>
      <p>Items left: <b>${R.stock.stock}</b> · Items sold: <b>${R.stock.sold}</b></p>
      <form method="POST" action="/race/stock/buy">
        <div class="clay-field">
          <label for="qty">Quantity</label>
          <input class="clay-input" type="text" id="qty" name="qty" placeholder="quantity" value="5" size="6" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Buy now</button>
      </form>
    </section>
    <section class="clay-card">
      <h3>Break it</h3>
      <p>Two parallel orders of 5 when only 5 exist. The stock check races the
      decrement and the shop oversells:</p>
      ${payloadBlock('Burp Repeater: Send group in parallel', 'Send the buy POST to Repeater (Ctrl+R), duplicate the tab so you have two identical orders of 5, select both tabs, right-click and choose Send group in parallel. Watch total sold climb past 5.')}
    </section>
    ${hintLadder(vuln)}
    ${backLink}
  `));
});

// POST /race/stock/buy -> place an order for qty gadgets.
router.post('/stock/buy', async (req, res) => {
  const R = raceState(req);
  const qty = parseInt(req.body.qty, 10);
  if (!Number.isInteger(qty) || qty <= 0) {
    return res.status(400).send(page('Buy', `
      <section class="clay-card">
        <h2>Bad request</h2>
        <p>Quantity must be a positive whole number.</p>
      </section>
      ${backLink}
    `));
  }
  // VULN: "enough stock?" is checked, then an await, then stock is decremented;
  // parallel orders each see the pre-sale stock level.
  if (R.stock.stock < qty) {
    return res.send(page('Buy', `
      <section class="clay-card">
        <h2>Out of stock</h2>
        <p>Only ${R.stock.stock} left; you asked for ${esc(String(qty))}.</p>
      </section>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.stock.stock -= qty;
  R.stock.sold += qty;

  let flagHtml = '';
  if (R.stock.sold > 5 && !captured(req, 'race', 'race-stock')) {
    flagHtml = flagBox(award(req, 'race', 'race-stock'));
    flagHtml += fixPanel('race', 'race-stock');
  }
  res.send(page('Order placed', `
    <section class="clay-card">
      <h2>Order placed: ${esc(String(qty))} item(s)</h2>
      <p>Stock left: <b>${R.stock.stock}</b> · Total sold: <b>${R.stock.sold}</b> (started with 5)</p>
      ${R.stock.sold > 5 ? '<p><b>Oversold:</b> more items were sold than ever existed in stock.</p>' : ''}
      ${flagHtml}
    </section>
    ${backLink}
  `));
});

module.exports = {
  vuln,
  router,
};
