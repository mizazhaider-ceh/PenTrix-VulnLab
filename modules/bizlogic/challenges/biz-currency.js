'use strict';
// Currency Confusion: /bizlogic/currency. The $50 total is denominated in USD,
// but the server accepts any currency label for that number and converts at
// face value, so "50 JPY" settles a $50 order for about $0.34.
const express = require('express');
const { esc, page, flagBox, fixPanel, appShell } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

router.get('/currency', (req, res) => {
  const s = shared.shop(req);
  res.send(page('Pay in your currency', `
    ${appShell('PenTrix Store', `
      <h2>PenTrix Hoodie: $50 USD</h2>
      <form method="POST" action="/bizlogic/currency/pay">
        <input type="hidden" name="amount" value="50" />
        <div class="clay-field">
          <label for="currency">Pay in currency</label>
          <select class="clay-input" id="currency" name="currency">
            <option value="USD">USD</option>
            <option value="EUR">EUR</option>
          </select>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Pay $50</button>
      </form>
      <p class="note">The amount is denominated in USD, but the currency label is
      yours to choose. The gateway accepts any code. Try it with curl:</p>
      <pre><code>curl -s -X POST http://localhost:3000/bizlogic/currency/pay -d 'amount=50&amp;currency=JPY'</code></pre>
    `, { nav: ['Catalog', 'Cart', 'Checkout', 'Account'], crumb: 'Checkout' })}
    ${shared.backLink(s)}
  `));
});

router.post('/currency/pay', (req, res) => {
  const s = shared.shop(req);
  const amount = parseFloat(req.body.amount);
  const currency = String(req.body.currency || 'USD').toUpperCase().slice(0, 8);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).send(page('Pay', `<p>Amount must be a positive number.</p>${shared.backLink(s)}`));
  }
  // VULN: the amount was priced in USD, but the server accepts any currency
  // label for it and converts at face value, so "50 JPY" settles a $50 order.
  const rate = shared.RATES[currency] || 1;
  const chargedUSD = amount / rate;
  s.balance -= chargedUSD;
  s.orders.push({
    id: s.orderSeq++, items: 'PenTrix Hoodie x1', total: 50,
    currency: 'USD', paid: true, note: `settled as ${amount} ${currency}`,
  });

  let flagHtml = '';
  if (currency === 'JPY' && !captured(req, 'bizlogic', 'biz-currency')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-currency'));
    flagHtml += fixPanel('bizlogic', 'biz-currency');
  }
  res.send(page('Payment done', `
    ${appShell('PenTrix Store', `
      <h2>Paid ${esc(String(amount))} ${esc(currency)}</h2>
      <p>That settled a <b>$50.00</b> order for about <b>${shared.money(chargedUSD)}</b>.
      New balance: <b>${shared.money(s.balance)}</b></p>
      ${currency === 'JPY' ? '<p><b>Currency confusion:</b> a USD-denominated amount was accepted under a JPY label.</p>' : ''}
      ${flagHtml}
    `, { nav: ['Catalog', 'Cart', 'Checkout', 'Account'], crumb: 'Checkout' })}
    ${shared.backLink(s)}
  `));
});

const vuln = {
  id: 'biz-currency',
  name: 'Currency Confusion',
  difficulty: 'Easy',
  hint: 'The $50 total is denominated in USD, but the server accepts any currency label for that number. 50 JPY is not 50 USD.',
  hints: ["The currency parameter changes the unit. What is 50 USD in JPY?", "The server converts wrong: 50 JPY is ~$0.34 but it's charged as $50 worth. Or vice versa.", "Checkout in a currency where the number 50 is worth almost nothing in dollars. The server treats the raw number the same under any currency label."],
  tools: "BZ, B",
  how: 'Pay at /bizlogic/currency with currency=JPY so a $50 order settles for about $0.34.',
  link: '/bizlogic#biz-currency',
  start: 'curl -s -b jar -c jar http://localhost:3000/bizlogic/currency',
};

module.exports = { vuln, router };
