// PenTrix VulnLab module: Business Logic Flaws (bizlogic)
// An in-module shop where the application logic itself is wrong: negative
// quantities, client-supplied prices, stackable coupons, client-side OTP checks,
// skippable checkout steps, confused currencies, email changes without
// re-authentication, and tamperable refund amounts. Shop state lives in the
// session; catalog and OTP are module-level constants.
const crypto = require('crypto');
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const PRODUCTS = [
  { id: 'hoodie', name: 'PenTrix Hoodie', price: 50 },
  { id: 'tee', name: 'PenTrix T-Shirt', price: 25 },
  { id: 'stickers', name: 'Sticker Pack', price: 5 },
];
const productById = (id) => PRODUCTS.find((p) => p.id === id);

const COUPONS = { SAVE50: 0.50, SAVE40: 0.40, SAVE30: 0.30 }; // each "one per order"
const REAL_OTP = '739184';            // "emailed" to the buyer (shown on the page for the demo)
const RATES = { USD: 1, EUR: 1.08, GBP: 1.27, JPY: 149.0 };
const START_BALANCE = 100;

function freshShop() {
  return {
    balance: START_BALANCE,
    cart: [],        // { productId, qty }
    orders: [],      // { id, items, total, currency, paid, note }
    orderSeq: 1,
    paid: false,     // set by the payment step of the multi-step checkout
    email: 'victim@pentrix.lab',
    originalEmail: 'victim@pentrix.lab',
    password: 'oldpass123',
  };
}
function shop(req) {
  if (!req.session.biz) req.session.biz = freshShop();
  return req.session.biz;
}
// Password-reset tokens, keyed by session so testers do not collide.
const resetTokens = {}; // sessionID -> { token, email }

const cartTotal = (s) => s.cart.reduce((sum, it) => {
  const p = productById(it.productId);
  return sum + (p ? p.price * it.qty : 0);
}, 0);
const money = (n) => `$${Number(n).toFixed(2)}`;
const balLine = (s) => `<p class="note">Your store balance: <b>${money(s.balance)}</b></p>`;

const BRIEF_HTML = `
<p><b>What is a business logic flaw?</b> Nothing is "injected" and nothing
crashes. The application simply trusts the client, skips a step, or gets its own
rules wrong: a negative quantity, a price taken from a hidden form field,
coupons that stack past 100%, an OTP checked by JavaScript, a checkout step you
can skip, a confused currency, an email change with no password check, a refund
amount you choose yourself.</p>
<p><b>How to attack these labs:</b> read each page like an accountant, not a
hacker. Ask "what does the server assume, and can I make that assumption false?"
View the page source: hidden fields are part of the attack surface. Every lab
starts you with a <b>$100</b> store balance; use <b>Reset shop</b> to start over.</p>`;

// ---------------------------------------------------------------- index page
const VULNS = [
  {
    id: 'biz-negative-qty', name: 'Negative Quantity Credit', difficulty: 'Easy',
    path: 'negative-qty',
    hint: 'The quantity field is never validated. What does "buying" -1 hoodies do to the total?',
    how: 'Order a negative quantity at /bizlogic/negative-qty so the shop credits your balance instead of charging it.',
  },
  {
    id: 'biz-price-tamper', name: 'Client-Side Price Tampering', difficulty: 'Easy',
    path: 'price-tamper',
    hint: 'View the page source: the price travels to the server in a hidden form field. The server never re-checks it against the catalog.',
    how: 'Change the hidden price field at /bizlogic/price-tamper and buy the $50 hoodie for less.',
  },
  {
    id: 'biz-coupon-stack', name: 'Coupon Stacking Past 100%', difficulty: 'Medium',
    path: 'coupon-stack',
    hint: 'Each coupon claims "one per order", but the discount math just adds every valid code together. 50 + 40 + 30 = ?',
    how: 'Apply SAVE50, SAVE40 and SAVE30 together at /bizlogic/coupon-stack so the discount exceeds 100%.',
  },
  {
    id: 'biz-otp-client', name: 'OTP Verified by JavaScript', difficulty: 'Medium',
    path: 'otp',
    hint: 'The page JavaScript checks the OTP and sets a hidden otp_ok flag. The server trusts that flag. What if you set it yourself?',
    how: 'POST to /bizlogic/otp/verify with otp_ok=1 and a wrong OTP, skipping the client-side check entirely.',
  },
  {
    id: 'biz-workflow-skip', name: 'Checkout Step Skipped', difficulty: 'Medium',
    path: 'workflow',
    hint: 'Checkout is cart, then payment, then confirm. The confirm endpoint never verifies that payment actually happened.',
    how: 'Add an item to the cart, then POST /bizlogic/workflow/confirm directly without paying.',
  },
  {
    id: 'biz-currency', name: 'Currency Confusion', difficulty: 'Easy',
    path: 'currency',
    hint: 'The $50 total is denominated in USD, but the server accepts any currency label for that number. 50 JPY is not 50 USD.',
    how: 'Pay at /bizlogic/currency with currency=JPY so a $50 order settles for about $0.34.',
  },
  {
    id: 'biz-email-noreauth', name: 'Email Change Without Re-Authentication', difficulty: 'Medium',
    path: 'account',
    hint: 'You can change the account email with no password confirmation. Then "forgot password" sends the reset to the new address: yours.',
    how: 'Change the email at /bizlogic/account, trigger forgot-password, and use the reset link to take over the account.',
  },
  {
    id: 'biz-refund', name: 'Tampered Refund Amount', difficulty: 'Medium',
    path: 'refund',
    hint: 'The refund form carries the amount in a hidden field. The server refunds whatever number you submit, even more than you paid.',
    how: 'Buy the $50 hoodie, then request a refund at /bizlogic/refund with an amount larger than $50.',
  },
];

router.get('/', (req, res) => {
  const rows = VULNS.map((v) => {
    const done = captured(req, 'bizlogic', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/bizlogic/${v.path}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('Business Logic Flaws', `
    ${brief('Module briefing', BRIEF_HTML)}
    ${balLine(shop(req))}
    <h2>Challenges</h2>
    ${rows}
    <p><a class="btn ghost" href="/bizlogic/reset">Reset shop</a>
    <span class="dim">Restores your $100 balance, cart, orders and account.</span></p>
  `));
});

router.get('/reset', (req, res) => {
  req.session.biz = freshShop();
  delete resetTokens[req.sessionID];
  res.send(page('Shop reset', `
    <h2>Shop reset</h2>
    <p>Balance restored to ${money(START_BALANCE)}; cart, orders and account cleared.</p>
    <p><a href="/bizlogic">Back to the Business Logic module</a></p>
  `));
});

const backLink = (s) => `<p>${balLine(s)}<a href="/bizlogic">Back to module</a> · <a href="/bizlogic/reset">Reset shop</a></p>`;

// ------------------------------------------------------- v1: negative quantity
router.get('/negative-qty', (req, res) => {
  const s = shop(req);
  res.send(page('Quantity checkout', `
    <h2>Buy the PenTrix Hoodie ($50)</h2>
    <form method="POST" action="/bizlogic/negative-qty">
      <label>Quantity: <input type="text" name="qty" value="1" size="6" /></label>
      <button type="submit">Checkout</button>
    </form>
    <p class="note">Total is computed as <code>$50 x qty</code>. The quantity is
    never validated.</p>
    ${backLink(s)}
  `));
});

router.post('/negative-qty', (req, res) => {
  const s = shop(req);
  const qty = parseInt(req.body.qty, 10);
  if (!Number.isInteger(qty) || qty === 0) {
    return res.status(400).send(page('Checkout', `<p>Quantity must be a non-zero whole number.</p>${backLink(s)}`));
  }
  // VULN: qty is never validated, so a negative quantity makes the total
  // negative and "charging" it credits the balance instead.
  const total = 50 * qty;
  s.balance -= total;

  let flagHtml = '';
  if (s.balance > START_BALANCE && !captured(req, 'bizlogic', 'biz-negative-qty')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-negative-qty'));
  }
  res.send(page('Checkout', `
    <h2>Order total: ${money(total)}</h2>
    <p>Quantity ${qty} x $50. New balance: <b>${money(s.balance)}</b></p>
    ${total < 0 ? '<p><b>The shop paid you.</b> A negative quantity turned the charge into a credit.</p>' : ''}
    ${flagHtml}
    ${backLink(s)}
  `));
});

// ---------------------------------------------------------- v2: price tamper
router.get('/price-tamper', (req, res) => {
  const s = shop(req);
  res.send(page('Buy it now', `
    <h2>PenTrix Hoodie: $50</h2>
    <form method="POST" action="/bizlogic/price-tamper/buy">
      <input type="hidden" name="product_id" value="hoodie" />
      <input type="hidden" name="price" value="50" />
      <button type="submit">Buy now for $50</button>
    </form>
    <p class="note">View the page source: the price is a hidden form field. Try it with curl:</p>
    <pre><code>curl -s -X POST http://localhost:3000/bizlogic/price-tamper/buy -d 'product_id=hoodie&price=1'</code></pre>
    ${backLink(s)}
  `));
});

router.post('/price-tamper/buy', (req, res) => {
  const s = shop(req);
  const p = productById(String(req.body.product_id || '')) || PRODUCTS[0];
  const price = parseFloat(req.body.price);
  // VULN: the price submitted by the browser is honored as-is; the server never
  // re-checks it against the product catalog.
  const total = Number.isFinite(price) ? price : p.price;
  if (total < 0) {
    return res.status(400).send(page('Buy', `<p>Price cannot be negative.</p>${backLink(s)}`));
  }
  s.balance -= total;
  s.orders.push({ id: s.orderSeq++, items: `${p.name} x1`, total, currency: 'USD', paid: true, note: '' });

  let flagHtml = '';
  if (total < p.price && !captured(req, 'bizlogic', 'biz-price-tamper')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-price-tamper'));
  }
  res.send(page('Order placed', `
    <h2>Order placed: ${esc(p.name)}</h2>
    <p>Catalog price: ${money(p.price)} · You paid: <b>${money(total)}</b></p>
    ${total < p.price ? '<p><b>Underpaid.</b> The server charged whatever price your browser sent.</p>' : ''}
    ${flagHtml}
    ${backLink(s)}
  `));
});

// ---------------------------------------------------------- v3: coupon stack
router.get('/coupon-stack', (req, res) => {
  const s = shop(req);
  res.send(page('Checkout with coupons', `
    <h2>Cart: PenTrix Hoodie x1 = $50</h2>
    <p>Available coupons (each "<b>one per order</b>"): <code>SAVE50</code> (50%),
    <code>SAVE40</code> (40%), <code>SAVE30</code> (30%)</p>
    <form method="POST" action="/bizlogic/coupon-stack">
      <input type="text" name="codes" placeholder="SAVE50" size="30" />
      <button type="submit">Apply coupons and pay</button>
    </form>
    <p class="note">Separate multiple codes with commas or spaces.</p>
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
  }
  res.send(page('Order placed', `
    <h2>Coupons applied: ${applied.length ? esc(applied.join(', ')) : 'none'}</h2>
    <p>Total discount: <b>${Math.round(discount * 100)}%</b> · You paid: <b>${money(total)}</b></p>
    ${total <= 0 ? '<p><b>Discount hit 100% or more.</b> The coupons stacked past free, and the shop owes you money.</p>' : ''}
    ${flagHtml}
    ${backLink(s)}
  `));
});

// --------------------------------------------------------------- v4: OTP
router.get('/otp', (req, res) => {
  const s = shop(req);
  res.send(page('OTP verification', `
    <h2>Confirm your $50 order</h2>
    <p>For this demo, the OTP "emailed" to you is: <b>${REAL_OTP}</b></p>
    <form method="POST" action="/bizlogic/otp/verify" onsubmit="return checkOtp(event)">
      <input type="text" id="otp" name="otp" placeholder="enter OTP" />
      <input type="hidden" id="otp_ok" name="otp_ok" value="0" />
      <button type="submit">Verify and pay</button>
    </form>
    <script>
      function checkOtp(e) {
        if (document.getElementById('otp').value === '${REAL_OTP}') {
          document.getElementById('otp_ok').value = '1';
          return true;
        }
        alert('Wrong OTP');
        e.preventDefault();
        return false;
      }
    </script>
    <p class="note">The JavaScript above is the only thing checking the code.
    What does the server check? Try it with curl:</p>
    <pre><code>curl -s -X POST http://localhost:3000/bizlogic/otp/verify -d 'otp=000000&otp_ok=1'</code></pre>
    ${backLink(s)}
  `));
});

router.post('/otp/verify', (req, res) => {
  const s = shop(req);
  const otp = String(req.body.otp || '');
  // VULN: the server trusts the client-side otp_ok flag instead of verifying
  // the OTP itself, so skipping the JavaScript check still "verifies".
  if (req.body.otp_ok === '1') {
    s.balance -= 50;
    s.orders.push({ id: s.orderSeq++, items: 'PenTrix Hoodie x1 (OTP order)', total: 50, currency: 'USD', paid: true, note: '' });

    let flagHtml = '';
    if (otp !== REAL_OTP && !captured(req, 'bizlogic', 'biz-otp-client')) {
      flagHtml = flagBox(award(req, 'bizlogic', 'biz-otp-client'));
    }
    return res.send(page('Order confirmed', `
      <h2>OTP accepted, order confirmed</h2>
      <p>Submitted OTP: <code>${esc(otp)}</code> · New balance: <b>${money(s.balance)}</b></p>
      ${otp !== REAL_OTP ? '<p><b>Verified without the real code.</b> The server never checked the OTP; it trusted your browser.</p>' : ''}
      ${flagHtml}
      ${backLink(s)}
    `));
  }
  res.send(page('Verification failed', `
    <h2>OTP verification failed</h2>
    <p>The check did not pass. (The server only looks at the <code>otp_ok</code> field your browser sends.)</p>
    ${backLink(s)}
  `));
});

// -------------------------------------------------------- v5: workflow skip
router.get('/workflow', (req, res) => {
  const s = shop(req);
  const cartRows = s.cart.map((it) => {
    const p = productById(it.productId);
    return `<li>${esc(p ? p.name : it.productId)} x${it.qty}</li>`;
  }).join('') || '<li><i>cart is empty</i></li>';
  res.send(page('Multi-step checkout', `
    <h2>Checkout: 3 steps</h2>
    <ol>
      <li><b>Cart</b>: add the hoodie below.</li>
      <li><b>Payment</b>: pay for what is in the cart.</li>
      <li><b>Confirm</b>: finalize the order.</li>
    </ol>
    <p>Cart (${money(cartTotal(s))}):</p><ul>${cartRows}</ul>
    <p>Payment done: <b>${s.paid}</b></p>
    <form method="POST" action="/bizlogic/workflow/cart" style="display:inline">
      <input type="hidden" name="product_id" value="hoodie" />
      <button type="submit">Step 1: add hoodie to cart</button>
    </form>
    <form method="POST" action="/bizlogic/workflow/pay" style="display:inline">
      <button type="submit">Step 2: pay ${money(cartTotal(s))}</button>
    </form>
    <form method="POST" action="/bizlogic/workflow/confirm" style="display:inline">
      <button type="submit">Step 3: confirm order</button>
    </form>
    <p class="note">Each step is just an endpoint. What happens if you call step 3 first?</p>
    ${backLink(s)}
  `));
});

router.post('/workflow/cart', (req, res) => {
  const s = shop(req);
  const p = productById(String(req.body.product_id || '')) || PRODUCTS[0];
  s.cart.push({ productId: p.id, qty: 1 });
  res.redirect('/bizlogic/workflow');
});

router.post('/workflow/pay', (req, res) => {
  const s = shop(req);
  const total = cartTotal(s);
  if (total <= 0) {
    return res.send(page('Payment', `<p>Cart is empty, nothing to pay for.</p>${backLink(s)}`));
  }
  if (s.balance < total) {
    return res.send(page('Payment', `<p>Insufficient balance for ${money(total)}.</p>${backLink(s)}`));
  }
  s.balance -= total;
  s.paid = true;
  res.send(page('Payment', `
    <h2>Paid ${money(total)}</h2>
    <p>Now confirm the order to finish.</p>
    ${backLink(s)}
  `));
});

router.post('/workflow/confirm', (req, res) => {
  const s = shop(req);
  if (!s.cart.length) {
    return res.send(page('Confirm', `<p>Cart is empty. Add something first.</p>${backLink(s)}`));
  }
  // VULN: confirm never checks that the payment step ran, so calling it
  // directly creates a paid-looking order for free.
  const total = cartTotal(s);
  const items = s.cart.map((it) => {
    const p = productById(it.productId);
    return `${p ? p.name : it.productId} x${it.qty}`;
  }).join(', ');
  const wasPaid = s.paid;
  s.orders.push({ id: s.orderSeq++, items, total, currency: 'USD', paid: wasPaid, note: '' });
  s.cart = [];
  s.paid = false;

  let flagHtml = '';
  if (!wasPaid && !captured(req, 'bizlogic', 'biz-workflow-skip')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-workflow-skip'));
  }
  res.send(page('Order confirmed', `
    <h2>Order confirmed: ${esc(items)} (${money(total)})</h2>
    <p>Payment step completed: <b>${wasPaid}</b></p>
    ${!wasPaid ? '<p><b>Free order.</b> The confirm endpoint never verified that payment happened.</p>' : ''}
    ${flagHtml}
    ${backLink(s)}
  `));
});

// ------------------------------------------------------------ v6: currency
router.get('/currency', (req, res) => {
  const s = shop(req);
  res.send(page('Pay in your currency', `
    <h2>PenTrix Hoodie: $50 USD</h2>
    <form method="POST" action="/bizlogic/currency/pay">
      <input type="hidden" name="amount" value="50" />
      <label>Pay
        <select name="currency">
          <option value="USD">USD</option>
          <option value="EUR">EUR</option>
        </select>
      </label>
      <button type="submit">Pay $50</button>
    </form>
    <p class="note">The amount is denominated in USD, but the currency label is
    yours to choose. The gateway accepts any code. Try it with curl:</p>
    <pre><code>curl -s -X POST http://localhost:3000/bizlogic/currency/pay -d 'amount=50&currency=JPY'</code></pre>
    ${backLink(s)}
  `));
});

router.post('/currency/pay', (req, res) => {
  const s = shop(req);
  const amount = parseFloat(req.body.amount);
  const currency = String(req.body.currency || 'USD').toUpperCase().slice(0, 8);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).send(page('Pay', `<p>Amount must be a positive number.</p>${backLink(s)}`));
  }
  // VULN: the amount was priced in USD, but the server accepts any currency
  // label for it and converts at face value, so "50 JPY" settles a $50 order.
  const rate = RATES[currency] || 1;
  const chargedUSD = amount / rate;
  s.balance -= chargedUSD;
  s.orders.push({
    id: s.orderSeq++, items: 'PenTrix Hoodie x1', total: 50,
    currency: 'USD', paid: true, note: `settled as ${amount} ${currency}`,
  });

  let flagHtml = '';
  if (currency === 'JPY' && !captured(req, 'bizlogic', 'biz-currency')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-currency'));
  }
  res.send(page('Payment done', `
    <h2>Paid ${esc(String(amount))} ${esc(currency)}</h2>
    <p>That settled a <b>$50.00</b> order for about <b>${money(chargedUSD)}</b>.
    New balance: <b>${money(s.balance)}</b></p>
    ${currency === 'JPY' ? '<p><b>Currency confusion:</b> a USD-denominated amount was accepted under a JPY label.</p>' : ''}
    ${flagHtml}
    ${backLink(s)}
  `));
});

// -------------------------------------------- v7: email change, no re-auth
router.get('/account', (req, res) => {
  const s = shop(req);
  res.send(page('Account settings', `
    <h2>Account</h2>
    <p>Email: <b>${esc(s.email)}</b> · Password: <b>${esc('*'.repeat(Math.min(s.password.length, 12)))}</b></p>
    <h3>Change email</h3>
    <form method="POST" action="/bizlogic/account/email">
      <input type="text" name="new_email" placeholder="new email" size="30" />
      <button type="submit">Change email</button>
    </form>
    <p class="note">No password asked. Interesting.</p>
    <h3>Forgot password</h3>
    <form method="POST" action="/bizlogic/account/forgot">
      <input type="text" name="email" placeholder="account email" size="30" />
      <button type="submit">Send reset link</button>
    </form>
    <p class="note">Demo mode: the reset link is displayed on screen instead of emailed.</p>
    ${backLink(s)}
  `));
});

router.post('/account/email', (req, res) => {
  const s = shop(req);
  const newEmail = String(req.body.new_email || '').trim().slice(0, 120);
  if (!newEmail.includes('@')) {
    return res.status(400).send(page('Account', `<p>That is not a valid email address.</p>${backLink(s)}`));
  }
  // VULN: changing the account email requires no password confirmation or
  // other re-authentication, so anyone at the keyboard can reroute the account.
  s.email = newEmail;
  res.send(page('Email changed', `
    <h2>Email changed</h2>
    <p>Account email is now <b>${esc(s.email)}</b>. No password was required.</p>
    <p>Next: use <b>forgot password</b> with this address to receive the reset link.</p>
    ${backLink(s)}
  `));
});

router.post('/account/forgot', (req, res) => {
  const s = shop(req);
  const email = String(req.body.email || '').trim();
  if (email !== s.email) {
    return res.send(page('Forgot password', `<p>No account uses that email address.</p>${backLink(s)}`));
  }
  const token = crypto.randomBytes(16).toString('hex');
  resetTokens[req.sessionID] = { token, email };
  res.send(page('Reset link sent', `
    <h2>Reset link "sent" to ${esc(email)}</h2>
    <p class="note">Demo mode: the email is shown here instead.</p>
    <p><a class="btn" href="/bizlogic/account/reset?token=${token}">Reset your password</a></p>
    <p class="dim">Token: <code>${token}</code></p>
    ${backLink(s)}
  `));
});

router.get('/account/reset', (req, res) => {
  const s = shop(req);
  const rec = resetTokens[req.sessionID];
  const token = String(req.query.token || '');
  if (!rec || rec.token !== token) {
    return res.status(400).send(page('Reset password', `<p>Invalid or expired reset token.</p>${backLink(s)}`));
  }
  res.send(page('Reset password', `
    <h2>Choose a new password for ${esc(rec.email)}</h2>
    <form method="POST" action="/bizlogic/account/reset">
      <input type="hidden" name="token" value="${esc(token)}" />
      <input type="password" name="new_password" placeholder="new password" />
      <button type="submit">Set new password</button>
    </form>
    ${backLink(s)}
  `));
});

router.post('/account/reset', (req, res) => {
  const s = shop(req);
  const rec = resetTokens[req.sessionID];
  const token = String(req.body.token || '');
  const newPassword = String(req.body.new_password || '').slice(0, 80);
  if (!rec || rec.token !== token) {
    return res.status(400).send(page('Reset password', `<p>Invalid or expired reset token.</p>${backLink(s)}`));
  }
  if (!newPassword) {
    return res.status(400).send(page('Reset password', `<p>A new password is required.</p>${backLink(s)}`));
  }
  // Takeover complete: the email was rerouted without re-auth, the reset token
  // went to the attacker's address, and the password is now theirs.
  s.password = newPassword;
  delete resetTokens[req.sessionID];

  let flagHtml = '';
  if (s.email !== s.originalEmail && !captured(req, 'bizlogic', 'biz-email-noreauth')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-email-noreauth'));
  }
  res.send(page('Password reset', `
    <h2>Password changed for ${esc(s.email)}</h2>
    ${s.email !== s.originalEmail
      ? '<p><b>Account takeover.</b> The email was changed with no password check, the reset link went to the new address, and the password is now yours.</p>'
      : '<p>Password updated.</p>'}
    ${flagHtml}
    ${backLink(s)}
  `));
});

// -------------------------------------------------------------- v8: refund
router.get('/refund', (req, res) => {
  const s = shop(req);
  const orderRows = s.orders.map((o) => `
    <tr>
      <td>#${o.id}</td><td>${esc(o.items)}</td><td>${money(o.total)}</td>
      <td>
        <form method="POST" action="/bizlogic/refund" style="display:inline">
          <input type="hidden" name="order_id" value="${o.id}" />
          <input type="hidden" name="amount" value="${o.total}" />
          <button type="submit">Refund ${money(o.total)}</button>
        </form>
      </td>
    </tr>`).join('') || '<tr><td colspan="4"><i>no orders yet: buy something first</i></td></tr>';
  res.send(page('Refunds', `
    <h2>Request a refund</h2>
    <form method="POST" action="/bizlogic/refund/buy">
      <input type="hidden" name="product_id" value="hoodie" />
      <button type="submit">Buy the $50 hoodie first</button>
    </form>
    <h3>Your orders</h3>
    <table class="tbl"><tr><th>Order</th><th>Items</th><th>Paid</th><th></th></tr>${orderRows}</table>
    <p class="note">View the page source: the refund amount is a hidden field. Try it with curl:</p>
    <pre><code>curl -s -X POST http://localhost:3000/bizlogic/refund -d 'order_id=1&amount=5000'</code></pre>
    ${backLink(s)}
  `));
});

router.post('/refund/buy', (req, res) => {
  const s = shop(req);
  const p = productById(String(req.body.product_id || '')) || PRODUCTS[0];
  if (s.balance < p.price) {
    return res.send(page('Buy', `<p>Insufficient balance for ${money(p.price)}.</p>${backLink(s)}`));
  }
  s.balance -= p.price;
  s.orders.push({ id: s.orderSeq++, items: `${p.name} x1`, total: p.price, currency: 'USD', paid: true, note: '' });
  res.redirect('/bizlogic/refund');
});

router.post('/refund', (req, res) => {
  const s = shop(req);
  const order = s.orders.find((o) => o.id === parseInt(req.body.order_id, 10));
  if (!order) {
    return res.status(404).send(page('Refund', `<p>Order not found.</p>${backLink(s)}`));
  }
  const amount = parseFloat(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).send(page('Refund', `<p>Refund amount must be a positive number.</p>${backLink(s)}`));
  }
  // VULN: the refund amount comes from a hidden form field and is never clamped
  // to what was actually paid, so any amount can be refunded.
  s.balance += amount;

  let flagHtml = '';
  if (amount > order.total && !captured(req, 'bizlogic', 'biz-refund')) {
    flagHtml = flagBox(award(req, 'bizlogic', 'biz-refund'));
  }
  res.send(page('Refund processed', `
    <h2>Refunded ${money(amount)} on order #${order.id}</h2>
    <p>That order paid ${money(order.total)}. New balance: <b>${money(s.balance)}</b></p>
    ${amount > order.total ? '<p><b>Over-refunded.</b> The server refunded more than the order was ever worth.</p>' : ''}
    ${flagHtml}
    ${backLink(s)}
  `));
});

module.exports = {
  id: 'bizlogic',
  name: 'Business Logic Flaws',
  tagline: 'No injection needed: break the shop by breaking its own rules.',
  description: 'An in-module shop whose application logic is wrong on purpose: negative quantities that credit your balance, prices taken from hidden form fields, coupons stacking past 100%, an OTP "verified" by JavaScript, a checkout step you can skip, confused currencies, email changes with no re-authentication, and refund amounts you choose yourself.',
  difficulty: 'Mixed',
  vulns: VULNS.map(({ id, name, difficulty, hint, how }) => ({ id, name, difficulty, hint, how })),
  router,
};
