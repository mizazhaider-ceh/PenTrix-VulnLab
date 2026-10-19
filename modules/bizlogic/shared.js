'use strict';
// Business Logic Flaws module: shared shop state and helpers. This is the
// shop logic the old module router.js held in one file; the per-challenge
// routers in ./challenges/ import exactly these names from '../shared'.
// Behavior is unchanged from router.js: every shop starts with a $100
// balance and lives in the visitor's session.
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
// Shared with the module /reset route (which clears the entry).
const resetTokens = {}; // sessionID -> { token, email }

const cartTotal = (s) => s.cart.reduce((sum, it) => {
  const p = productById(it.productId);
  return sum + (p ? p.price * it.qty : 0);
}, 0);
const money = (n) => `$${Number(n).toFixed(2)}`;
const balLine = (s) => `<p class="note">Your store balance: <b>${money(s.balance)}</b></p>`;
const backLink = (s) => `<p>${balLine(s)}<a href="/bizlogic">Back to module</a> · <a href="/bizlogic/reset">Reset shop</a></p>`;

module.exports = {
  PRODUCTS,
  productById,
  COUPONS,
  REAL_OTP,
  RATES,
  START_BALANCE,
  freshShop,
  shop,
  resetTokens,
  cartTotal,
  money,
  balLine,
  backLink,
};
