'use strict';
// Business Logic Flaws (bizlogic): an in-module shop whose application logic
// is wrong on purpose. Thin aggregator: the eight challenges live in
// ./challenges/, shared shop state in ./shared.js. Only the module index page
// and the shop /reset helper route live here.
const express = require('express');
const { brief, esc, hintLadder, page, toolsPill, trackBanner, difficultyPill, easyFirst, cardConsoles, startBlock, fixSection, consoleMap , capturedPill } = require('../../lib/page');
const shared = require('./shared');

const challenges = [
  require('./challenges/biz-negative-qty'),
  require('./challenges/biz-price-tamper'),
  require('./challenges/biz-coupon-stack'),
  require('./challenges/biz-otp-client'),
  require('./challenges/biz-workflow-skip'),
  require('./challenges/biz-currency'),
  require('./challenges/biz-email-noreauth'),
  require('./challenges/biz-refund'),
];

const router = express.Router();
// Module-scoped form parsing (mirrors the old module router). The challenge
// routers that define POST routes without their own parser rely on this.
router.use(express.urlencoded({ extended: false }));

// Challenge entry-point paths, used by the module index cards below.
const CHALLENGE_PATH = {
  'biz-negative-qty': '/negative-qty',
  'biz-price-tamper': '/price-tamper',
  'biz-coupon-stack': '/coupon-stack',
  'biz-otp-client': '/otp',
  'biz-workflow-skip': '/workflow',
  'biz-currency': '/currency',
  'biz-email-noreauth': '/account',
  'biz-refund': '/refund',
};

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

// GET /bizlogic/reset -> reset the shop (module-level helper route, kept from
// the old module router; it is not part of any single challenge).
router.get('/reset', (req, res) => {
  req.session.biz = shared.freshShop();
  delete shared.resetTokens[req.sessionID];
  res.send(page('Shop reset', `
    <h2>Shop reset</h2>
    <p>Balance restored to ${shared.money(shared.START_BALANCE)}; cart, orders and account cleared.</p>
    <p><a href="/bizlogic">Back to the Business Logic module</a></p>
  `));
});

// GET /bizlogic -> module index page (the in-module shop front).
router.get('/', (req, res) => {
  const ordered = easyFirst(challenges);
  const consoles = cardConsoles('bizlogic', ordered, consoleMap('/bizlogic', CHALLENGE_PATH));
  const cards = ordered.map(({ vuln: v }, i) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)} ${capturedPill(req, 'bizlogic', v.id)}</h3>
      <p>${esc(v.how)}</p>
      ${startBlock(v, consoles[i])}
      ${hintLadder(v)}
      ${toolsPill(v)}
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/bizlogic${CHALLENGE_PATH[v.id]}">Open challenge</a></p>
    </article>`).join('');

  res.send(page('Business Logic Flaws', `
    ${brief('Module briefing', BRIEF_HTML)}
    ${trackBanner(module.exports)}
    ${shared.balLine(shared.shop(req))}

    <h2>Challenges</h2>
    <p>Eight flaws hide in this little shop. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}

    <h2>Reset</h2>
    <p><a class="btn ghost" href="/bizlogic/reset">Reset shop</a>
    <span class="dim">Restores your $100 balance, cart, orders and account.</span></p>
  ${fixSection('bizlogic', challenges)}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'bizlogic',
  name: 'Business Logic Flaws',
  tagline: 'No injection needed: break the shop by breaking its own rules.',
  description: 'An in-module shop whose application logic is wrong on purpose: negative quantities that credit your balance, prices taken from hidden form fields, coupons stacking past 100%, an OTP "verified" by JavaScript, a checkout step you can skip, confused currencies, email changes with no re-authentication, and refund amounts you choose yourself.',
  difficulty: 'Intermediate',
  track: 'Advanced',
  prerequisites: ['Foundations track'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
