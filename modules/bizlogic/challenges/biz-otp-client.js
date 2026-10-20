'use strict';
// OTP Verified by JavaScript: the client-side check sets a hidden otp_ok flag
// and the server trusts that flag instead of verifying the OTP itself.
// NOTE: the finisher's shared.js (modules/bizlogic/shared.js) provides:
//   shop(req)        session shop state (balance, cart, orders)
//   money(n)         USD formatting helper
//   balLine(s)       store-balance line used by every shop page
//   backLink(s)      "Back to module / Reset shop" footer for shop pages
//   REAL_OTP         the OTP "emailed" to the buyer ('739184')
const express = require('express');
const { page, esc, flagBox, fixPanel } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');
const { shop, money, balLine, backLink, REAL_OTP } = shared;

const router = express.Router();
// Form parsing for this challenge's routes (mirrors router.js router-scoped use).
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'biz-otp-client',
  name: 'OTP Verified by JavaScript',
  difficulty: 'Medium',
  hint: 'The page JavaScript checks the OTP and sets a hidden otp_ok flag. The server trusts that flag. What if you set it yourself?',
  hints: ["The OTP check happens client-side. Check the Proxy history in Burp: which field does the server actually trust?", "The server trusts the client-side 'otp_ok' field. Send the POST to Repeater and tamper with that one field.", "In Repeater, flip the flag field your browser sends to its verified value, then send the request. The OTP value itself can stay wrong."],
  tools: 'BZ, B, DT',
  how: 'In Burp Repeater, take the intercepted POST to /bizlogic/otp/verify and forge the client-side otp_ok claim so the server accepts it, using a wrong OTP. The JavaScript check never runs on the server side.',
  link: '/bizlogic#biz-otp-client',
  start: 'Open /bizlogic/otp in the browser with Burp Proxy on and submit any wrong OTP. Find the POST to /bizlogic/otp/verify in Proxy > HTTP history, send it to Repeater, and experiment with the hidden field the JavaScript normally sets.',
};

router.get('/otp', (req, res) => {
  const s = shop(req);
  res.send(page('OTP verification', `
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">🛒</span><b>PenTrix Shop</b><span class="dim">order verification</span></div>
      <h2>Confirm your $50 order</h2>
      <p>For this demo, the OTP "emailed" to you is: <b>${REAL_OTP}</b></p>
      <form method="POST" action="/bizlogic/otp/verify" onsubmit="return checkOtp(event)">
        <label class="field-label" for="otp">One-time code</label>
        <input class="clay-input" type="text" id="otp" name="otp" placeholder="enter OTP" />
        <input type="hidden" id="otp_ok" name="otp_ok" value="0" />
        <p><button class="clay-btn clay-btn-primary" type="submit">Verify and pay</button></p>
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
      What does the server check? Try it in Burp Repeater: submit any wrong OTP
      with Proxy intercepting, send the request to Repeater with Ctrl+R, flip
      <code>otp_ok</code> to <code>1</code>, and send.</p>
      <div class="payload"><div class="payload-head"><span>Burp Repeater</span></div><pre class="payload-body">POST /bizlogic/otp/verify HTTP/1.1
Host: <your-lab-address>
Content-Type: application/x-www-form-urlencoded
Content-Length: 19

otp=000000&amp;otp_ok=1</pre></div>
    </div>
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
      flagHtml += fixPanel('bizlogic', 'biz-otp-client');
    }
    return res.send(page('Order confirmed', `
      <div class="card clay-card">
        <div class="card-top"><span class="orb" aria-hidden="true">🛒</span><b>PenTrix Shop</b><span class="dim">order receipt</span></div>
        <h2>OTP accepted, order confirmed</h2>
        <p>Submitted OTP: <code>${esc(otp)}</code> · New balance: <b>${money(s.balance)}</b></p>
        ${otp !== REAL_OTP ? '<p><b>Verified without the real code.</b> The server never checked the OTP; it trusted your browser.</p>' : ''}
        ${flagHtml}
      </div>
      ${backLink(s)}
    `));
  }
  res.send(page('Verification failed', `
    <div class="card clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">🛒</span><b>PenTrix Shop</b><span class="dim">order verification</span></div>
      <h2>OTP verification failed</h2>
      <p>The check did not pass. (The server only looks at the <code>otp_ok</code> field your browser sends.)</p>
    </div>
    ${backLink(s)}
  `));
});

module.exports = { vuln, router };
