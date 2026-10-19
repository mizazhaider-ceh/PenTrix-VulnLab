'use strict';
// XSS in a JavaScript string: input is reflected raw inside a single-quoted literal.
const express = require('express');
const { page, esc, claimBox, fixCta } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');

const router = express.Router();

router.get('/jsctx', (req, res) => {
  const q = String(req.query.q || '');
  // VULN: user input reflected raw inside a single-quoted JavaScript string.
  const script = `var q = '${q}';
      document.getElementById('greet').textContent = q ? 'Hello, ' + q + '!' : 'Enter a name to see your greeting.';`;
  res.send(page('Greeting card · Postmark Cards', `
    <h2>Postmark Cards</h2>
    ${xssNonceTag(req, 'xss-js-context')}
    ${siteFrame('Postmark Cards', ['Cards', 'Greetings', 'Orders'], `
      <p>Type the recipient's name and we will print a personal greeting on the card.</p>
      <form method="GET" action="/xss/jsctx">
        <div class="clay-field">
          <label for="q">Recipient name</label>
          <input class="clay-input" type="text" id="q" name="q" value="${esc(q)}" placeholder="Alex" autocomplete="off">
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Create greeting</button>
      </form>
      <h3>Card text</h3>
      <div class="note" id="greet">Enter a name to see your greeting.</div>
      <script>
      ${script}
      </script>`)}
    ${claimBox({ vulnId: 'xss-js-context', payload: esc(`';${beacon('xss-js-context')};//`), statusUrl: '/xss/claim-status?v=xss-js-context' })}
    ${fixCta('xss', 'xss-js-context')}
    ${backLinks('xss-js-context')}
  `));
});

module.exports = {
  vuln: {
    id: 'xss-js-context',
    name: 'XSS in a JavaScript String',
    difficulty: 'Medium',
    hint: "Your input lands inside a single-quoted JS string: var q = '...'. Break out of the string, run your code, and comment out the tail.",
    hints: [
      "Open the page behind Burp Proxy, submit a test name, and find where it lands in the response: inside a single-quoted JS string (var q = '...'). The quote character is not escaped. What can you do with an unescaped quote?",
      'In Burp Repeater, tweak q until the reflected line reads as valid JavaScript again. You need a quote and a semicolon to break out and run your own statement, plus something to silence the leftover tail of the line.',
      'Craft the final request in Burp Repeater, then load that URL in the browser: your injected statement must call the /xss/collect endpoint with the page token (window.__px), because the server only awards the flag when it sees a beacon carrying a fresh token.',
    ],
    tools: 'BZ, B',
    how: 'Break out of the single-quoted JS string with a quote and a semicolon, run a fetch() beacon to /xss/collect for v=xss-js-context with the page token, and end with // to comment out the tail. Craft the request in Burp Repeater, then load the final URL in the browser so the injected statement runs and fires the beacon.',
    link: '/xss/jsctx',
    start: 'Proxy the page through Burp and submit a name normally, then send the request to Repeater. Watch how q reflects inside var q = \'...\' in the response. Tweak q in Repeater until the reflection shows your breakout, then paste the Repeater URL into the browser to fire the beacon.',
  },
  router,
};
