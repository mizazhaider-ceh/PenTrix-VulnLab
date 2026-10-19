'use strict';
// XSS in a JavaScript string: input is reflected raw inside a single-quoted literal.
const express = require('express');
const { page, esc, claimBox } = require('../../../lib/page');
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
      "Your input lands inside a JavaScript string: var q = '...'. The single quote is not escaped.",
      'Break out of the string with a quote and a semicolon, run your own statement, then comment out the rest of the line with //.',
      'Submit a single quote and semicolon, then a fetch() call to /xss/collect (parameters c, v=xss-js-context and n=window.__px), then // to swallow the leftover quote.',
    ],
    tools: 'B',
    how: 'Break out of the single-quoted string with a quote, run a fetch() beacon for v=xss-js-context, and end with // to comment out the tail.',
    link: '/xss/jsctx',
    start: 'curl -s "http://localhost:3000/xss/jsctx?q=Alex" | grep -n "var q"',
  },
  router,
};
