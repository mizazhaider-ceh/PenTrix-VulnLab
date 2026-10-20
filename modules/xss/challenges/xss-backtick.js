'use strict';
// XSS in a template literal: input is reflected raw inside backticks, where ${...} evaluates.
const express = require('express');
const { page, esc, claimBox, fixCta } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');

const router = express.Router();

router.get('/backtick', (req, res) => {
  const m = String(req.query.m || '');
  // VULN: user input reflected raw inside a JavaScript template literal.
  const script = 'var msg = `' + m + '`;\n      document.getElementById(\'status\').textContent = msg || \'No status set.\';';
  res.send(page('Status · Pulse Team Chat', `
    <h2>Pulse Team Chat</h2>
    ${xssNonceTag(req, 'xss-backtick')}
    ${siteFrame('Pulse Team Chat', ['Channels', 'People', 'Status'], `
      <p>Let your team know what you are up to. Your status shows next to your name.</p>
      <form method="GET" action="/xss/backtick">
        <div class="clay-field">
          <label for="m">Status message</label>
          <input class="clay-input" type="text" id="m" name="m" value="${esc(m)}" placeholder="Heads down until 3pm" autocomplete="off">
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Set status</button>
      </form>
      <h3>Current status</h3>
      <div class="note" id="status">No status set.</div>
      <script>
      ${script}
      </script>`)}
    ${claimBox({ vulnId: 'xss-backtick', payload: esc('${' + beacon('xss-backtick') + '}'), statusUrl: '/xss/claim-status?v=xss-backtick' })}
    ${fixCta('xss', 'xss-backtick')}
    ${backLinks('xss-backtick')}
  `));
});

module.exports = {
  vuln: {
    id: 'xss-backtick',
    name: 'XSS in a Template Literal',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'Your input lands inside backticks: var msg = `...`. Template literals evaluate ${...} expressions inline.',
    hints: [
      'Your input lands inside a JavaScript template literal: var msg = `...`. Template literals do something special with ${}.',
      "The ${...} inside backticks is evaluated as code. You don't need to break out; just inject an expression.",
      'In Burp Repeater, build the request with your ${...} expression in the m parameter and check the reflected script in the response. Then load the final request URL in the browser and watch for the /xss/collect hit.',
    ],
    tools: 'BZ, B',
    how: 'Your input sits inside a template literal, which evaluates embedded expressions on its own. In Burp Repeater, work out how to get an expression evaluated in place, then load the final URL in the browser so it fires the beacon.',
    link: '/xss/backtick',
    start: 'Proxy the page through Burp, then send the request to Repeater. Watch how m lands inside var msg = `...` in the response. Test ${...} expressions in Repeater, then paste the Repeater URL into the browser to fire the beacon.',
  },
  router,
};
