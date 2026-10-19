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
    hint: 'Your input lands inside backticks: var msg = `...`. Template literals evaluate ${...} expressions inline.',
    hints: [
      'Your input lands inside a JavaScript template literal: var msg = `...`. Template literals do something special with ${}.',
      "The ${...} inside backticks is evaluated as code. You don't need to break out; just inject an expression.",
      'Submit a ${...} expression whose body calls /xss/collect (parameters c, v=xss-backtick and n=window.__px).',
    ],
    tools: 'B',
    how: 'Inject a ${...} expression that calls /xss/collect for v=xss-backtick; it executes inside the literal.',
    link: '/xss/backtick',
    start: 'curl -s "http://localhost:3000/xss/backtick?m=hello" | grep -n "var msg"',
  },
  router,
};
