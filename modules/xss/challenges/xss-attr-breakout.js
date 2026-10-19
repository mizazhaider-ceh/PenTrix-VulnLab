'use strict';
// XSS via attribute breakout: input is reflected raw inside value="...".
const express = require('express');
const { page, esc, claimBox } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');

const router = express.Router();

router.get('/attr', (req, res) => {
  const n = String(req.query.n || '');
  // VULN: user input reflected raw inside an HTML attribute value.
  const preview = `<input class="clay-input" type="text" id="preview-nick" value="${n}" readonly>`;
  res.send(page('Profile nickname · Hearth Forum', `
    <h2>Hearth Forum</h2>
    ${xssNonceTag(req, 'xss-attr-breakout')}
    ${siteFrame('Hearth Forum', ['Boards', 'Members', 'Profile'], `
      <p>Pick the nickname shown next to your posts and preview how it will look.</p>
      <form method="GET" action="/xss/attr">
        <div class="clay-field">
          <label for="n">Nickname</label>
          <input class="clay-input" type="text" id="n" name="n" value="${esc(n)}" placeholder="nightowl42" autocomplete="off">
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Preview</button>
      </form>
      <h3>Preview card</h3>
      <div class="card">
        <label for="preview-nick">Posting as</label>
        ${preview}
      </div>`)}
    ${claimBox({ vulnId: 'xss-attr-breakout', payload: esc(`"><script>${beacon('xss-attr-breakout')}</script>`), statusUrl: '/xss/claim-status?v=xss-attr-breakout' })}
    ${backLinks('xss-attr-breakout')}
  `));
});

module.exports = {
  vuln: {
    id: 'xss-attr-breakout',
    name: 'XSS via Attribute Breakout',
    difficulty: 'Medium',
    hint: 'Your input lands inside value="...". The quote is not escaped, so you can close the attribute and open a new tag.',
    hints: [
      'Your input lands inside an HTML attribute: value="...". The quote character is not escaped. What can you do with an unescaped quote?',
      'Close the attribute with ">, then open a new tag. You are breaking out of the attribute context into the HTML body context.',
      'Submit a double quote and a closing angle bracket, followed by a script tag that calls /xss/collect (parameters c, v=xss-attr-breakout and n=window.__px).',
    ],
    tools: 'B',
    how: 'Submit "> followed by a script tag carrying the exfiltration payload (v=xss-attr-breakout).',
    link: '/xss/attr',
    start: 'curl -s "http://localhost:3000/xss/attr?n=nightowl" | grep -n nightowl',
  },
  router,
};
