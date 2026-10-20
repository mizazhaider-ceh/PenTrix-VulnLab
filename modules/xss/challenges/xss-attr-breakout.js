'use strict';
// XSS via attribute breakout: input is reflected raw inside value="...".
const express = require('express');
const { page, esc, claimBox, fixCta } = require('../../../lib/page');
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
    ${fixCta('xss', 'xss-attr-breakout')}
    ${backLinks('xss-attr-breakout')}
  `));
});

module.exports = {
  vuln: {
    id: 'xss-attr-breakout',
    name: 'XSS via Attribute Breakout',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'Your input lands inside value="...". The quote is not escaped, so you can close the attribute and open a new tag.',
    hints: [
      'Your input lands inside an HTML attribute: value="...". The quote character is not escaped. What can you do with an unescaped quote?',
      'Close the attribute with ">, then open a new tag. You are breaking out of the attribute context into the HTML body context.',
      'In Burp Repeater, build the request with your breakout expression in the n parameter and inspect the reflected markup in the response. Then load the final request URL in the browser and watch for the /xss/collect hit.',
    ],
    tools: 'BZ, B',
    how: 'Break out of the attribute with an unescaped quote, then open a script tag that calls /xss/collect for v=xss-attr-breakout. Craft the request in Burp Repeater, then load the final URL in the browser so the injected script runs and fires the beacon.',
    link: '/xss/attr',
    start: 'Proxy the page through Burp, then send the request to Repeater. Watch how n reflects inside value="..." in the response. Tweak n in Repeater until the reflection shows your breakout markup, then paste the Repeater URL into the browser to fire the beacon.',
  },
  router,
};
