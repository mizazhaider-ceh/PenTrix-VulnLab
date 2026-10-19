'use strict';
// Clickjacking: the Postbox account page sends no framing protection, so an attacker can embed it.
const express = require('express');
const crypto = require('crypto');
const { page, esc, brief, flagBox, fixPanel, hintLadder, hintBox, toolsPill } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { postbox, attackerSite, backLink } = require('../shared');

const router = express.Router();

// The "dangerous" button is deliberately harmless: the vulnerability under
// test is the missing framing protection.
//
// Verification model: merely visiting /csrf/framedemo awards nothing. The flag
// is awarded only when the server observes the full framing chain: (1) the
// framing demo issues a one-time frame token, (2) the victim page is actually
// loaded inside the frame carrying that token, (3) the framed form is
// submitted back with the token. A bare page visit or a bare POST with no
// token earns no flag.
function vipPage(message, frameToken) {
  return page('Account actions', `
    <h1>Account actions</h1>
    ${postbox('Account', `
      <p class="dim">Closing your account removes your mailbox and all stored mail.</p>
      ${message || ''}
      <form method="post" action="/csrf/vip-action">
        ${frameToken ? `<input type="hidden" name="frame" value="${esc(frameToken)}" />` : ''}
        <button type="submit" class="clay-btn clay-btn-primary">Delete my account</button>
      </form>
    `)}
  `);
}

router.get('/vip-action', (req, res) => {
  // VULN: deliberately no X-Frame-Options (and no CSP frame-ancestors): this
  // missing header is the vulnerability, so any site can frame this page.
  res.removeHeader('X-Frame-Options');
  // A frame token proves this load came through the framing demo; record it so
  // the later form submission can be tied to a real framed load.
  const f = String(req.query.frame || '');
  const frameToken = (f && req.session.frameNonce === f) ? f : null;
  if (frameToken) req.session.frameSeen = frameToken;
  res.send(vipPage('', frameToken));
});

router.post('/vip-action', (req, res) => {
  res.removeHeader('X-Frame-Options');
  const f = String(req.body.frame || '');
  // Award only when the submission carries the one-time token AND the token was
  // previously seen on a framed load of the victim page: evidence the click
  // actually landed on the framed button.
  const ok = f.length > 0 && req.session.frameNonce === f && req.session.frameSeen === f;
  if (ok) {
    req.session.frameSeen = null; // single-use: the token cannot award twice
    const flag = award(req, 'csrf', 'clickjacking');
    return res.send(vipPage(`
      <p><b>Demo only:</b> your account was <u>not</u> deleted. But the click you
      just made landed on this framed button through the attacker's page,
      which is a successful clickjacking.</p>
      ${flagBox(flag)}
      ${fixPanel('csrf', 'clickjacking')}
    `, null));
  }
  res.send(vipPage(`
    <p><b>Demo only:</b> your account was <u>not</u> deleted. This page exists to
    demonstrate framing, not to do anything destructive.</p>
    <p class="dim">No flag: it is awarded only when this form is submitted from
    inside the attacker's frame (with its one-time token), proving a framed
    click actually happened.</p>
  `, null));
});

// Framing demo: the in-lab attacker page. Visiting it alone awards nothing;
// the flag comes from the framed submission.
router.get('/framedemo', (req, res) => {
  // VULN: the demo issues the framing token, but the token alone is worthless:
  // it only becomes evidence when the framed page loads with it and posts back.
  req.session.frameNonce = crypto.randomBytes(16).toString('hex');
  req.session.frameSeen = null;
  const nonce = req.session.frameNonce;
  res.send(page('Prize page', `
    <h1>Prize page</h1>
    ${brief('Scenario', `
      You received a link to a page that promises a free prize. The page is run
      by an attacker, and it embeds a real Postbox page you are already signed
      in to. Your goal: get a click of yours to land on a Postbox button you
      never meant to press.
    `)}
    ${attackerSite('prizes.example', `
      <h3>You have been selected!</h3>
      <p><a class="clay-btn clay-btn-primary" href="#framed-victim">Claim your FREE prize</a></p>
      <p class="dim">A real attack makes the frame below transparent and lines
      the real button up exactly under the one above. Here the frame is left
      visible so you can see what is being embedded.</p>
      <iframe id="framed-victim" title="Embedded Postbox account page" src="/csrf/vip-action?frame=${esc(nonce)}" width="100%" height="460"></iframe>
    `)}
    ${hintLadder(module.exports.vuln)}
    ${hintBox('An attacker would make the iframe fully invisible and place a fake button exactly over the real one. The victim clicks "Win a prize" but hits "Delete my account".')}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csrf/vip-action">Open the framed page directly</a>
    (no token, so submitting it there earns no flag)</p>
    ${toolsPill(module.exports.vuln)}
    ${backLink()}
  `));
});

module.exports = {
  vuln: {
    id: 'clickjacking',
    name: 'Clickjacking (missing X-Frame-Options)',
    difficulty: 'Easy',
    hint: 'The VIP action page sends no X-Frame-Options header, so any site can embed it in an invisible iframe and trick clicks into landing on its buttons. Open /csrf/framedemo and click the decoy prize button: your click lands on the hidden "Delete my account" button, and the framed form submission captures the flag.',
    hints: ["The VIP action page has no X-Frame-Options. Can it be framed?", "An attacker's invisible iframe can host the page. Your click on their decoy button lands on the hidden real button.", "Open the framing demo and press the real button inside the frame. The framed form submits with the one-time token."],
    tools: "B",
    how: 'Open /csrf/framedemo and click the decoy button layered over the nearly-invisible framed page. The click submits the framed form, which carries the one-time framing token.',
    link: '/csrf/framedemo',
    start: 'curl -s -I http://localhost:3000/csrf/vip-action',
  },
  router,
};
