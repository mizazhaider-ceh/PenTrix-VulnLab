'use strict';
// HTTP Method Override Smuggling: a plain POST with _method=DELETE reaches the "protected" delete path.
const express = require('express');
const { page, brief, flagBox, fixPanel, hintLadder, hintBox, toolsPill } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { currentUser, postbox, attackerSite, backLink, notLoggedInPage, crossSiteEvidence, notForgedPage } = require('../shared');

const router = express.Router();

// DELETE is treated as the privileged method (cross-site DELETE needs a CORS
// preflight), but the app honors a _method=DELETE field on a plain POST, which
// needs no preflight at all.
router.get('/account', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage('Account'));
  const deleted = !!req.session.accountDeleted;
  res.send(page('Account', `
    <h1>Account</h1>
    ${brief('Scenario', `
      Closing a Postbox account is a destructive action, so the developers
      reserved it for the <code>DELETE</code> method: browsers insist on a CORS
      preflight before a foreign site may send one, so they did not bother with
      a CSRF token. Your goal: close the signed-in user's account from a page
      the victim opens.
    `)}
    ${postbox('Account', `
      <p>Account status: <span class="clay-pill">${deleted ? 'DELETED' : 'active'}</span></p>
      <p class="dim">The Postbox web client closes accounts with a
      <code>DELETE /csrf/account</code> request sent by its own JavaScript.</p>
    `)}
    ${attackerSite('evil.example', `
      <h3>Verify you are human</h3>
      <p>This page can only make the victim's browser send a plain form. It
      carries one extra hidden field.</p>
      <form method="POST" action="/csrf/account">
        <input type="hidden" name="_method" value="DELETE" />
        <button type="submit" class="clay-btn clay-btn-primary">Continue</button>
      </form>
      <p class="dim">Note: this form lives on the lab's own page, so submitting
      it here is a same-origin request and earns nothing. Host the same form on
      another site, or in Burp Repeater set a foreign <code>Referer</code> or
      <code>Origin</code> header, so the arriving request really crosses sites.</p>
    `)}
    ${hintLadder(module.exports.vuln)}
    ${hintBox('Method-override parameters exist for HTML forms, which can only send GET and POST. Honoring them on state-changing routes re-opens every method you thought was protected.')}
    ${backLink()}
  `));
});

router.post('/account', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage('Account'));
  // VULN: manual _method override lets a plain POST trigger the privileged DELETE path.
  if (String(req.body._method || '').toUpperCase() === 'DELETE') {
    // The forged delete only proves anything when it really crossed sites.
    // A plain self-POST (no foreign Referer or Origin) changes nothing.
    if (!crossSiteEvidence(req)) {
      return res.status(403).send(notForgedPage('Account',
        'The override field parsed, but the request carried no cross-site evidence (no foreign Referer or Origin header), so the account was left untouched.'));
    }
    req.session.accountDeleted = true;
    const flag = award(req, 'csrf', 'method-override-csrf');
    return res.send(page('Account', `
      <h1>Account deleted</h1>
      ${flagBox(flag)}
      ${fixPanel('csrf', 'method-override-csrf')}
      ${postbox('Account', '<p>The <code>_method=DELETE</code> override on a plain POST triggered the delete path.</p>')}
      ${toolsPill(module.exports.vuln)}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csrf/account">Back to the account page</a></p>
    `));
  }
  res.send(page('Account', `
    <h1>Account</h1>
    ${postbox('Account', '<p>Nothing to do: a plain POST does not close the account.</p>')}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csrf/account">Back to the account page</a></p>
  `));
});

// The "proper" client path: a real DELETE. It deletes but earns no flag; the
// challenge is the override.
router.delete('/account', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage('Account'));
  req.session.accountDeleted = true;
  res.send(page('Account', `
    <h1>Account deleted</h1>
    ${postbox('Account', '<p>Deleted via the DELETE method. No flag on this path: the challenge is the override.</p>')}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/csrf/account">Back to the account page</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'method-override-csrf',
    name: 'HTTP Method Override Smuggling (_method=DELETE)',
    difficulty: 'Medium',
    hint: 'The app treats DELETE as the privileged method, but honors a _method=DELETE field on a plain POST. Cross-site forms can only send GET/POST, so the override smuggles the "protected" method through with no preflight. The flag demands cross-site evidence (a foreign Referer or Origin): a self-POST in your own session changes nothing.',
    hints: ["The app honors _method=DELETE on a POST. Why is that a CSRF problem?", "Cross-site forms can only send GET/POST. The override smuggles the 'protected' DELETE through a plain POST with no preflight.", "Capture the plain form in Burp Proxy, then tweak and replay it in Repeater: give the _method field the value that names the privileged verb, and set a foreign Referer or Origin header so the request reads as a genuine cross-site forgery. To turn the working request into the attacker page a victim would visit, right-click it and choose Engagement tools, Generate CSRF PoC (Tool Setup Guide, section 9)."],
    tools: "BZ, B",
    how: 'Post the account form with the method-override field set so the plain POST reaches the privileged delete path, carrying a foreign Referer or Origin header as cross-site evidence.',
    link: '/csrf/account',
    start: 'Point your browser at Burp Proxy, sign in as alice at /csrf/login/alice, then open /csrf/account and intercept the attacker form submission.',
  },
  router,
};
