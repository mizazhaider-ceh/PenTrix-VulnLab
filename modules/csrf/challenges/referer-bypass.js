'use strict';
// Weak Referer Check Bypass: the nickname endpoint trusts a substring match on the attacker-controlled Referer.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, hintBox, toolsPill, errorPage } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { currentUser, postbox, backLink, notLoggedInPage } = require('../shared');

const router = express.Router();

// Is the Referer URL served from this very host (a legitimate same-origin request)?
function isSameOrigin(ref, host) {
  try { return new URL(ref).host === host; } catch (e) { return false; }
}

// The app is meant to be served at pentrix.lab, and the check is
// referer.includes('pentrix.lab'). The attacker controls the referer sent from
// their own page, so https://evil.com/?pentrix.lab passes.
router.get('/nickname', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.send(notLoggedInPage('Profile settings'));
  const nick = req.session.nickname || '(not set)';
  res.send(page('Profile settings', `
    <h1>Profile settings</h1>
    ${brief('Scenario', `
      Postbox only accepts profile changes that come from its own pages: the
      server looks at the <code>Referer</code> header and refuses anything that
      does not come from the production domain, <code>pentrix.lab</code>. There
      is no CSRF token. Your goal: change <b>${esc(user.username)}</b>'s
      nickname as if the request came from a trusted page.
    `)}
    ${postbox('Profile', `
      <p>Current nickname: <b>${esc(nick)}</b></p>
      <form method="post" action="/csrf/api/nickname">
        <div class="clay-field">
          <label for="nickname">New nickname</label>
          <input class="clay-input" id="nickname" name="nickname" type="text" maxlength="40" placeholder="new nickname" required />
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Save nickname</button>
      </form>
      <p class="dim">In this lab the app runs on localhost, so even this form is
      refused: your browser sends a localhost referer, not a pentrix.lab one.
      That is the check working as coded.</p>
    `)}
    ${hintLadder(module.exports.vuln)}
    ${hintBox('A substring check on an attacker-controlled value is not a security boundary. Think about what URLs contain the magic string without being on the trusted domain.')}
    ${backLink()}
  `));
});

router.post('/api/nickname', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).send(notLoggedInPage('Profile settings'));
  const ref = req.get('referer') || '';
  // VULN: substring referer check is attacker-controlled; evil.com/?pentrix.lab passes it.
  if (!ref.includes('pentrix.lab')) {
    return res.status(403).send(page('Forbidden', errorPage(403, 'Referer check failed',
      '<p>This request did not come from a trusted Postbox page.</p><p><a href="/csrf/nickname">Back to profile settings</a></p>')));
  }
  const nick = String(req.body.nickname || '').slice(0, 40);
  req.session.nickname = nick;
  // Award only when the change came through a forged (non-same-origin) referer.
  const flagHtml = isSameOrigin(ref, req.get('host') || '') ? '' : flagBox(award(req, 'csrf', 'referer-bypass')) + fixPanel('csrf', 'referer-bypass');
  res.send(page('Profile settings', `
    <h1>Nickname changed</h1>
    ${flagHtml}
    ${postbox('Profile', `<p>Nickname is now: <b>${esc(nick)}</b> (referer was <code>${esc(ref)}</code>)</p>`)}
    ${toolsPill(module.exports.vuln)}
    ${backLink()}
  `));
});

module.exports = {
  vuln: {
    id: 'referer-bypass',
    name: 'Weak Referer Check Bypass',
    difficulty: 'Medium',
    hint: 'The Referer check is a substring match against a domain name the page itself reveals. The key insight: you control the Referer of requests from your own page, so craft a URL on an untrusted host that merely contains that trusted domain string.',
    hints: ["The nickname change checks the Referer header. Who controls the Referer?", "You do. The check is a substring match, so any URL that merely contains the trusted domain name passes.", "In Burp Repeater, take the nickname POST and rewrite the Referer header by hand. Think of a URL on an untrusted host that still happens to contain the trusted domain name."],
    tools: "BZ, B",
    how: 'In Burp Repeater, replay the nickname POST with the Referer header rewritten by hand: the check is a substring match, so a foreign URL that merely contains the trusted domain string passes, the nickname changes, and the flag is awarded.',
    link: '/csrf/nickname',
    start: 'Open Burp Suite, point your browser at the proxy, and visit /csrf/nickname. Log in as alice, submit the nickname form once so the POST lands in Proxy history, then send it to Repeater and work on the Referer header.',
  },
  router,
};
