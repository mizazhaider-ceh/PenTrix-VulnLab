'use strict';
// Parameter Pollution Picks Last: GET /redirect/polluted. When ?next= appears
// more than once, the server silently honors the LAST value; the first one is
// only camouflage for anyone reviewing the link.
const express = require('express');
const { award } = require('../../../lib/flags');
const { page, esc, flagBox, fixPanel, hintLadder, toolsPill } = require('../../../lib/page');
// Shared module helpers (created by the finisher in modules/redirect/shared.js):
//   shared.sendRedirect(res, target, innerHtml) -> 302 + Location + page body.
//   shared.challengeForm(action, noteHtml)     -> GET form used by sibling labs.
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'redirect-pollution',
  name: 'Parameter Pollution Picks Last',
  difficulty: 'Medium',
  hint: 'When ?next= appears twice, the server silently honors the last value. The first one is just camouflage.',
  hints: [
    'The endpoint takes ?next=. What if next appears twice?',
    'Duplicate parameters: the validator checks the first, but the redirect uses the last.',
    'Try ?next=safe&next=https://evil.com. The Location has the evil host.',
  ],
  tools: 'C',
  how: 'Request /redirect/polluted?next=safe&next=https://evil.com and check which value lands in the Location header.',
  link: '/redirect#redirect-pollution',
  start: 'curl -s http://localhost:3000/redirect/polluted | head -c 400\ncurl -i "http://localhost:3000/redirect/polluted?next=safe&next=https://evil.com" | grep -i location',
};

// ----------------------------------------------- v6: parameter pollution
router.get('/polluted', (req, res) => {
  const raw = req.query.next;
  if (raw === undefined) {
    return res.send(page('Redirect: parameter pollution', `
      <div class="clay-card">
        <h2>Legacy redirect</h2>
        <p>This old endpoint redirects to <code>next</code>. When the parameter
        appears more than once, the server silently honors the <b>last</b> value.</p>
        <form method="GET" action="/redirect/polluted">
          <div class="clay-field">
            <label for="next">Redirect target</label>
            <input class="clay-input" type="text" id="next" name="next" size="60"
              placeholder="https://example.com/welcome" />
          </div>
          <button class="clay-btn clay-btn-primary" type="submit">Go</button>
        </form>
        <p class="note">Try <code>?next=safe&amp;next=https://evil.com</code> and check
        which value lands in the <code>Location</code> header.</p>
      </div>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
      ${hintLadder(vuln)}
      ${toolsPill(vuln)}
    `));
  }
  const vals = Array.isArray(raw) ? raw : [raw];
  // VULN: with duplicate parameters the code honors the last value; the first
  // one is only camouflage for anyone reviewing the link.
  const target = String(vals[vals.length - 1]);
  let host = '';
  try { host = new URL(target).hostname.toLowerCase(); } catch (e) { host = ''; }
  let flagHtml = '';
  if (vals.length > 1 && host && host !== 'pentrix.lab') {
    const flag = award(req, 'redirect', 'redirect-pollution');
    flagHtml = `<hr /><p>${vals.length} values were supplied
      (<code>${vals.map((v) => esc(String(v))).join('</code>, <code>')}</code>);
      the server honored the last one.</p>${flagBox(flag)}${fixPanel('redirect', 'redirect-pollution')}`;
  }
  shared.sendRedirect(res, target, `
    <div class="clay-card">
      <h2>Redirecting...</h2>
      <p>If your browser does not follow automatically,
      <a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(target)}">click here</a>.</p>
      ${flagHtml}
    </div>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect/polluted">Try another value</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
  `);
});

module.exports = {
  vuln,
  router,
};
