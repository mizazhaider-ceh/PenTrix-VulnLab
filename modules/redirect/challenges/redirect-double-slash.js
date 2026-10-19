'use strict';
// Protocol-Relative Redirect: GET /go uses ?next= as the redirect target with
// zero validation. A target starting with // is a protocol-relative URL, so the
// browser keeps the current scheme but navigates to the attacker's host.
const express = require('express');
const { esc, page, flagBox, fixPanel, hintLadder, toolsPill } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

// Answers with a real 302 plus a readable body, so `curl -i` shows the
// Location header and the explanation page at the same time.
function sendRedirect(res, target, innerHtml) {
  res.status(302).set('Location', target);
  res.send(page('Redirecting', innerHtml));
}

// Clay-styled "where to next" form, submitted as a GET so the value shows up
// in the URL.
function challengeForm() {
  return `
    <form method="get" action="/redirect/go" class="clay-card">
      <div class="clay-field">
        <label for="next">Where should we send you after login?</label>
        <input class="clay-input" id="next" name="next" type="text" size="60"
          placeholder="https://example.com/welcome" autocomplete="off" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Go</button>
    </form>
    <p class="note">Try <code>?next=//evil.com</code> and watch the
    <code>Location</code> header with <code>curl -i</code>.</p>`;
}

// GET /go -> v1 protocol-relative redirect. After login, the app sends the
// browser to the `next` parameter.
router.get('/go', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(page('Open redirect: no validation', `
      <h2>Login complete, where to next?</h2>
      <p>After logging in, the app sends you to the <code>next</code> parameter.
      This endpoint performs <b>no validation at all</b>.</p>
      ${challengeForm()}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
      ${hintLadder(vuln)}
      ${toolsPill(vuln)}
    `));
  }
  const target = String(next);
  // VULN: the next parameter is used as the redirect target with zero validation.
  let flagHtml = '';
  if (target.startsWith('//')) {
    const flag = award(req, 'redirect', 'redirect-double-slash');
    flagHtml = `<hr /><p>A protocol-relative URL was honored: the browser keeps the
      current scheme (<code>http:</code> or <code>https:</code>) but navigates to
      the attacker's host.</p>${flagBox(flag)}${fixPanel('redirect', 'redirect-double-slash')}`;
  }
  sendRedirect(res, target, `
    <h2>Redirecting...</h2>
    <p>If your browser does not follow automatically,
    <a href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect/go">Try another value</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
  `);
});

const vuln = {
  id: 'redirect-double-slash',
  name: 'Protocol-Relative Redirect',
  difficulty: 'Easy',
  hint: 'The ?next= parameter is passed straight to the redirect with no validation. What does a URL starting with // mean to a browser?',
  hints: ["The redirector checks whether the URL starts with '/'. What does a browser do with a URL that starts with two slashes?", "Protocol-relative URLs start with //. The check sees a leading slash and allows it, but the browser resolves the whole thing to an external host you control.", "Make the browser keep the current scheme but navigate to a host you control. The key insight: the check only sees a leading slash, while the browser resolves the whole URL, and a protocol-relative target resolves to an external host."],
  tools: 'B, C',
  how: 'Request /redirect/go?next=//evil.com and confirm the Location header points at evil.com.',
  link: '/redirect#redirect-double-slash',
  start: 'curl -i "http://localhost:3000/redirect/go?next=//evil.com"',
};

module.exports = { vuln, router };
