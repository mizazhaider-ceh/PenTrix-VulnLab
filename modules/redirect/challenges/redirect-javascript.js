'use strict';
// javascript: Scheme Honored: GET /js puts ?next= straight into the Location
// header with no scheme allowlist. Dangerous schemes like javascript: are
// honored the same way a plain https: URL is.
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

// Clay-styled promo redirect form, submitted as a GET so the value shows up
// in the URL.
function challengeForm() {
  return `
    <form method="get" action="/redirect/js" class="clay-card">
      <div class="clay-field">
        <label for="next">Which promo page should we send you to?</label>
        <input class="clay-input" id="next" name="next" type="text" size="60"
          placeholder="https://example.com/promo" autocomplete="off" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Go</button>
    </form>
    <p class="note">Try <code>?next=javascript:alert(1)</code> and inspect the
    <code>Location</code> header with <code>curl -i</code>.</p>`;
}

// GET /js -> v2 javascript: scheme redirect. This promo endpoint redirects to
// `next` and never checks the URL scheme.
router.get('/js', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(page('Redirect: javascript: scheme', `
      <h2>Promo redirect</h2>
      <p>This promo endpoint redirects to <code>next</code>. It never checks the
      URL scheme.</p>
      ${challengeForm()}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
      ${hintLadder(vuln)}
      ${toolsPill(vuln)}
    `));
  }
  const target = String(next);
  // VULN: the Location header is set from user input with no scheme allowlist.
  let flagHtml = '';
  if (/^javascript:/i.test(target)) {
    const flag = award(req, 'redirect', 'redirect-javascript');
    flagHtml = `<hr /><p>The server honored a <code>javascript:</code> URL in the
      <code>Location</code> header. Older browsers execute it in the context of
      the trusted site; modern ones still leak it into logs, referers, and
      link previews.</p>${flagBox(flag)}${fixPanel('redirect', 'redirect-javascript')}`;
  }
  sendRedirect(res, target, `
    <h2>Redirecting...</h2>
    <p>If your browser does not follow automatically,
    <a href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect/js">Try another value</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
  `);
});

const vuln = {
  id: 'redirect-javascript',
  name: 'javascript: Scheme Honored',
  difficulty: 'Medium',
  hint: 'The redirect puts whatever you give it into the Location header, with no scheme allowlist. Browsers treat javascript: as code, not a page.',
  hints: ["Proxy the promo form submit in Burp, send the request to Repeater, and change the value of next. What does the response Location header do with it?", "Think about schemes: Repeater lets you send any Location target back. Which scheme does a browser treat as code?", "The key insight: the server copies your input into the Location header with no scheme allowlist, so the scheme is yours to choose."],
  tools: 'BZ, B',
  how: 'In Repeater, request /redirect/js with next set to a javascript: URL and confirm the Location header carries that scheme.',
  link: '/redirect#redirect-javascript',
  start: 'Submit the promo form at /redirect/js through Burp Proxy and send the request to Repeater.',
};

module.exports = { vuln, router };
