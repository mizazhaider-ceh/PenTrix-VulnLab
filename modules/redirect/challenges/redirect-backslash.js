'use strict';
// Backslash Allowlist Bypass (redirect-backslash): GET /redirect/trusted only
// allows redirects to https://pentrix.lab, but it compares the raw string
// prefix instead of the parsed hostname and accepts backslash separators.
// Browsers normalize backslash to slash, so https:\\evil.com passes the check
// while landing on evil.com. The flag lands only when the check passed but the
// real parsed hostname is not pentrix.lab.
const express = require('express');
const { page, esc, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'redirect-backslash',
  name: 'Backslash Allowlist Bypass',
  difficulty: 'Medium',
  hint: 'The code allowlists URLs starting with https://pentrix.lab, but compares the raw string and accepts backslashes as separators. Browsers normalize backslash to slash.',
  hints: ["The allowlist checks for 'https://'. But URLs can use backslashes too.", "The check inspects the raw string instead of the parsed hostname. Browsers treat backslash as a path separator, so the string the check reads and the host the browser resolves can disagree.", "Craft a value whose raw string starts like an allowlisted URL while its parsed hostname points somewhere else. The key insight: the server validates the string, the browser parses the URL, and those two can disagree on the destination."],
  tools: "C",
  how: 'Pass ?next=https:%5C%5Cevil.com (https:\\\\evil.com URL-encoded) to /redirect/trusted and watch the check pass.',
  link: '/redirect#redirect-backslash',
  start: 'curl -i "http://localhost:3000/redirect/trusted?next=https:%5C%5Cevil.com"',
};

const APP = 'PartnerHub';

function entryPage() {
  return page('Redirect: naive allowlist', `
  <section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">P</span><b>${APP}</b><span class="dim">Partner redirect</span></div>
    <h2>Partner redirect</h2>
    <p>This endpoint only allows redirects to <code>https://pentrix.lab</code>.
    It checks the <b>raw string prefix</b> instead of parsing the URL.</p>
    <form method="GET" action="/redirect/trusted">
      <div class="clay-field">
        <label for="next">Partner URL</label>
        <input class="clay-input" id="next" name="next" type="text" size="60" placeholder="https://pentrix.lab/dashboard" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Go</button>
    </form>
    <p class="note">Try <code>?next=https:%5C%5Cevil.com</code> (that is
    <code>https:\\\\evil.com</code> URL-encoded). Browsers normalize backslashes to slashes.</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
  </section>
  ${hintLadder(vuln)}`);
}

router.get('/trusted', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(entryPage());
  }
  const target = String(next);
  // VULN: naive allowlist. The check compares the raw string prefix instead of
  // the parsed hostname, and it also accepts the backslash spelling of a URL.
  // Browsers and the WHATWG URL parser treat backslash as a path separator,
  // so https:\\evil.com navigates to evil.com while sailing through this check.
  const lowered = target.toLowerCase();
  const trusted = lowered.startsWith('https://pentrix.lab') || /^https:\\\\[^\\]+/.test(lowered);
  if (!trusted) {
    return res.status(400).send(page('Redirect blocked', `
  <section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">P</span><b>${APP}</b><span class="dim">Blocked</span></div>
    <h2>Blocked</h2>
    <p class="clay-err" role="alert"><code>${esc(target)}</code> is not an allowed redirect target.</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect/trusted">Try another value</a></p>
  </section>`));
  }
  let host = '';
  try { host = new URL(target).hostname.toLowerCase(); } catch (e) { host = ''; }
  let flagHtml = '';
  // Award only when the check passed but the real destination is NOT pentrix.lab.
  if (host && host !== 'pentrix.lab') {
    const flag = award(req, 'redirect', 'redirect-backslash');
    flagHtml = `<hr /><p>The naive check passed, but the parsed hostname is
      <code>${esc(host)}</code>, not <code>pentrix.lab</code>. The browser would
      navigate to the attacker's site.</p>${flagBox(flag)}${fixPanel('redirect', 'redirect-backslash')}`;
  }
  // Answers with a real 302 plus a readable body, so `curl -i` shows the
  // Location header and the explanation page at the same time.
  res.status(302).set('Location', target);
  res.send(page('Redirecting', `
  <section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">P</span><b>${APP}</b><span class="dim">Redirecting</span></div>
    <h2>Redirecting...</h2>
    <p>Target passed the allowlist check.</p>
    <p>If your browser does not follow automatically,
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect/trusted">Try another value</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
  </section>`));
});

module.exports = { vuln, router };
