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
  est: 'about 10 to 25 minutes',
  hint: 'The code allowlists URLs starting with https://pentrix.lab, but compares the raw string and accepts backslashes as separators. Browsers normalize backslash to slash.',
  hints: ["Intercept the redirect in Burp Proxy and send it to Repeater. The allowlist checks for 'https://', but URLs can use backslashes as separators too.", "In Repeater, probe what the server's check accepts. It inspects the raw string instead of the parsed hostname. Browsers treat backslash as a path separator, so the string the check reads and the host the browser resolves can disagree.", "In Repeater, craft a next value whose raw string starts like an allowlisted URL while its parsed hostname points somewhere else (Repeater's URL-encode option handles the special characters). The key insight: the server validates the string, the browser parses the URL, and those two can disagree on the destination."],
  tools: "BZ, C",
  how: 'A raw-string allowlist and a browser URL parser can disagree about the same URL. In Burp Repeater, explore separator spellings until the check passes but the destination the browser would resolve is not the trusted host.',
  link: '/redirect#redirect-backslash',
  start: 'In Burp Proxy, visit /redirect/trusted, submit the Partner URL form, and send the request to Repeater. Then experiment with the next parameter until the check passes but the destination is not the trusted host.',
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
    <p class="note">Think about which separator spellings a browser accepts in a URL,
    and how a raw-string prefix check reads those same spellings.</p>
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
