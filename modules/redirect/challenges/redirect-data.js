'use strict';
// data: Scheme Honored (redirect-data): GET /redirect/data redirects to the raw
// ?next= value with no scheme allowlist. A data:text/html URL smuggles a whole
// attacker-controlled document through the redirect, and the flag lands when
// the server honors it in the Location header.
const express = require('express');
const { page, esc, flagBox, fixPanel, hintLadder } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'redirect-data',
  name: 'data: Scheme Honored',
  difficulty: 'Medium',
  hint: 'Same sink, different scheme: data: URLs let you smuggle a whole HTML document through the redirect.',
  hints: ["data: URLs can hold HTML. What if the redirect goes to one?", "A data:text/html URL renders as a page. It's a redirect to attacker content.", "Send a data: URL that carries a full HTML document as the redirect target. The key insight: the server honors any scheme in the Location header, so the redirect becomes a delivery channel for attacker-controlled content."],
  tools: "C",
  how: 'Request /redirect/data?next=data:text/html,<script>alert(1)</script> (URL-encoded) and check the Location header.',
  link: '/redirect#redirect-data',
  start: 'curl -i "http://localhost:3000/redirect/data?next=data:text/html,%3Cscript%3Ealert(1)%3C/script%3E"',
};

const APP = 'ShareLink';

function entryPage() {
  return page('Redirect: data: scheme', `
  <section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>${APP}</b><span class="dim">Share redirect</span></div>
    <h2>Share this link</h2>
    <p>This share endpoint redirects to <code>next</code>. Same missing scheme
    check as the promo endpoint, different payload.</p>
    <form method="GET" action="/redirect/data">
      <div class="clay-field">
        <label for="next">Destination URL</label>
        <input class="clay-input" id="next" name="next" type="text" size="60" placeholder="https://example.com/welcome" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Go</button>
    </form>
    <p class="note">Try <code>?next=data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;</code>
    (URL-encoded) and inspect the <code>Location</code> header.</p>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
  </section>
  ${hintLadder(vuln)}`);
}

router.get('/data', (req, res) => {
  const next = req.query.next;
  if (next === undefined) {
    return res.send(entryPage());
  }
  const target = String(next);
  // VULN: the Location header is set from user input with no scheme allowlist.
  let flagHtml = '';
  if (/^data:/i.test(target)) {
    const flag = award(req, 'redirect', 'redirect-data');
    flagHtml = `<hr /><p>The server honored a <code>data:</code> URL in the
      <code>Location</code> header. A <code>data:text/html</code> URL smuggles a
      whole attacker-controlled document through the redirect.</p>${flagBox(flag)}${fixPanel('redirect', 'redirect-data')}`;
  }
  // Answers with a real 302 plus a readable body, so `curl -i` shows the
  // Location header and the explanation page at the same time.
  res.status(302).set('Location', target);
  res.send(page('Redirecting', `
  <section class="clay-card">
    <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>${APP}</b><span class="dim">Redirecting</span></div>
    <h2>Redirecting...</h2>
    <p>If your browser does not follow automatically,
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(target)}">click here</a>.</p>
    ${flagHtml}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect/data">Try another value</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redirect">Back to the module</a></p>
  </section>`));
});

module.exports = { vuln, router };
