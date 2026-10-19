'use strict';
// CSRF & Clickjacking: forged cross-site requests against the fictional Postbox webmail app.
const express = require('express');
const { fixCta, brief, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner, difficultyPill  } = require('../../lib/page');
const { currentUser, emailOf } = require('./shared');

const challenges = [
  require('./challenges/email'),
  require('./challenges/clickjacking'),
  require('./challenges/json-csrf'),
  require('./challenges/referer-bypass'),
  require('./challenges/method-override-csrf'),
];

const router = express.Router();

// Quick-login. Module-level demo login, not a challenge: it lets students skip
// the auth module and start the CSRF flows as alice (user id 2).
router.get('/login/alice', (req, res) => {
  req.session.user = { id: 2, username: 'alice', role: 'user' };
  res.send(page('Logged in', `
    <h1>Logged in</h1>
    <div class="card">
      <p>You are now logged in as <b>alice</b> (user id 2).</p>
      <p>Current account email: <code>${esc(emailOf(req.session.user))}</code></p>
      <p>
        <a class="clay-btn clay-btn-primary clay-btn-sm" href="/csrf">Back to the CSRF module</a>
      </p>
    </div>
  `));
});

// GET /csrf -> module index page.
router.get('/', (req, res) => {
  const user = currentUser(req);
  const status = user
    ? `<p>Logged in as <b>${esc(user.username)}</b> (id ${esc(String(user.id))}). Current email: <code>${esc(emailOf(user))}</code></p>`
    : '<p>You are <b>not logged in</b>. Log in as alice to try the challenges.</p>';

  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3>${esc(v.name)} ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(v.link)}">Open challenge</a></p>
    </article>`).join('');

  // M11 break-then-fix: honest coming-soon note (additive, existing content untouched).
  const fixSectionHtml = `
    <section class="fix-mode-section">
      <h2>Break then fix</h2>
      <p class="dim">Fix mode is not available for this module yet. When it lands, you will be able to repair each challenge: edit the vulnerable code and the runner will check that the exploit is blocked while legitimate use still works.</p>
      ${challenges.map((c) => fixCta('csrf', c.vuln.id)).join('')}
    </section>`;
  res.send(page('CSRF & Clickjacking', `
    <h1>CSRF &amp; Clickjacking</h1>
    ${brief('Briefing', `
      <b>Cross-Site Request Forgery (CSRF)</b> abuses the fact that browsers
      automatically send your cookies with every request, even ones triggered by
      a <i>different</i> site. If an application changes state (password, email,
      delete) without proof that the request really came from its own pages, an
      attacker can forge that request from their own page and your browser will
      execute it while you are logged in.
      <br><br><b>Clickjacking</b> layers the attack visually: a page that can be
      embedded in someone else's <code>&lt;iframe&gt;</code> lets an attacker
      steer your clicks onto buttons you never saw.
      <br><br>Every challenge below is a page of <b>Postbox</b>, a small
      fictional webmail app, plus the attacker's page that targets it.
    `)}
    ${trackBanner(module.exports)}
    <div class="card">
      ${status}
      <p>
        <a class="clay-btn clay-btn-primary clay-btn-sm" href="/csrf/login/alice">Log in as alice</a>
      </p>
    </div>

    <h2>Postbox pages</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">Postbox pages used by the challenges</caption>
      <thead><tr><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Description</th></tr></thead>
      <tbody>
        <tr><td>GET</td><td><code>/csrf/change-email</code></td><td>Email settings</td></tr>
        <tr><td>GET</td><td><code>/csrf/framedemo</code></td><td>Prize page that embeds a Postbox page</td></tr>
        <tr><td>GET, POST</td><td><code>/csrf/vip-action</code></td><td>Account actions page</td></tr>
        <tr><td>GET</td><td><code>/csrf/json-email</code></td><td>Email API console</td></tr>
        <tr><td>POST</td><td><code>/csrf/api/email</code></td><td>Update email (JSON)</td></tr>
        <tr><td>GET</td><td><code>/csrf/nickname</code></td><td>Profile settings</td></tr>
        <tr><td>POST</td><td><code>/csrf/api/nickname</code></td><td>Update nickname</td></tr>
        <tr><td>GET, POST, DELETE</td><td><code>/csrf/account</code></td><td>Account status and closure</td></tr>
      </tbody>
    </table></div>

    <h2>Challenges</h2>
    <p>Five flaws hide in the pages above. Each card has a hint ladder: level 1
    nudges, level 2 teaches the technique, level 3 shows the shape of the
    request.</p>
    ${cards}
  ${fixSectionHtml}
`));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'csrf',
  name: 'CSRF & Clickjacking',
  tagline: 'Forge cross-site requests and frame the unframeable.',
  description: 'Learn how state-changing requests with no CSRF token let attackers act as you, how content-type confusion smuggles simple requests into JSON APIs, and how a missing X-Frame-Options header enables clickjacking.',
  difficulty: 'Beginner',
  track: 'Foundations',
  prerequisites: ['xss'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
