'use strict';
// Race-vote: one vote per name is enforced by a duplicate check, but the
// check and the insert are separated by an async gap, so parallel votes for
// the same name both pass the check and the name is counted twice.
const express = require('express');
const { page, esc, appShell, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
// Module-level race plumbing lives in ../shared.js (finisher-owned): the
// shared state object, the sleep/WINDOW race window, and reset.
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'race-vote',
  name: 'Vote Counted Twice',
  difficulty: 'Easy',
  hint: 'One vote per name is enforced by checking first, then recording. Send two votes for the same name in parallel.',
  hints: ["Votes check for duplicate names, but the check and the insert are not atomic. Capture the vote POST in Burp Proxy and send it to Repeater.", "Repeater can fire a whole group at once: duplicate the vote tab, select both tabs, and choose Send group in parallel so both votes for the same name land at the same instant. Community Intruder is throttled and would serialize the votes, so it cannot win this race.", "Watch the results table: more than one vote for one name proves the duplicate check lost the race."],
  tools: 'BZ, C',
  est: 'about 10 minutes',
  how: 'Send two votes for the same name at the same instant through Repeater (duplicate the tab, then Send group in parallel) so both pass the duplicate check.',
  link: '/race#race-vote',
  start: 'Burp Proxy: capture a vote POST for name=voter1, send it to Repeater (Ctrl+R), duplicate the tab, then Send group in parallel.',
};

// Challenge-local presentation: a clay card hero for the poll screen.
function poll(body) {
  return appShell('PollPulse', body, { crumb: 'Polls', mark: '◈', nav: ['Polls', 'Results', 'About'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <form method="POST" action="/race/reset" style="display:inline"><button type="submit" class="clay-btn clay-btn-secondary clay-btn-sm">Reset lab state</button></form></p>`;
}

router.get('/vote', (req, res) => {
  const votes = shared.state(req).votes;
  const rows = Object.entries(votes)
    .map(([name, n]) => `<tr><td>${esc(name)}</td><td>${n}</td></tr>`).join('')
    || '<tr><td colspan="2"><i>no votes yet</i></td></tr>';
  res.send(page('Poll: vote once', poll(`
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>PollPulse</b><span class="dim">Live poll</span></div>
      <h2>Best programming language (one vote per name)</h2>
      <form method="POST" action="/race/vote">
        <div class="clay-field">
          <label for="name">Your name</label>
          <input class="clay-input" type="text" id="name" name="name" value="voter1" placeholder="your name" autocomplete="off">
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Vote</button>
      </form>
      <h3>Votes</h3>
      <div class="tbl-scroll"><table class="tbl"><thead><tr><th scope="col">Name</th><th scope="col">Votes</th></tr></thead><tbody>${rows}</tbody></table></div>
    </section>
    ${hintLadder(vuln)}
    <h2>Test it yourself</h2>
    <p>The duplicate check races the insert. Two parallel votes for the same name both get recorded:</p>
    ${payloadBlock('Burp Repeater: Send group in parallel', 'Send the vote POST to Repeater (Ctrl+R), duplicate the tab so you have two identical votes for the same name, select both tabs, right-click and choose Send group in parallel. Check the results table.')}
    ${backLinks()}
  `)));
});

router.post('/vote', async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40);
  if (!name) {
    return res.status(400).send(page('Vote', poll(`
      <section class="clay-card">
        <h2>Vote</h2>
        <p>A name is required.</p>
        ${backLinks()}
      </section>
    `)));
  }
  const s = shared.state(req);
  // VULN: "has this name voted?" is checked, then an await, then the vote is
  // recorded; parallel votes for the same name both pass the check.
  if (s.votes[name]) {
    return res.send(page('Vote', poll(`
      <section class="clay-card">
        <h2>Already voted</h2>
        <p>${esc(name)} has already voted. One vote per name.</p>
        ${backLinks()}
      </section>
    `)));
  }
  await shared.sleep(shared.WINDOW());
  s.votes[name] = (s.votes[name] || 0) + 1;

  let flagHtml = '';
  if (s.votes[name] > 1 && !captured(req, 'race', 'race-vote')) {
    flagHtml = flagBox(award(req, 'race', 'race-vote'));
    flagHtml += fixPanel('race', 'race-vote');
  }
  res.send(page('Vote recorded', poll(`
    <section class="clay-card">
      <h2>Vote recorded for ${esc(name)}</h2>
      <p>Votes for ${esc(name)}: <b>${s.votes[name]}</b></p>
      ${s.votes[name] > 1 ? '<p><b>One name, two votes.</b> The duplicate check raced the insert.</p>' : ''}
      ${flagHtml}
      ${backLinks()}
    </section>
  `)));
});

module.exports = { vuln, router };
