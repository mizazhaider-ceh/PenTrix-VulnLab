'use strict';
// Race-referral: the referral code REF2026 pays 50 points once, but the
// "already claimed?" check and the claim recording are separated by an async
// gap, so parallel claims all pass the check and the bonus lands twice.
const express = require('express');
const { page, esc, appShell, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
// Module-level race plumbing lives in ../shared.js (finisher-owned): the
// shared state object, the sleep/WINDOW race window, and reset.
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'race-referral',
  name: 'Referral Bonus Claimed Twice',
  difficulty: 'Medium',
  hint: 'The referral code REF2026 pays 50 points once. The "already claimed" check has a gap before the claim is recorded.',
  hints: ["The referral bonus is once per user. What if you claim twice at once?", "Parallel claims both see 'not claimed' and both award the bonus.", "Fire parallel claims. Bonus lands twice."],
  tools: 'P, C',
  how: 'Claim the referral code with parallel POSTs at /race/referral so the bonus lands twice.',
  link: '/race#race-referral',
  start: 'curl http://localhost:3000/race/referral\nseq 1 10 | xargs -P10 -I{} curl -s -X POST http://localhost:3000/race/referral -d \'code=REF2026\'',
};

// Challenge-local presentation: a clay card hero for the rewards screen.
function rewards(body) {
  return appShell('PenTrix Shop', body, { crumb: 'Rewards', mark: '◈', nav: ['Home', 'Catalog', 'Rewards', 'Cart'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race/reset">Reset lab state</a></p>`;
}

router.get('/referral', (req, res) => {
  const r = shared.state().referral;
  res.send(page('Referral bonus', rewards(`
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>Rewards</b><span class="dim">Referral program</span></div>
      <h2>Referral program</h2>
      <p>Your referral code: <b>REF2026</b> (50 points, claimable once)</p>
      <p>Claims so far: <b>${r.claims}</b> · Points paid out: <b>${r.points}</b></p>
      <form method="POST" action="/race/referral">
        <div class="clay-field">
          <label for="code">Referral code</label>
          <input class="clay-input" type="text" id="code" name="code" value="REF2026" placeholder="referral code" autocomplete="off">
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Claim bonus</button>
      </form>
    </section>
    ${hintLadder(vuln)}
    <h2>Test it yourself</h2>
    <p>Claim it with parallel requests before the first claim is recorded:</p>
    ${payloadBlock('Parallel claims', `seq 1 10 | xargs -P10 -I{} curl -s -X POST http://localhost:3000/race/referral -d 'code=REF2026'`)}
    ${backLinks()}
  `)));
});

router.post('/referral', async (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  if (code !== 'REF2026') {
    return res.send(page('Referral', rewards(`
      <section class="clay-card">
        <h2>Invalid code</h2>
        <p>That referral code does not exist.</p>
        ${backLinks()}
      </section>
    `)));
  }
  const s = shared.state();
  // VULN: "already claimed?" check, await, then record the claim; concurrent
  // claims all pass the check and the bonus is paid out multiple times.
  if (s.referral.claimed[code]) {
    return res.send(page('Referral', rewards(`
      <section class="clay-card">
        <h2>Already claimed</h2>
        <p>This referral bonus was already claimed.</p>
        ${backLinks()}
      </section>
    `)));
  }
  await shared.sleep(shared.WINDOW());
  s.referral.claimed[code] = true;
  s.referral.claims += 1;
  s.referral.points += 50;

  let flagHtml = '';
  if (s.referral.claims > 1 && !captured(req, 'race', 'race-referral')) {
    flagHtml = flagBox(award(req, 'race', 'race-referral'));
    flagHtml += fixPanel('race', 'race-referral');
  }
  res.send(page('Referral claimed', rewards(`
    <section class="clay-card">
      <h2>50 points claimed</h2>
      <p>Total claims: <b>${s.referral.claims}</b> · Points paid out: <b>${s.referral.points}</b></p>
      ${s.referral.claims > 1 ? '<p><b>The one-time bonus was claimed more than once.</b></p>' : ''}
      ${flagHtml}
      ${backLinks()}
    </section>
  `)));
});

module.exports = { vuln, router };
