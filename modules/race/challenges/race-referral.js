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
  hints: ["Claim REF2026 once in the browser with Burp Proxy on, then send that claim POST to Repeater.", "In Repeater, duplicate the claim tab 10 times, select all the tabs, and choose Send group in parallel so the claims land together. Community Intruder is throttled and would spread the claims out past the check gap.", "Every request must land inside the check gap, so each one still sees 'not claimed' when it arrives."],
  tools: 'BZ, C, P',
  est: 'about 10 minutes',
  how: 'Claim the referral code with parallel POSTs at /race/referral (Repeater: duplicate the tab, then Send group in parallel) so the bonus lands twice.',
  link: '/race#race-referral',
  start: 'Browse to /race/referral with Burp Proxy on and claim REF2026 once, then send that POST to Repeater, duplicate the tab 10 times, and Send group in parallel so the claims all land before the first claim is recorded.',
};

// Challenge-local presentation: a clay card hero for the rewards screen.
function rewards(body) {
  return appShell('PenTrix Shop', body, { crumb: 'Rewards', mark: '◈', nav: ['Home', 'Catalog', 'Rewards', 'Cart'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <form method="POST" action="/race/reset" style="display:inline"><button type="submit" class="clay-btn clay-btn-secondary clay-btn-sm">Reset lab state</button></form></p>`;
}

router.get('/referral', (req, res) => {
  const r = shared.state(req).referral;
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
    ${payloadBlock('Burp Repeater: Send group in parallel', 'Send the claim POST to Repeater (Ctrl+R), duplicate the tab until you have 10 tabs of the same request, select them all, then right-click and choose Send group in parallel. Watch the responses.')}
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
  const s = shared.state(req);
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
