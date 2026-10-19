'use strict';
// Race-balance: the wallet transfer checks the balance ("can it cover this?")
// and applies the debit as two separate steps with an async gap between them,
// so parallel transfers each pass the check against the same starting balance
// and the balance goes negative (a double-spend).
const express = require('express');
const { page, esc, appShell, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();

const vuln = {
  id: 'race-balance',
  name: 'Double-Spend the Balance',
  difficulty: 'Medium',
  hint: 'The balance check and the debit are two separate steps with a gap between them. Two transfers of the full balance, at the same time...',
  hints: ["Transfers check the balance, then debit. What if the check and debit are separated by time?", "The await between check and debit is the window. Parallel transfers both pass the check.", "Run parallel transfers that together exceed the balance. The balance goes negative."],
  tools: 'P, C',
  how: 'Send parallel transfers that together exceed the $100 balance and drive it negative.',
  link: '/race#race-balance',
  start: 'curl http://localhost:3000/race/transfer',
};

// Challenge-local presentation: a clay card hero for this wallet screen.
function wallet(crumb, body) {
  return appShell('PenTrix Wallet', body, { crumb, mark: '◈', nav: ['Home', 'Wallet', 'Activity', 'Settings'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race/reset">Reset lab state</a></p>`;
}

router.get('/transfer', (req, res) => {
  const balance = shared.state().balance;
  const ledger = shared.state().ledger
    .map((t) => `<li>$${t.amount.toFixed(2)} to ${esc(t.to)}</li>`).join('')
    || '<li><i>none yet</i></li>';
  res.send(page('Balance transfer', wallet('Send money', `
    <section class="clay-card">
      <div class="card-top"><span class="orb" aria-hidden="true">◈</span><b>Wallet</b><span class="dim">Send money</span></div>
      <h2>Wallet transfer</h2>
      <p>Current balance: <b>$${balance.toFixed(2)}</b></p>
      <form method="POST" action="/race/transfer">
        <div class="clay-field">
          <label for="to">Recipient</label>
          <input class="clay-input" id="to" name="to" type="text" value="attacker">
        </div>
        <div class="clay-field">
          <label for="amount">Amount</label>
          <input class="clay-input" id="amount" name="amount" type="text" value="100">
        </div>
        <button type="submit" class="clay-btn clay-btn-primary">Transfer</button>
      </form>
      <h3>Ledger</h3><ul>${ledger}</ul>
    </section>
    ${hintLadder(vuln)}
    <h2>Test it yourself</h2>
    <p>The balance is $100. Send 20 parallel transfers of $100 and watch the balance go negative:</p>
    ${payloadBlock('Parallel transfers', "seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/transfer -d 'to=attacker&amount=100'")}
    ${backLinks()}
  `)));
});

router.post('/transfer', async (req, res) => {
  const to = String(req.body.to || 'attacker').slice(0, 40);
  const amount = parseFloat(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).send(page('Transfer', wallet('Send money', `
      <section class="clay-card">
        <p class="clay-err" role="alert">Amount must be a positive number.</p>
        ${backLinks()}
      </section>
    `)));
  }
  // VULN: balance is checked, then an await happens, then the debit is applied;
  // parallel transfers each pass the check against the same starting balance.
  if (shared.state().balance < amount) {
    return res.status(200).send(page('Transfer', wallet('Send money', `
      <section class="clay-card">
        <h2>Insufficient funds</h2>
        <p>Balance $${shared.state().balance.toFixed(2)} cannot cover $${amount.toFixed(2)}.</p>
        ${backLinks()}
      </section>
    `)));
  }
  await shared.sleep(shared.WINDOW());
  const s = shared.state();
  s.balance -= amount;
  s.ledger.push({ to, amount });

  let flagHtml = '';
  if (s.balance < 0 && !captured(req, 'race', 'race-balance')) {
    flagHtml = flagBox(award(req, 'race', 'race-balance'));
    flagHtml += fixPanel('race', 'race-balance');
  }
  res.send(page('Transfer done', wallet('Send money', `
    <section class="clay-card">
      <h2>Transferred $${amount.toFixed(2)} to ${esc(to)}</h2>
      <p>New balance: <b>$${s.balance.toFixed(2)}</b></p>
      ${s.balance < 0 ? '<p><b>Balance is negative:</b> more money left the wallet than it ever held. Double-spend achieved.</p>' : ''}
      ${flagHtml}
      ${backLinks()}
    </section>
  `)));
});

module.exports = { vuln, router };
