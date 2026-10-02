// PenTrix VulnLab module: Race Conditions (race)
// Eight time-of-check to time-of-use labs. Every handler awaits a short sleep
// between the safety check and the state change, so parallel requests interleave
// on Node's event loop and the invariant breaks. State is module-level so all
// requests in this process share it.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

// Widen the check-to-use window so parallel requests reliably interleave even
// when process-spawn stagger separates them; a single click only waits ~0.2s.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WINDOW = () => 150 + Math.floor(Math.random() * 101); // 150-250ms

function freshState() {
  return {
    coupon: { used: false, redeems: 0, credit: 0 },
    balance: 100,
    ledger: [],
    votes: {},                 // name -> number of votes recorded
    referral: { claimed: {}, claims: 0, points: 0 },
    accounts: [],              // { username, password }
    files: {},                 // name -> { content, timer }
    ratelimit: { count: 0 },
    stock: { stock: 5, sold: 0 },
  };
}
let R = freshState();

function resetRace() {
  for (const name of Object.keys(R.files)) clearTimeout(R.files[name].timer);
  R = freshState();
}

const BRIEF_HTML = `
<p><b>What is a race condition?</b> The server checks something ("is this coupon
unused?"), then acts on it ("redeem it") as two separate steps. If two requests
arrive at the same time, both can pass the check before either one acts, and the
invariant the check was protecting gets violated.</p>
<p><b>How to attack these labs:</b> send many identical requests <b>in
parallel</b>. A single request at a time behaves correctly; twenty at once do
not. Each challenge page tells you the exact command, e.g.</p>
<pre><code>seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/coupon/redeem</code></pre>
<p>Use the <b>Reset lab state</b> link before each attempt so you start from a
clean slate. Flags are awarded only when the invariant is actually broken.</p>`;

// ---------------------------------------------------------------- index page
const VULNS = [
  {
    id: 'race-coupon', name: 'Single-Use Coupon Redeemed Twice', difficulty: 'Medium',
    path: 'coupon',
    hint: 'The coupon is marked "used" only after an async gap. What happens when 20 requests check "is it used?" at the same moment?',
    how: 'Fire parallel POSTs at /race/coupon/redeem so the coupon is redeemed more than once.',
  },
  {
    id: 'race-balance', name: 'Double-Spend the Balance', difficulty: 'Medium',
    path: 'transfer',
    hint: 'The balance check and the debit are two separate steps with a gap between them. Two transfers of the full balance, at the same time...',
    how: 'Send parallel transfers that together exceed the $100 balance and drive it negative.',
  },
  {
    id: 'race-vote', name: 'Vote Counted Twice', difficulty: 'Easy',
    path: 'vote',
    hint: 'One vote per name is enforced by checking first, then recording. Send two votes for the same name in parallel.',
    how: 'POST two votes for the same name at /race/vote at the same instant so both pass the duplicate check.',
  },
  {
    id: 'race-referral', name: 'Referral Bonus Claimed Twice', difficulty: 'Medium',
    path: 'referral',
    hint: 'The referral code REF2026 pays 50 points once. The "already claimed" check has a gap before the claim is recorded.',
    how: 'Claim the referral code with parallel POSTs at /race/referral so the bonus lands twice.',
  },
  {
    id: 'race-register', name: 'Duplicate Username Registration', difficulty: 'Medium',
    path: 'register',
    hint: 'Usernames must be unique: the code checks, then inserts. Two registrations of the same name racing each other both pass the check.',
    how: 'Register the same username with parallel POSTs at /race/register so two accounts exist with one name.',
  },
  {
    id: 'race-upload-scan', name: 'Beat the AV Scan (TOCTOU)', difficulty: 'Hard',
    path: 'upload',
    hint: 'Uploaded files are served immediately, but a simulated AV scan deletes them 2 seconds later. The file exists in a window where it should not.',
    how: 'Upload a file at /race/upload, then fetch /race/files/<name> before the 2-second scan deletes it.',
  },
  {
    id: 'race-ratelimit', name: 'Burst Through the Rate Limit', difficulty: 'Medium',
    path: 'ratelimit',
    hint: 'The limiter allows 5 requests, but it counts each request only after an async gap. A parallel burst all reads "0 used" at once.',
    how: 'Hit POST /race/ratelimit/hit with 20 parallel requests so more than 5 are allowed in one window.',
  },
  {
    id: 'race-stock', name: 'Oversell the Stock', difficulty: 'Easy',
    path: 'stock',
    hint: 'Only 5 items in stock. The stock check and the decrement are separated by a gap. Two orders of 5 at the same time...',
    how: 'Buy with parallel POSTs at /race/stock whose quantities total more than the 5 items in stock.',
  },
];

router.get('/', (req, res) => {
  const rows = VULNS.map((v) => {
    const done = captured(req, 'race', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/race/${v.path}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('Race Conditions', `
    ${brief('Module briefing', BRIEF_HTML)}
    <h2>Challenges</h2>
    ${rows}
    <p><a class="btn ghost" href="/race/reset">Reset lab state</a>
    <span class="dim">Resets coupons, balances, votes, accounts, uploads, limits and stock.</span></p>
  `));
});

router.get('/reset', (req, res) => {
  resetRace();
  res.send(page('Race lab reset', `
    <h2>State reset</h2>
    <p>All race state is back to its initial values.</p>
    <p><a href="/race">Back to the Race Conditions module</a></p>
  `));
});

const backLink = `<p><a href="/race">Back to module</a> · <a href="/race/reset">Reset lab state</a></p>`;

// ------------------------------------------------------- v1: single-use coupon
router.get('/coupon', (req, res) => {
  res.send(page('Single-use coupon', `
    <h2>Coupon: RACE10 ($10 credit, one use only)</h2>
    <p>Coupon used: <b>${R.coupon.used}</b> · Redeemed: <b>${R.coupon.redeems}</b> time(s) ·
    Credit issued: <b>$${R.coupon.credit}</b></p>
    <form method="POST" action="/race/coupon/redeem">
      <button type="submit">Redeem coupon</button>
    </form>
    <hr />
    <p><b>Attack:</b> one click redeems it once. Twenty parallel requests redeem it
    more than once:</p>
    <pre><code>seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/coupon/redeem</code></pre>
    ${backLink}
  `));
});

router.post('/coupon/redeem', async (req, res) => {
  // VULN: the "already used?" check and the "mark used" write are separated by
  // an await, so parallel requests all see used=false before any write lands.
  if (R.coupon.used) {
    return res.send(page('Coupon', `
      <h2>Already redeemed</h2>
      <p>This coupon was already used. <a href="/race/reset">Reset</a> to try again.</p>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.coupon.used = true;
  R.coupon.redeems += 1;
  R.coupon.credit += 10;

  let flagHtml = '';
  if (R.coupon.redeems > 1 && !captured(req, 'race', 'race-coupon')) {
    flagHtml = flagBox(award(req, 'race', 'race-coupon'));
  }
  res.send(page('Coupon redeemed', `
    <h2>Coupon redeemed</h2>
    <p>$10 credit issued. Total redemptions so far: <b>${R.coupon.redeems}</b>.</p>
    ${R.coupon.redeems > 1 ? '<p><b>The one-use coupon was redeemed more than once.</b> The check raced the write.</p>' : ''}
    ${flagHtml}
    ${backLink}
  `));
});

// ------------------------------------------------------- v2: balance transfer
router.get('/transfer', (req, res) => {
  const ledger = R.ledger.map((t) => `<li>$${t.amount.toFixed(2)} to ${esc(t.to)}</li>`).join('') || '<li><i>none yet</i></li>';
  res.send(page('Balance transfer', `
    <h2>Wallet transfer</h2>
    <p>Current balance: <b>$${R.balance.toFixed(2)}</b></p>
    <form method="POST" action="/race/transfer">
      <input type="text" name="to" placeholder="recipient" value="attacker" />
      <input type="text" name="amount" placeholder="amount" value="100" size="8" />
      <button type="submit">Transfer</button>
    </form>
    <h3>Ledger</h3><ul>${ledger}</ul>
    <hr />
    <p><b>Attack:</b> the balance is $100. Send 20 parallel transfers of $100 and
    watch the balance go negative:</p>
    <pre><code>seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/transfer -d 'to=attacker&amount=100'</code></pre>
    ${backLink}
  `));
});

router.post('/transfer', async (req, res) => {
  const to = String(req.body.to || 'attacker').slice(0, 40);
  const amount = parseFloat(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).send(page('Transfer', `<p>Amount must be a positive number.</p>${backLink}`));
  }
  // VULN: balance is checked, then an await happens, then the debit is applied;
  // parallel transfers each pass the check against the same starting balance.
  if (R.balance < amount) {
    return res.send(page('Transfer', `
      <h2>Insufficient funds</h2>
      <p>Balance $${R.balance.toFixed(2)} cannot cover $${amount.toFixed(2)}.</p>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.balance -= amount;
  R.ledger.push({ to, amount });

  let flagHtml = '';
  if (R.balance < 0 && !captured(req, 'race', 'race-balance')) {
    flagHtml = flagBox(award(req, 'race', 'race-balance'));
  }
  res.send(page('Transfer done', `
    <h2>Transferred $${amount.toFixed(2)} to ${esc(to)}</h2>
    <p>New balance: <b>$${R.balance.toFixed(2)}</b></p>
    ${R.balance < 0 ? '<p><b>Balance is negative:</b> more money left the wallet than it ever held. Double-spend achieved.</p>' : ''}
    ${flagHtml}
    ${backLink}
  `));
});

// ----------------------------------------------------------------- v3: voting
router.get('/vote', (req, res) => {
  const rows = Object.entries(R.votes)
    .map(([name, n]) => `<tr><td>${esc(name)}</td><td>${n}</td></tr>`).join('')
    || '<tr><td colspan="2"><i>no votes yet</i></td></tr>';
  res.send(page('Poll: vote once', `
    <h2>Best programming language (one vote per name)</h2>
    <form method="POST" action="/race/vote">
      <input type="text" name="name" placeholder="your name" value="voter1" />
      <button type="submit">Vote</button>
    </form>
    <h3>Votes</h3>
    <table class="tbl"><tr><th>Name</th><th>Votes</th></tr>${rows}</table>
    <hr />
    <p><b>Attack:</b> the duplicate check races the insert. Two parallel votes
    for the same name both get recorded:</p>
    <pre><code>seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/vote -d 'name=voter1'</code></pre>
    ${backLink}
  `));
});

router.post('/vote', async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40);
  if (!name) {
    return res.status(400).send(page('Vote', `<p>A name is required.</p>${backLink}`));
  }
  // VULN: "has this name voted?" is checked, then an await, then the vote is
  // recorded; parallel votes for the same name both pass the check.
  if (R.votes[name]) {
    return res.send(page('Vote', `
      <h2>Already voted</h2>
      <p>${esc(name)} has already voted. One vote per name.</p>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.votes[name] = (R.votes[name] || 0) + 1;

  let flagHtml = '';
  if (R.votes[name] > 1 && !captured(req, 'race', 'race-vote')) {
    flagHtml = flagBox(award(req, 'race', 'race-vote'));
  }
  res.send(page('Vote recorded', `
    <h2>Vote recorded for ${esc(name)}</h2>
    <p>Votes for ${esc(name)}: <b>${R.votes[name]}</b></p>
    ${R.votes[name] > 1 ? '<p><b>One name, two votes.</b> The duplicate check raced the insert.</p>' : ''}
    ${flagHtml}
    ${backLink}
  `));
});

// ------------------------------------------------------------- v4: referrals
router.get('/referral', (req, res) => {
  res.send(page('Referral bonus', `
    <h2>Referral program</h2>
    <p>Your referral code: <b>REF2026</b> (50 points, claimable once)</p>
    <p>Claims so far: <b>${R.referral.claims}</b> · Points paid out: <b>${R.referral.points}</b></p>
    <form method="POST" action="/race/referral">
      <input type="text" name="code" placeholder="referral code" value="REF2026" />
      <button type="submit">Claim bonus</button>
    </form>
    <hr />
    <p><b>Attack:</b> claim it with parallel requests before the first claim is recorded:</p>
    <pre><code>seq 1 10 | xargs -P10 -I{} curl -s -X POST http://localhost:3000/race/referral -d 'code=REF2026'</code></pre>
    ${backLink}
  `));
});

router.post('/referral', async (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  if (code !== 'REF2026') {
    return res.send(page('Referral', `<h2>Invalid code</h2><p>That referral code does not exist.</p>${backLink}`));
  }
  // VULN: "already claimed?" check, await, then record the claim; concurrent
  // claims all pass the check and the bonus is paid out multiple times.
  if (R.referral.claimed[code]) {
    return res.send(page('Referral', `
      <h2>Already claimed</h2>
      <p>This referral bonus was already claimed.</p>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.referral.claimed[code] = true;
  R.referral.claims += 1;
  R.referral.points += 50;

  let flagHtml = '';
  if (R.referral.claims > 1 && !captured(req, 'race', 'race-referral')) {
    flagHtml = flagBox(award(req, 'race', 'race-referral'));
  }
  res.send(page('Referral claimed', `
    <h2>50 points claimed</h2>
    <p>Total claims: <b>${R.referral.claims}</b> · Points paid out: <b>${R.referral.points}</b></p>
    ${R.referral.claims > 1 ? '<p><b>The one-time bonus was claimed more than once.</b></p>' : ''}
    ${flagHtml}
    ${backLink}
  `));
});

// ------------------------------------------------------------- v5: register
router.get('/register', (req, res) => {
  const rows = R.accounts.map((a) => `<tr><td>${esc(a.username)}</td></tr>`).join('')
    || '<tr><td><i>no accounts yet</i></td></tr>';
  res.send(page('Register', `
    <h2>Create an account (usernames must be unique)</h2>
    <form method="POST" action="/race/register">
      <input type="text" name="username" placeholder="username" value="racer" />
      <input type="password" name="password" placeholder="password" value="hunter2" />
      <button type="submit">Register</button>
    </form>
    <h3>Accounts (${R.accounts.length})</h3>
    <table class="tbl"><tr><th>Username</th></tr>${rows}</table>
    <hr />
    <p><b>Attack:</b> register the same username twice in parallel; the uniqueness
    check races the insert:</p>
    <pre><code>seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/register -d 'username=racer&password=hunter2'</code></pre>
    ${backLink}
  `));
});

router.post('/register', async (req, res) => {
  const username = String(req.body.username || '').trim().slice(0, 40);
  const password = String(req.body.password || '').slice(0, 80);
  if (!username) {
    return res.status(400).send(page('Register', `<p>Username is required.</p>${backLink}`));
  }
  // VULN: uniqueness is checked, then an await, then the row is inserted;
  // parallel registrations of the same name both pass the check.
  if (R.accounts.some((a) => a.username === username)) {
    return res.send(page('Register', `
      <h2>Username taken</h2>
      <p>${esc(username)} is already registered.</p>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.accounts.push({ username, password });
  const dupes = R.accounts.filter((a) => a.username === username).length;

  let flagHtml = '';
  if (dupes > 1 && !captured(req, 'race', 'race-register')) {
    flagHtml = flagBox(award(req, 'race', 'race-register'));
  }
  res.send(page('Registered', `
    <h2>Account created: ${esc(username)}</h2>
    <p>Accounts with this username: <b>${dupes}</b></p>
    ${dupes > 1 ? '<p><b>Duplicate usernames exist.</b> The uniqueness check raced the insert.</p>' : ''}
    ${flagHtml}
    ${backLink}
  `));
});

// ------------------------------------------------------- v6: upload vs AV scan
router.get('/upload', (req, res) => {
  const live = Object.keys(R.files).map((n) => `<li><a href="/race/files/${encodeURIComponent(n)}">${esc(n)}</a></li>`).join('')
    || '<li><i>no live files (the AV scan deletes uploads after 2 seconds)</i></li>';
  res.send(page('Upload (AV scanned)', `
    <h2>File upload with AV scan</h2>
    <p>Uploaded files are served <b>immediately</b>, but a simulated antivirus
    scan deletes each file <b>2 seconds</b> after upload. There is a window where
    the file exists but should not.</p>
    <form method="POST" action="/race/upload">
      <input type="text" name="filename" placeholder="filename" value="secret.txt" /><br /><br />
      <textarea name="content" rows="4" cols="60" placeholder="file content">top secret lab data</textarea><br /><br />
      <button type="submit">Upload</button>
    </form>
    <h3>Live files</h3><ul>${live}</ul>
    <hr />
    <p><b>Attack:</b> upload, then fetch the file URL within 2 seconds, before the
    scan deletes it:</p>
    <pre><code>curl -s -X POST http://localhost:3000/race/upload -d 'filename=secret.txt&content=top+secret+lab+data'
curl -s http://localhost:3000/race/files/secret.txt</code></pre>
    ${backLink}
  `));
});

router.post('/upload', (req, res) => {
  const filename = String(req.body.filename || 'upload.txt').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 60) || 'upload.txt';
  const content = String(req.body.content || '').slice(0, 5000);
  if (R.files[filename]) clearTimeout(R.files[filename].timer);
  // VULN (TOCTOU): the file is servable the instant it is stored; the "scan"
  // that deletes it only runs 2 seconds later, leaving a fetchable window.
  R.files[filename] = {
    content,
    timer: setTimeout(() => { delete R.files[filename]; }, 2000),
  };
  res.send(page('Uploaded', `
    <h2>Uploaded: ${esc(filename)}</h2>
    <p>The file is live <b>now</b>. The AV scan deletes it in 2 seconds.</p>
    <p><a class="btn" href="/race/files/${encodeURIComponent(filename)}">Fetch it before the scan</a></p>
    ${backLink}
  `));
});

router.get('/files/:name', (req, res) => {
  const name = String(req.params.name || '').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 60);
  const f = R.files[name];
  if (!f) {
    return res.status(404).send(page('File gone', `
      <h2>404: file not found</h2>
      <p>It was never uploaded, or the AV scan already deleted it. Upload again
      and fetch faster.</p>
      ${backLink}
    `));
  }
  // Fetching a live file means you beat the scan: the TOCTOU window was real.
  const flag = award(req, 'race', 'race-upload-scan');
  res.send(page('File: ' + name, `
    <h2>${esc(name)}</h2>
    <p><b>You fetched the file before the AV scan deleted it.</b> For 2 seconds
    it was served even though policy says it should not exist.</p>
    <pre>${esc(f.content)}</pre>
    ${flagBox(flag)}
    ${backLink}
  `));
});

// ---------------------------------------------------------- v7: rate limiter
router.get('/ratelimit', (req, res) => {
  res.send(page('Rate-limited API', `
    <h2>API endpoint (limit: 5 requests)</h2>
    <p>Requests counted in this window: <b>${R.ratelimit.count}</b></p>
    <form method="POST" action="/race/ratelimit/hit">
      <button type="submit">Send one request</button>
    </form>
    <hr />
    <p><b>Attack:</b> click once and you are counted. Send 20 at the same instant
    and the counter cannot keep up:</p>
    <pre><code>seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/ratelimit/hit</code></pre>
    ${backLink}
  `));
});

router.post('/ratelimit/hit', async (req, res) => {
  // VULN: the "under the limit?" check runs, then an await, and only then is
  // the counter incremented; a parallel burst all reads the old counter value.
  if (R.ratelimit.count >= 5) {
    return res.status(429).send(page('Rate limited', `
      <h2>429: too many requests</h2>
      <p>The limit of 5 requests was reached.</p>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.ratelimit.count += 1;

  let flagHtml = '';
  if (R.ratelimit.count > 5 && !captured(req, 'race', 'race-ratelimit')) {
    flagHtml = flagBox(award(req, 'race', 'race-ratelimit'));
  }
  res.send(page('API response', `
    <h2>200: request allowed (#${R.ratelimit.count})</h2>
    ${R.ratelimit.count > 5 ? '<p><b>More than 5 requests were allowed in one window.</b> The burst beat the counter.</p>' : ''}
    ${flagHtml}
    ${backLink}
  `));
});

// ---------------------------------------------------------------- v8: stock
router.get('/stock', (req, res) => {
  res.send(page('Limited stock shop', `
    <h2>Gadget (only 5 in stock)</h2>
    <p>Items left: <b>${R.stock.stock}</b> · Items sold: <b>${R.stock.sold}</b></p>
    <form method="POST" action="/race/stock/buy">
      <input type="text" name="qty" placeholder="quantity" value="5" size="6" />
      <button type="submit">Buy now</button>
    </form>
    <hr />
    <p><b>Attack:</b> two parallel orders of 5 when only 5 exist. The stock check
    races the decrement and the shop oversells:</p>
    <pre><code>seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/stock/buy -d 'qty=5'</code></pre>
    ${backLink}
  `));
});

router.post('/stock/buy', async (req, res) => {
  const qty = parseInt(req.body.qty, 10);
  if (!Number.isInteger(qty) || qty <= 0) {
    return res.status(400).send(page('Buy', `<p>Quantity must be a positive whole number.</p>${backLink}`));
  }
  // VULN: "enough stock?" is checked, then an await, then stock is decremented;
  // parallel orders each see the pre-sale stock level.
  if (R.stock.stock < qty) {
    return res.send(page('Buy', `
      <h2>Out of stock</h2>
      <p>Only ${R.stock.stock} left; you asked for ${qty}.</p>
      ${backLink}
    `));
  }
  await sleep(WINDOW());
  R.stock.stock -= qty;
  R.stock.sold += qty;

  let flagHtml = '';
  if (R.stock.sold > 5 && !captured(req, 'race', 'race-stock')) {
    flagHtml = flagBox(award(req, 'race', 'race-stock'));
  }
  res.send(page('Order placed', `
    <h2>Order placed: ${qty} item(s)</h2>
    <p>Stock left: <b>${R.stock.stock}</b> · Total sold: <b>${R.stock.sold}</b> (started with 5)</p>
    ${R.stock.sold > 5 ? '<p><b>Oversold:</b> more items were sold than ever existed in stock.</p>' : ''}
    ${flagHtml}
    ${backLink}
  `));
});

module.exports = {
  id: 'race',
  name: 'Race Conditions',
  tagline: 'Check-then-act flaws: win the race between the check and the use.',
  description: 'Eight time-of-check to time-of-use vulnerabilities. Each handler pauses briefly between verifying a condition and acting on it, so parallel requests interleave and break the invariant: single-use coupons redeemed twice, negative balances, double votes, duplicate accounts, a file fetched before the AV scan deletes it, a burst through a rate limit, and oversold stock.',
  difficulty: 'Mixed',
  vulns: VULNS.map(({ id, name, difficulty, hint, how }) => ({ id, name, difficulty, hint, how })),
  router,
};
