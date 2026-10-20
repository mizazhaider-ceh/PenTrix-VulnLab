'use strict';
// Duplicate Username Registration: the uniqueness check and the insert are
// separated by an async gap, so two parallel signups for the same username
// both pass the check and both get inserted.
const express = require('express');
const { page, esc, appShell, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award, captured } = require('../../../lib/flags');
const shared = require('../shared');

const router = express.Router();
// Router-scoped form parsing (same as the original race router).
router.use(express.urlencoded({ extended: false }));

const vuln = {
  id: 'race-register',
  name: 'Duplicate Username Registration',
  difficulty: 'Medium',
  hint: 'Usernames must be unique: the code checks, then inserts. Two registrations of the same name racing each other both pass the check.',
  hints: ["Usernames must be unique. But the uniqueness check can be raced. Confirm in Burp Repeater that one signup with a fresh name works and shows the accounts table.", "Repeater sends one request at a time, and a race needs many at once. Duplicate the signup Repeater tab, select both tabs, and use Send group in parallel. Community Intruder is throttled and cannot reliably hit the gap, so the Repeater group is the race tool here.", "The await between the check and the insert is the window. Fire both signups in parallel with the same username, then reload the signup page and count how many times the name appears: more than once proves the check lost the race."],
  tools: 'BZ, C',
  est: 'about 10 minutes',
  how: 'Username uniqueness is checked before the account is inserted, and nothing holds that answer while the insert waits its turn.',
  link: '/race#race-register',
  start: 'Capture one POST /race/register in Burp, send it to Repeater (Ctrl+R), duplicate the tab, then Send group in parallel.',
};

// Challenge-local presentation: a clay app shell for the signup screens.
function accounts(crumb, body) {
  return appShell('PenTrix Accounts', body, { crumb, mark: '◈', nav: ['Home', 'Sign up', 'Sign in', 'Help'] });
}

function backLinks() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/race">Back to module</a>
  <form method="POST" action="/race/reset" style="display:inline"><button type="submit" class="clay-btn clay-btn-secondary clay-btn-sm">Reset lab state</button></form></p>`;
}

router.get('/register', (req, res) => {
  const list = shared.state(req).accounts;
  const rows = list.map((a) => `<tr><td>${esc(a.username)}</td></tr>`).join('')
    || '<tr><td><i>no accounts yet</i></td></tr>';
  res.send(page('Create an account', accounts('Sign up', `
    <section class="clay-card">
      <h2>Create your account</h2>
      <p class="dim">Every username can be used <b>exactly once</b>. Claim yours below.</p>
      <form method="POST" action="/race/register">
        <div class="clay-field">
          <label for="username">Username</label>
          <input class="clay-input" type="text" id="username" name="username" value="racer" autocomplete="username" />
        </div>
        <div class="clay-field">
          <label for="password">Password</label>
          <input class="clay-input" type="password" id="password" name="password" value="hunter2" autocomplete="new-password" />
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Create account</button>
      </form>
    </section>
    <section class="clay-card">
      <h2>Registered accounts (${list.length})</h2>
      <table class="tbl"><tr><th>Username</th></tr>${rows}</table>
    </section>
    <section class="clay-card">
      <h2>Try it yourself</h2>
      <p>One signup at a time behaves. Two signups for the same username, fired
      at the same instant, may not:</p>
      ${payloadBlock('Burp Repeater: Send group in parallel', 'Send the signup POST to Repeater (Ctrl+R), duplicate the tab so you have two identical requests, select both tabs, right-click and choose Send group in parallel. Reload the page and count the name.')}
    </section>
    ${hintLadder(vuln)}
    ${backLinks()}
  `)));
});

router.post('/register', async (req, res) => {
  const username = String(req.body.username || '').trim().slice(0, 40);
  const password = String(req.body.password || '').slice(0, 80);
  if (!username) {
    return res.status(400).send(page('Create an account', accounts('Sign up', `
      <section class="clay-card">
        <h2>Username is required</h2>
        <p>Pick a username and try again.</p>
        ${backLinks()}
      </section>
    `)));
  }
  // VULN: uniqueness is checked, then an await, then the row is inserted;
  // parallel registrations of the same name both pass the check.
  if (shared.state(req).accounts.some((a) => a.username === username)) {
    return res.send(page('Create an account', accounts('Sign up', `
      <section class="clay-card">
        <h2>Username taken</h2>
        <p><b>${esc(username)}</b> is already registered. Pick another name, or
        reset the lab and try the parallel signup again.</p>
        ${backLinks()}
      </section>
    `)));
  }
  await shared.sleep(shared.WINDOW());
  // Re-read state after the gap, exactly like the original router's live
  // binding, so a lab reset mid-race lands in the fresh state.
  const R = shared.state(req);
  R.accounts.push({ username, password });
  const dupes = R.accounts.filter((a) => a.username === username).length;

  let flagHtml = '';
  if (dupes > 1 && !captured(req, 'race', 'race-register')) {
    flagHtml = flagBox(award(req, 'race', 'race-register'));
    flagHtml += fixPanel('race', 'race-register');
  }
  res.send(page('Account created', accounts('Sign up', `
    <section class="clay-card">
      <h2>Account created: ${esc(username)}</h2>
      <p>Accounts with this username: <b>${dupes}</b></p>
      ${dupes > 1 ? '<p><b>Duplicate usernames exist.</b> Two signups for one name slipped through: the uniqueness check raced the insert.</p>' : '<p>Welcome aboard. Your notebook is ready.</p>'}
      ${flagHtml}
      ${backLinks()}
    </section>
  `)));
});

module.exports = { vuln, router };
