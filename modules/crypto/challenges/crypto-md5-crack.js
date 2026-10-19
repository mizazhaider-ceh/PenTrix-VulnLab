'use strict';
// Crack the MD5: an old backup leaked the unsalted MD5 hash of the demo
// account password. The password is a dictionary word from the in-lab
// wordlist, so it falls to an offline dictionary attack, then a login.
const express = require('express');
const crypto = require('crypto');
const { page, esc, brief, flagBox, fixPanel, hintLadder, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'crypto-md5-crack',
  name: 'Crack the MD5',
  difficulty: 'Easy',
  hint: 'Unsalted MD5 of a weak password. The password is in the in-lab wordlist: hash every candidate until one matches.',
  hints: ["The hash is unsalted MD5 of a dictionary word. What's the attack?", "Offline cracking with a wordlist (or hashcat).", "Hash every entry in the in-lab wordlist with MD5 until one matches the leak, then log in with it."],
  tools: 'W, P',
  how: 'Crack the hash with the wordlist, then log in with the password.',
  link: '/crypto#crypto-md5-crack',
  start: 'curl -s http://localhost:3000/crypto/md5\ncurl -s http://localhost:3000/crypto/md5/wordlist.txt',
};

// In-app chrome: the challenge reads as a small real product, not a harness.
function appCard(appName, mark, crumb, body) {
  return `<section class="clay-card">
  <div class="card-top"><span class="orb" aria-hidden="true">${esc(mark)}</span><b>${esc(appName)}</b><span class="dim">${esc(crumb)}</span></div>
  ${body}
</section>`;
}

function field(id, name, label, type, extra) {
  return `<div class="clay-field">
    <label for="${esc(id)}">${esc(label)}</label>
    <input class="clay-input" id="${esc(id)}" name="${esc(name)}" type="${esc(type || 'text')}"${extra || ''} />
  </div>`;
}

function submit(label) {
  return `<button type="submit" class="clay-btn clay-btn-primary">${esc(label)}</button>`;
}

function moduleBack() {
  return `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto">Module index</a></p>`;
}

const MD5_WORDLIST = [
  'password', '123456', '123456789', 'qwerty', 'abc123', 'letmein', 'welcome',
  'monkey', 'dragon', 'sunshine', 'princess', 'football', 'charlie', 'aa123456',
  'donald', 'password1', 'qwerty123', 'michael', 'shadow', 'master', 'jennifer',
  'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger',
  'sunset', 'superman', 'qazwsx', 'maggie', 'ferrari', 'jordan', 'mustang',
  'pepper', 'joshua', 'ginger', 'solo', 'summer', 'trustno1', 'michelle',
  'butter', 'corvette', 'thunder', 'ranger', 'thomas', 'taylor',
];
const MD5_PASSWORD = 'sunshine'; // deliberately in the wordlist
const md5Target = crypto.createHash('md5').update(MD5_PASSWORD).digest('hex');

router.get('/md5/wordlist.txt', (req, res) => {
  res.type('text/plain').send(MD5_WORDLIST.join('\n') + '\n');
});

router.get('/md5', (req, res) => {
  res.send(page('Crack the MD5',
    brief('Recover the demo account',
      `LegacyBox, an old file backup service, leaked a database backup. The backup
      exposed the unsalted MD5 hash of the demo account password. Crack it with the
      in-lab wordlist and log in to prove the account is back under control.`) +
    appCard('LegacyBox', 'L', 'Account login', `
      <h2>Leaked password hash</h2>
      <p>An old backup leaked this unsalted MD5 hash of the demo account password:</p>
      ${payloadBlock('Leaked MD5 hash', md5Target)}
      <p>The password is weak and comes from our
      <a href="/crypto/md5/wordlist.txt">in-lab wordlist</a>. Crack it, then log in.</p>
      <hr />
      <h3>Login</h3>
      <form method="POST" action="/crypto/md5/login">
        ${field('username', 'username', 'Username', 'text', ' value="demo" readonly')}
        ${field('password', 'password', 'Password', 'password', ' placeholder="cracked password" required')}
        ${submit('Log in')}
      </form>`) +
    hintLadder(vuln) +
    moduleBack()));
});

router.post('/md5/login', (req, res) => {
  const pw = (req.body.password || '').toString();
  // VULN: unsalted, fast MD5 of a dictionary password: crackable offline.
  if (crypto.createHash('md5').update(pw).digest('hex') === md5Target) {
    const flag = award(req, 'crypto', 'crypto-md5-crack');
    return res.send(page('Logged in',
      appCard('LegacyBox', 'L', 'Account login', `
        <h2>Welcome back</h2>
        <p>Password <code>${esc(pw)}</code> matches the leaked hash. Dictionary
        attack successful.</p>`) +
      flagBox(flag) +
      fixPanel('crypto', 'crypto-md5-crack') +
      moduleBack()));
  }
  res.status(401).send(page('Login failed',
    appCard('LegacyBox', 'L', 'Account login', `
      <h2>Login failed</h2>
      <p class="clay-err" role="alert">That password does not match the leaked hash.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/crypto/md5">Try again</a></p>`)));
});

module.exports = { vuln, router };
