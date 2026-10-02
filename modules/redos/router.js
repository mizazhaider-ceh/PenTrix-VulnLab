// PenTrix VulnLab module: ReDoS (redos)
// Four endpoints test user input against catastrophic regular expressions.
// Each endpoint measures wall-clock time; if the check takes longer than
// 1500 ms the flag is awarded, demonstrating the denial of service.
// Inputs are length-capped so the worst case stays in seconds, not minutes.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));

const THRESHOLD_MS = 1500;

// Calibrated catastrophic patterns (evil inputs verified to exceed the
// threshold while length caps keep the worst case in seconds).
const EMAIL_RE = /^(([a-zA-Z0-9_\-\.]+)+)@([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/;
const USER_RE = /^(a+)+$/;
const URL_RE = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
// For /search the query is interpolated into this template (see route).
const SEARCH_TARGET = 'a'.repeat(26) + '!';

// ---------------------------------------------------------------- index page
const CHALLENGES = [
  ['email', 'redos-email'],
  ['username', 'redos-username'],
  ['url', 'redos-url'],
  ['search', 'redos-search'],
];

router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const ch = CHALLENGES.find((c) => c[1] === v.id);
    const done = captured(req, 'redos', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/redos/${ch[0]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('ReDoS', `
    ${brief('Module briefing', `
      <p><b>What is ReDoS?</b> A regular expression with nested quantifiers
      (like <code>(a+)+</code>) can take exponential time on certain inputs:
      the engine tries every way to split the input before giving up. One
      crafted string ties up the server's single thread, denying service to
      everyone.</p>
      <p><b>How this lab works:</b> each endpoint runs your input against a
      vulnerable regex and reports the milliseconds it took. Push the check past
      <b>${THRESHOLD_MS} ms</b> and the flag is awarded. Inputs are length-capped
      so the worst case is seconds, not minutes. Time your requests with
      <code>time curl ...</code> or watch the reported time on the page.</p>`)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

function tooLong(s, max) {
  return s.length > max;
}

function redosForm(action, field, label, maxLen, exampleNote) {
  return `
    <h2>${esc(label)}</h2>
    <form method="GET" action="/redos/${action}">
      <input type="text" name="${field}" placeholder="${esc(label)}" size="50" required />
      <button type="submit">Validate</button>
    </form>
    <p class="note">Max length: ${maxLen} characters. ${exampleNote}</p>
    <p><a href="/redos">Module index</a></p>`;
}

function redosResult(req, title, input, reSource, ok, ms, vulnId, back) {
  let extra = '';
  if (ms > THRESHOLD_MS) {
    const flag = award(req, 'redos', vulnId);
    extra = `<h3>Denial of service demonstrated</h3>
      <p>The check took <b>${ms} ms</b>. On a real server, every request like
      this one blocks the event loop for everyone.</p>${flagBox(flag)}`;
  }
  return page(title, `
    <h2>${esc(title)}</h2>
    <p>Input: <code>${esc(input)}</code></p>
    <p>Pattern: <code>${esc(reSource)}</code></p>
    <p>Match: <b>${ok ? 'yes' : 'no'}</b> &middot; Time: <b>${ms} ms</b>
    (threshold: ${THRESHOLD_MS} ms)</p>
    ${extra}
    <p><a href="${back}">Try another input</a> &middot; <a href="/redos">Module index</a></p>
  `);
}

// ------------------------------------------------------- v1: email validator
router.get('/email', (req, res) => {
  const email = req.query.email;
  if (email === undefined) {
    return res.send(page('Email validator', redosForm('email', 'email',
      'Newsletter signup: email validator', 33,
      'The local part allows letters, digits, and . _ -. What input has no @ at all?')));
  }
  const s = String(email).slice(0, 500);
  if (tooLong(s, 33)) return res.status(400).send(page('Too long', '<p>Max 33 characters.</p><p><a href="/redos/email">Back</a></p>'));
  // VULN: nested quantifier ((...+)+) in the local part: a long run of valid
  // characters with no @ forces exponential backtracking.
  const t0 = Date.now();
  const ok = EMAIL_RE.test(s);
  const ms = Date.now() - t0;
  res.send(redosResult(req, 'Email validator', s, String(EMAIL_RE), ok, ms, 'redos-email', '/redos/email'));
});

// ----------------------------------------------------- v2: username checker
router.get('/username', (req, res) => {
  const username = req.query.username;
  if (username === undefined) {
    return res.send(page('Username checker', redosForm('username', 'username',
      'Username availability checker', 30,
      'The pattern is <code>^(a+)+$</code>. Feed it many a&#39;s, then break the match at the end.')));
  }
  const s = String(username).slice(0, 500);
  if (tooLong(s, 30)) return res.status(400).send(page('Too long', '<p>Max 30 characters.</p><p><a href="/redos/username">Back</a></p>'));
  // VULN: the textbook catastrophic pattern (a+)+ : every partition of the
  // a-run is tried before the trailing mismatch fails the match.
  const t0 = Date.now();
  const ok = USER_RE.test(s);
  const ms = Date.now() - t0;
  res.send(redosResult(req, 'Username checker', s, String(USER_RE), ok, ms, 'redos-username', '/redos/username'));
});

// ---------------------------------------------------------- v3: URL validator
router.get('/url', (req, res) => {
  const url = req.query.url;
  if (url === undefined) {
    return res.send(page('URL validator', redosForm('url', 'url',
      'Bookmark saver: URL validator', 46,
      'The path part is <code>([\\/\\w .-]*)*</code>, a quantifier inside a quantifier. Repeat a path segment, then break it.')));
  }
  const s = String(url).slice(0, 500);
  if (tooLong(s, 46)) return res.status(400).send(page('Too long', '<p>Max 46 characters.</p><p><a href="/redos/url">Back</a></p>'));
  // VULN: nested quantifiers in the path group: repeated segments with a final
  // mismatch explode the backtracking.
  const t0 = Date.now();
  const ok = URL_RE.test(s);
  const ms = Date.now() - t0;
  res.send(redosResult(req, 'URL validator', s, String(URL_RE), ok, ms, 'redos-url', '/redos/url'));
});

// ------------------------------------ v4: search building RegExp from query
function searchHandler(req, res) {
  const q = (req.method === 'GET' ? req.query.q : (req.body.q || '')).toString();
  const s = q.slice(0, 500);
  if (!/^[a-z]{1,10}$/.test(s)) {
    return res.status(400).send(page('Bad query', `
      <p>Query may only contain lowercase letters (max 10 chars).</p>
      <p><a href="/redos/search">Back</a></p>`));
  }
  // VULN: the search query is interpolated as the atom of a nested-quantifier
  // template, so q=a compiles to ^((a)+)+$, which backtracks catastrophically.
  let re;
  try {
    re = new RegExp('^((' + s + ')+)+$');
  } catch (e) {
    return res.status(400).send(page('Bad query', `<p>Invalid pattern: ${esc(e.message)}</p><p><a href="/redos/search">Back</a></p>`));
  }
  const t0 = Date.now();
  const ok = re.test(SEARCH_TARGET);
  const ms = Date.now() - t0;
  res.send(redosResult(req, 'Site search', s, '^((' + s + ')+)+$  against a fixed 27-char haystack',
    ok, ms, 'redos-search', '/redos/search'));
}

router.get('/search', (req, res) => {
  if (req.query.q === undefined) {
    return res.send(page('Site search', `
      <h2>Site search</h2>
      <p>Search queries may only contain lowercase letters.
      The query is compiled into a validation pattern before searching.</p>
      <form method="GET" action="/redos/search">
        <input type="text" name="q" placeholder="search query" size="40" required />
        <button type="submit">Search</button>
      </form>
      <p class="note">The query becomes the atom of the pattern
      <code>^((q)+)+$</code>, tested against a fixed haystack of 26
      <code>a</code>'s followed by <code>!</code>. The template nests
      quantifiers; your input decides what they repeat.</p>
      <p><a href="/redos">Module index</a></p>
    `));
  }
  searchHandler(req, res);
});
router.post('/search', searchHandler);

module.exports = {
  id: 'redos',
  name: 'ReDoS',
  tagline: 'One crafted string to block the event loop.',
  description: 'Four endpoints validate user input with catastrophic regular expressions. Find the evil input shape for each pattern, push the check past 1500 ms, and watch a single request deny service.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'redos-email',
      name: 'Catastrophic Email Regex',
      difficulty: 'Medium',
      hint: 'The local part is ((...+)+): nested quantifiers. Send a long run of valid characters with no @ anywhere.',
      how: 'Submit 30 a\'s followed by a non-matching character as the email (add a few more, up to the length cap, if your machine is very fast).',
    },
    {
      id: 'redos-username',
      name: 'Nested Quantifier Username',
      difficulty: 'Easy',
      hint: 'The pattern is shown on the page: ^(a+)+$. Give it what it wants, then take it away at the last character.',
      how: 'Submit 27 a\'s plus a trailing character that breaks the match (add a few more, up to the length cap, if your machine is very fast).',
    },
    {
      id: 'redos-url',
      name: 'Catastrophic URL Regex',
      difficulty: 'Medium',
      hint: 'The path group is ([\\/\\w .-]*)*. Repeat a path segment many times, then end with a character the pattern rejects.',
      how: 'Submit http://example.com/ with the path segment a/ repeated 12 times and a trailing !.',
    },
    {
      id: 'redos-search',
      name: 'Regex Injection Search',
      difficulty: 'Medium',
      hint: 'Your query is compiled into ^((q)+)+$ as the repeated atom. The haystack is 26 a\'s plus !. Which atom gives the nesting something to chew on?',
      how: 'Search for the haystack\'s character so the compiled pattern becomes ^((a)+)+$.',
    },
  ],
  router,
};
