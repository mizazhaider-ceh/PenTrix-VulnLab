'use strict';
// Regex Injection Search: GET/POST /redos/search compiles the query into
// ^((q)+)+$ and tests it against a fixed 27-char haystack. Searching for the
// haystack's own character turns the template into a catastrophic pattern,
// the check exceeds 1000 ms, and the flag is awarded.
const express = require('express');
const { page, esc } = require('../../../lib/page');
// Module-level helpers (redosResult, THRESHOLD_MS) and the urlencoded
// middleware (needed so POST reads req.body.q) live in ../shared.js and the
// module index (finisher assembles them).
const shared = require('../shared');

const router = express.Router();

// VULN (verbatim from router.js): the fixed haystack the compiled pattern is
// tested against.
const SEARCH_TARGET = 'a'.repeat(26) + '!';

const vuln = {
  id: 'redos-search',
  name: 'Regex Injection Search',
  difficulty: 'Medium',
  est: 'about 10 to 25 minutes',
  hint: 'Your query is compiled into ^((q)+)+$ as the repeated atom. The haystack is 26 a\'s plus !. Which atom gives the nesting something to chew on?',
  hints: [
    'Your search term becomes a regex atom. Can you inject a catastrophic pattern?',
    'The text you type becomes the atom that the server wraps in its own nested quantifiers. Build that atom from the haystack\'s repeated character so the nesting has something to chew on.',
    'The catastrophic pattern only explodes because the last character can never match. Capture the search request in Burp Proxy, push it to Repeater, set q to the haystack\'s repeated character, and watch the response time Repeater reports for each send.',
  ],
  tools: 'BZ, B, C',
  how: 'In Burp Repeater, choose the search term so the pattern the server compiles from it has nested quantifiers something to chew on against the fixed haystack. The claim fires when the response takes over 1000 ms.',
  link: '/redos#redos-search',
  start: 'Proxy on, open /redos/search in the Burp browser and submit the search form once with a harmless query (for example test). In Proxy history, send the request to Repeater. Start tweaking the q parameter and watch the response time.',
};

function searchHandler(req, res) {
  const q = (req.method === 'GET' ? req.query.q : (req.body.q || '')).toString();
  const s = q.slice(0, 500);
  if (!/^[a-z]{1,10}$/.test(s)) {
    return res.status(400).send(page('Bad query', `
      <section class="clay-card">
        <h2>Bad query</h2>
        <p class="clay-err" role="alert">Query may only contain lowercase letters (max 10 chars).</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos/search">Back</a></p>
      </section>`));
  }
  // VULN: the search query is interpolated as the atom of a nested-quantifier
  // template, so q=a compiles to ^((a)+)+$, which backtracks catastrophically.
  let re;
  try {
    re = new RegExp('^((' + s + ')+)+$');
  } catch (e) {
    return res.status(400).send(page('Bad query', `
      <section class="clay-card">
        <h2>Bad query</h2>
        <p class="clay-err" role="alert">Invalid pattern: ${esc(e.message)}</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos/search">Back</a></p>
      </section>`));
  }
  const t0 = Date.now();
  const ok = re.test(SEARCH_TARGET);
  const ms = Date.now() - t0;
  res.send(shared.redosResult(req, 'Site search', s, '^((' + s + ')+)+$  against a fixed 27-char haystack',
    ok, ms, 'redos-search', '/redos/search'));
}

router.get('/search', (req, res) => {
  if (req.query.q === undefined) {
    return res.send(page('Site search', `
      <section class="clay-card">
        <div class="card-top"><span class="orb" aria-hidden="true">S</span><b>Site search</b></div>
        <h2>Site search</h2>
        <p>Search queries may only contain lowercase letters.
        The query is compiled into a validation pattern before searching.</p>
        <form method="GET" action="/redos/search">
          <div class="clay-field">
            <label for="q">Search query</label>
            <input class="clay-input" type="text" id="q" name="q" placeholder="search query" size="40" required />
          </div>
          <button class="clay-btn clay-btn-primary" type="submit">Search</button>
        </form>
        <p class="note">The query becomes the atom of the pattern
        <code>^((q)+)+$</code>, tested against a fixed haystack of 26
        <code>a</code>'s followed by <code>!</code>. The template nests
        quantifiers; your input decides what they repeat.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos">Module index</a></p>
      </section>
    `));
  }
  searchHandler(req, res);
});
router.post('/search', searchHandler);

module.exports = { vuln, router };
