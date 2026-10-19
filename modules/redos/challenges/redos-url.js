'use strict';
// Catastrophic URL Regex: GET /redos/url validates a bookmark URL against a
// regex whose path group nests quantifiers. A long run of repeated path
// segments plus a bad tail explodes the backtracking past 1000 ms and the
// flag is awarded.
const express = require('express');
const { page } = require('../../../lib/page');
// Module-level helpers (tooLong, redosForm, redosResult, THRESHOLD_MS) and
// the urlencoded middleware live in ../shared.js (finisher assembles it).
const shared = require('../shared');

const router = express.Router();

// VULN (verbatim from router.js): nested quantifiers in the path group
// ([\/\w .-]*)* mean repeated segments with a final mismatch explode the
// backtracking.
const URL_RE = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;

const vuln = {
  id: 'redos-url',
  name: 'Catastrophic URL Regex',
  difficulty: 'Medium',
  hint: 'The path group is ([\\/\\w .-]*)*. Repeat a path segment many times, then end with a character the pattern rejects.',
  hints: [
    'The URL regex has nested quantifiers in the path group.',
    'Same as email: long run + bad tail.',
    'Feed the validator a URL whose path repeats one simple segment many times, then ends with a character the pattern cannot match, forcing the nested group to retry every split. Time the response.',
  ],
  tools: 'B, C',
  how: 'Submit http://example.com/ with the path segment a/ repeated 12 times and a trailing !.',
  link: '/redos#redos-url',
  start: 'curl -s "http://localhost:3000/redos/url"\ntime curl -s "http://localhost:3000/redos/url?url=http://example.com/" | grep -o "Time: <b>[0-9]* ms</b>"',
};

router.get('/url', (req, res) => {
  const url = req.query.url;
  if (url === undefined) {
    return res.send(page('URL validator', shared.redosForm('url', 'url',
      'Bookmark saver: URL validator', 46,
      'The path part is <code>([\\/\\w .-]*)*</code>, a quantifier inside a quantifier. Repeat a path segment, then break it.')));
  }
  const s = String(url).slice(0, 500);
  if (shared.tooLong(s, 46)) {
    return res.status(400).send(page('Too long', `
      <section class="clay-card">
        <h2>Too long</h2>
        <p class="clay-err" role="alert">Max 46 characters.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/redos/url">Back</a></p>
      </section>`));
  }
  const t0 = Date.now();
  const ok = URL_RE.test(s);
  const ms = Date.now() - t0;
  res.send(shared.redosResult(req, 'URL validator', s, String(URL_RE), ok, ms, 'redos-url', '/redos/url'));
});

module.exports = { vuln, router };
