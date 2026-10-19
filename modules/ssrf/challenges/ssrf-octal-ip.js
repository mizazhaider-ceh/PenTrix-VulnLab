'use strict';
// Octal IP bypass: GET /ssrf/octal-ip fetches a user-supplied URL server-side
// after a naive substring blocklist check. Leading zeros mean octal to the
// WHATWG URL parser, so 0177.0.0.1 normalizes to 127.0.0.1: the raw string
// check never matches while the request still goes to loopback. Reaching the
// internal secret endpoint through this fetcher captures the flag.
const express = require('express');
const { fetchBody, guardedFetch, rawHostBlock } = require('../shared');

const router = express.Router();

// GET /ssrf/octal-ip -> blocklisted fetcher. The check is a naive substring
// test on the raw URL string; octal-encoded loopback normalizes to 127.0.0.1
// in the URL parser, so it passes the check and still hits loopback.
router.get('/octal-ip', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Octal IP', vulnId: 'ssrf-octal-ip', check: rawHostBlock, fetch: fetchBody,
}));

module.exports = {
  vuln: {
    id: 'ssrf-octal-ip',
    name: 'Octal IP bypass',
    difficulty: 'Medium',
    hint: 'Leading zeros mean octal to the URL parser, and the blocklist only knows dotted decimal.',
    hints: ["Leading zeros change how an IP is parsed. What is 0177 in octal?", "0177.0.0.1 is 127.0.0.1 in octal. The substring blocklist misses it.", "Fetch http://0177.0.0.1:PORT/ssrf/internal/secret."],
    tools: 'C',
    how: 'Fetch http://0177.0.0.1:PORT/ssrf/internal/secret via /ssrf/octal-ip.',
    link: '/ssrf#ssrf-octal-ip',
    start: 'curl "http://localhost:3000/ssrf/octal-ip?url=http://0177.0.0.1:3000/ssrf/internal/status"',
  },
  router,
};
