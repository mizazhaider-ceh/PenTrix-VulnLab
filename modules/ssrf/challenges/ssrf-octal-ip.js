'use strict';
// Octal IP bypass: GET /ssrf/octal-ip fetches a user-supplied URL server-side
// after a naive substring blocklist check. Leading zeros mean octal to the
// WHATWG URL parser, so 0177.0.0.1 normalizes to 127.0.0.1: the raw string
// check never matches while the request still goes to loopback. Reaching the
// internal secret endpoint through this fetcher captures the flag.
const express = require('express');
const { fetchBody, guardedFetch, rawHostBlock } = require('../shared');

const router = express.Router();

// GET /ssrf/octal-ip -> blocklisted fetcher.
// VULN: the check is a naive substring test on the raw URL string;
// octal-encoded loopback normalizes to 127.0.0.1 in the URL parser, so it
// passes the check and still hits loopback.
router.get('/octal-ip', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Octal IP', vulnId: 'ssrf-octal-ip', check: rawHostBlock, fetch: fetchBody,
}));

module.exports = {
  vuln: {
    id: 'ssrf-octal-ip',
    name: 'Octal IP bypass',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'Leading zeros mean octal to the URL parser, and the blocklist only knows dotted decimal.',
    hints: ["In Repeater, confirm a plain loopback fetch gets blocked. Then think about what leading zeros do to IP parsing.", "127 written in octal is 0177. Spell the loopback octets with leading zeros in the Repeater url value, so the parser reads octal while the substring blocklist misses it.", "Aim the url value at the internal secret path using the octal spelling of loopback, and read the flag from the response."],
    tools: 'BZ, C',
    how: 'In Burp Repeater, re-spell the loopback address for /ssrf/octal-ip in a form the URL parser reads differently from dotted decimal, so the naive substring blocklist never matches while the request still lands on loopback.',
    link: '/ssrf#ssrf-octal-ip',
    start: 'Open the Octal IP fetch page in your browser through Burp Proxy, submit a fetch, send the request to Repeater, then edit the url value to spell loopback with leading zeros.',
  },
  router,
};
