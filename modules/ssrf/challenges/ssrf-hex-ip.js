'use strict';
// Hex IP bypass: GET /ssrf/hex-ip fetches a user-supplied URL server-side
// after a naive substring blocklist check. The WHATWG URL parser normalizes
// hex spellings of loopback (0x7f.0.0.1) to 127.0.0.1, so they slip past the
// raw string check while the request still goes to loopback. Reaching the
// internal secret endpoint through this fetcher captures the flag.
const express = require('express');
const { fetchBody, guardedFetch, rawHostBlock } = require('../shared');

const router = express.Router();

// GET /ssrf/hex-ip -> blocklisted fetcher.
// VULN: the check is a naive substring test on the raw URL string;
// hex-encoded loopback normalizes to 127.0.0.1 in the URL parser, so it
// passes the check and still hits loopback.
router.get('/hex-ip', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Hex IP', vulnId: 'ssrf-hex-ip', check: rawHostBlock, fetch: fetchBody,
}));

module.exports = {
  vuln: {
    id: 'ssrf-hex-ip',
    name: 'Hex IP bypass',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'Proxy the fetcher form in Burp and watch the blocklist: it compares raw strings, but the server-side URL parser normalizes the host before fetching. Which spellings of loopback slip through?',
    hints: ["With Burp Proxy on, submit the fetcher form with a plain loopback URL and send the request to Repeater. The 403 comes from a blocklist that only matches raw strings. Loopback has more than one spelling.", "Keep the same request in Repeater and re-spell the loopback host using hex octets (127 is 0x7f in hex). The raw string check will not match that spelling, but the URL parser still resolves it to 127.0.0.1.", "In Repeater, aim the hex-spelled host at the internal secret path on the lab port and send. The internal marker earns the flag."],
    tools: 'BZ, C',
    how: 'The blocklist matches raw strings, but the URL parser normalizes the host before fetching. In Burp Repeater, re-spell loopback so the string check misses it while the parser still resolves it, and aim it at the internal secret path.',
    link: '/ssrf#ssrf-hex-ip',
    start: 'With Burp Proxy on, open the Hex IP challenge form (/ssrf), submit a URL with the plain loopback host, then send the request to Repeater and re-spell the host.',
  },
  router,
};
