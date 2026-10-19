'use strict';
// Hex IP bypass: GET /ssrf/hex-ip fetches a user-supplied URL server-side
// after a naive substring blocklist check. The WHATWG URL parser normalizes
// hex spellings of loopback (0x7f.0.0.1) to 127.0.0.1, so they slip past the
// raw string check while the request still goes to loopback. Reaching the
// internal secret endpoint through this fetcher captures the flag.
const express = require('express');
const { fetchBody, guardedFetch, rawHostBlock } = require('../shared');

const router = express.Router();

// GET /ssrf/hex-ip -> blocklisted fetcher. The check is a naive substring
// test on the raw URL string; hex-encoded loopback normalizes to 127.0.0.1
// in the URL parser, so it passes the check and still hits loopback.
router.get('/hex-ip', (req, res) => guardedFetch(req, res, {
  title: 'SSRF Hex IP', vulnId: 'ssrf-hex-ip', check: rawHostBlock, fetch: fetchBody,
}));

module.exports = {
  vuln: {
    id: 'ssrf-hex-ip',
    name: 'Hex IP bypass',
    difficulty: 'Medium',
    hint: 'The blocklist compares raw strings, but the URL parser normalizes hex IP parts.',
    hints: ["The blocklist looks for '127.0.0.1' as text. But IP addresses have hex spellings too.", "0x7f.0.0.1 is 127.0.0.1 in hex. The string check doesn't recognize it, but the URL parser does.", "Fetch http://0x7f.0.0.1:PORT/ssrf/internal/secret."],
    tools: 'C',
    how: 'Fetch http://0x7f.0.0.1:PORT/ssrf/internal/secret via /ssrf/hex-ip.',
    link: '/ssrf#ssrf-hex-ip',
    start: 'curl "http://localhost:3000/ssrf/hex-ip?url=http://0x7f.0.0.1:3000/ssrf/internal/status"',
  },
  router,
};
