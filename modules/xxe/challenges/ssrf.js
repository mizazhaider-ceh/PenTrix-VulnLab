'use strict';
// SSRF via XXE: the same shared XML importer also fetches http:// external
// entities server-side, so pointing an entity at an internal URL makes the
// server request it and splice the response into the import result. This
// challenge shares the /import endpoint with the "XXE File Read" challenge
// (both map to the import page).
// This challenge shares the XML importer console with the "XXE File Read"
// challenge. The endpoint lives in ../importer.js and is mounted exactly
// once via the file.js entry; a second copy here used to be shadowed by
// Express (first match wins), so this router intentionally registers no
// routes. The shared importer awards this challenge's flag when an http://
// entity fetches the internal secret.
// VULN: the XML importer fetches http:// external entities server-side, so
// an entity pointing at an internal URL makes the server request it and
// splice the response into the import result (SSRF via XXE).
const express = require('express');
const router = express.Router();

const vuln = {
  id: 'ssrf',
  name: 'SSRF via XXE',
  difficulty: 'Hard',
  est: 'about 15 minutes',
  hint: "The same importer also fetches http:// entities server-side. What happens when the parser requests an internal URL for you?",
  hints: [
    "Entities can have http:// URLs too. What happens when the parser fetches one?",
    "In Burp, submit the XML importer form with Proxy intercept on, then send the captured POST to Repeater so you can edit and re-send the xml parameter freely.",
    "An external entity with an http:// SYSTEM identifier makes the server request that URL. The primitives are the ones from the file-read challenge: declare the entity, reference it where the output renders, and URL-encode the xml value so characters like & and the quote marks do not break the form field.",
  ],
  tools: 'BZ, C',
  how: 'External entities are fetched server-side. Point one at an internal endpoint the firewall would never let your browser reach.',
  link: '/xxe#file',
  start: 'Browse to the XML Importer (/xxe/import) with Burp Proxy intercepting, submit the form once, and send the captured POST request to Repeater. Replace the xml parameter with your own XML document containing a DOCTYPE and an external entity that points at an http:// URL, URL-encode the parameter value, send, and read the parsed content.',
};

module.exports = { vuln, router };
