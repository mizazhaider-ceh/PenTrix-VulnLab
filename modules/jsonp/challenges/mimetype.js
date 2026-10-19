'use strict';
// JSONP MIME sniffing: GET /jsonp/snippet serves JSONP as text/html, so the
// browser parses the response as a document and HTML/JS in the callback
// executes on direct visit or inside an iframe. The response embeds a
// per-session token; only an executed payload that echoes it back to
// /jsonp/beacon-xss captures the flag (the beacon lives in the module index).
const express = require('express');
// Module-level helper (kept out of this file on purpose): the finisher must
// provide jsonpNonce via modules/jsonp/shared.js. See final report.
const { jsonpNonce } = require('../shared');

const router = express.Router();

// GET /jsonp/snippet?callback=... -> v5 JSONP served as text/html.
router.get('/snippet', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 300);
  // VULN: JSONP served as text/html is parsed as a document, so HTML/JS in the
  // callback executes on direct visit or inside an iframe.
  res.set('Content-Type', 'text/html; charset=utf-8');
  // The old input-pattern award (any '<' in the callback) is gone: the attempt
  // shape is recorded here, but only an executed script echoing the token back
  // to /jsonp/beacon-xss earns the flag.
  if (/</.test(cb)) req.session.jsonpMimeAttempt = true;
  const body = `${cb}({"note":"hello","token":"${jsonpNonce(req, 'mimetype')}"});`;
  res.send(body);
});

const vuln = {
  id: 'mimetype',
  name: 'JSONP MIME Sniffing',
  difficulty: 'Easy',
  hint: 'The response is served as text/html, so the browser parses it as a document, not just script. Your injected markup must read the per-session token from the response text and beacon it to /jsonp/beacon-xss.',
  hints: ["The JSONP is served as text/html. What does the browser do with it?", "It parses as a document. Your callback becomes HTML/JS.", "Request with an HTML-shaped callback and echo the token."],
  tools: 'B',
  how: 'Put an HTML tag in the callback and open the URL directly, e.g. <img src=x onerror="fetch(\'/jsonp/beacon-xss?v=mimetype&n=\'+document.body.innerHTML.match(/\\"token\\":\\"([a-f0-9]+)\\"/)[1])">.',
  link: '/jsonp#mimetype',
  start: 'curl -si "http://localhost:3000/jsonp/snippet?callback=cb"',
};

module.exports = { vuln, router };
