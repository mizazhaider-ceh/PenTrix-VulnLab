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
  hints: ["In Burp Proxy, open /jsonp/snippet?callback=hello in the browser and watch the response in Proxy history. It is served as text/html, so the browser treats it as a document, not as a script. What happens to a callback value that looks like HTML?", "Send that request to Repeater and try an HTML-shaped callback value. The response text carries a per-session token; think about how code running in that document could read it and send it back.", "Load the Repeater-crafted URL in Burp's browser so the injected markup executes. Echo the token to /jsonp/beacon-xss and the beacon response shows the flag."],
  tools: 'BZ, B',
  how: 'Craft the /jsonp/snippet request in Repeater with an HTML-shaped callback, then open that URL in the browser: served as text/html, the response is parsed as a document and your markup runs. Read the per-session token from the response text and echo it to /jsonp/beacon-xss?v=mimetype&n=<token>; the beacon response shows the flag.',
  link: '/jsonp#mimetype',
  start: 'In Burp Proxy, open /jsonp/snippet?callback=hello in the browser and watch the response headers in Proxy history. Send the request to Repeater and try HTML-shaped callback values until the Repeater URL, opened in the browser, runs your markup; then echo the per-session token to /jsonp/beacon-xss?v=mimetype&n=<token>.',
};

module.exports = { vuln, router };
