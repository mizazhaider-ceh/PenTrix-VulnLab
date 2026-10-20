'use strict';
// JSONP MIME sniffing: GET /jsonp/snippet serves JSONP as text/html, so the
// browser parses the response as a document and HTML/JS in the callback
// executes on direct visit or inside an iframe. The response embeds a
// per-session token; only an executed payload that echoes it back to
// /jsonp/beacon-xss captures the flag (the beacon lives in the module index).
const express = require('express');
// Module-level helper (kept out of this file on purpose): the finisher must
// provide jsonpNonce via modules/jsonp/shared.js. See final report.
const { jsonpNonceShares } = require('../shared');

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
  const shares = jsonpNonceShares(req, 'mimetype');
  const body = `${cb}({\"note\":\"hello\",\"pxa\":\"${shares.pxa}\",\"pxk\":\"${shares.pxk}\"});`;
  res.send(body);
});

const vuln = {
  id: 'mimetype',
  name: 'JSONP MIME Sniffing',
  difficulty: 'Easy',
  hint: 'The response is served as text/html, so the browser parses it as a document, not as data. What does a document do with markup it finds inside itself?',
  hints: ["In Burp Proxy, open /jsonp/snippet?callback=hello in the browser and watch the response in Proxy history. It is served as text/html, so the browser treats it as a document, not as a script. What happens to a callback value that looks like HTML?", "Send that request to Repeater and try an HTML-shaped callback value. Then think about how code running inside that document could read the proof shares carried in the response text, combine them at runtime, and send the result back.", "Shape: a callback value shaped like markup rather than a function call, loaded in the browser so the document parses and runs it, with the executed code echoing the reassembled proof token to the beacon endpoint named on the module page."],
  tools: 'BZ, B',
  est: 'about 5 to 10 minutes',
  how: 'JSONP data served with an HTML MIME type is parsed as a document, so reflected content stops being data and starts being markup.',
  link: '/jsonp#mimetype',
  start: 'In Burp Proxy, open /jsonp/snippet?callback=hello in the browser and watch the response headers in Proxy history. Send the request to Repeater and experiment with callback values there, then load your crafted URL in the browser and watch what the document does with it.',
};

module.exports = { vuln, router };
