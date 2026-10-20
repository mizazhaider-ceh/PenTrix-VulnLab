'use strict';
// Callback XSS: GET /jsonp/user reflects the callback parameter straight into
// executable JavaScript with no validation, so a caller can break out of the
// function-call context. The response embeds a per-session token in the data
// object; the injected script must echo it back to the shared
// /jsonp/beacon-xss endpoint, which proves the payload really executed.
// NOTE: jsonpNonce lives in modules/jsonp/shared.js (placed by the finisher).
// The /beacon-xss route is shared by the three reflection labs and is mounted
// once by the finisher, not in this file.
const express = require('express');
const { jsonpNonceShares } = require('../shared');

const router = express.Router();

router.get('/user', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: the callback name is reflected into executable JavaScript with no
  // validation, so it can break out of the function-call context.
  // The response embeds a per-session token in the data object; the injected
  // script must echo it back to /jsonp/beacon-xss. The old input-pattern award
  // (any non-word character in the callback) is gone: no execution, no flag.
  const shares = jsonpNonceShares(req, 'callback-xss');
  const body = `${cb}({\"user\":\"alice\",\"role\":\"user\",\"pxa\":\"${shares.pxa}\",\"pxk\":\"${shares.pxk}\"});`;
  res.send(body);
});

module.exports = {
  vuln: {
    id: 'callback-xss',
    name: 'Callback XSS',
    difficulty: 'Easy',
    hint: 'The callback parameter is dropped straight into executable JavaScript. It does not have to stay a function name. Tweak it in Repeater and watch what the response becomes.',
    hints: ["In Burp's browser, open /jsonp/user?callback=hello and watch the response in Proxy. It is a JavaScript function call. Ask what the response would execute if the callback value were not a plain function name.", "Send that request to Repeater and try callback values that close the call early, so your own JavaScript becomes part of the response.", "Shape: a callback value that ends the expected call and continues with your own expression, loaded in the browser so it runs with the response data. The data carries the per-session proof token only as two share fields; code executing alongside the data can combine them at runtime (the hex shares XOR back into the token) and echo the result to the beacon endpoint named on the module page."],
    tools: "BZ, B",
    est: 'about 5 to 10 minutes',
    how: 'An unvalidated callback is reflected into executable JavaScript, so the supposed function name can break out and become code of its own.',
    link: '/jsonp#callback-xss',
    start: 'Browse to /jsonp/user?callback=hello through Burp Proxy and intercept the feed request, then send it to Repeater. Experiment with the callback parameter there, then load your crafted URL in the Burp browser so any injected code actually runs.',
  },
  router,
};
