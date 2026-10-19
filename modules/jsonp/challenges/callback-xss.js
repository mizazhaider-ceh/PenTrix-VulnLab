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
const { jsonpNonce } = require('../shared');

const router = express.Router();

router.get('/user', (req, res) => {
  const cb = (req.query.callback || 'callback').toString().slice(0, 200);
  res.type('application/javascript');
  // VULN: the callback name is reflected into executable JavaScript with no
  // validation, so it can break out of the function-call context.
  // The response embeds a per-session token in the data object; the injected
  // script must echo it back to /jsonp/beacon-xss. The old input-pattern award
  // (any non-word character in the callback) is gone: no execution, no flag.
  const body = `${cb}({"user":"alice","role":"user","token":"${jsonpNonce(req, 'callback-xss')}"});`;
  res.send(body);
});

module.exports = {
  vuln: {
    id: 'callback-xss',
    name: 'Callback XSS',
    difficulty: 'Easy',
    hint: 'The callback parameter is dropped straight into executable JavaScript. It does not have to stay a function name. Tweak it in Repeater. The response data carries a per-session token your script must echo back to /jsonp/beacon-xss.',
    hints: ["In Burp's browser, open /jsonp/user?callback=hello and watch the response in Proxy. It is a JavaScript function call. Ask what the response would execute if the callback value were not a plain function name.", "Send that request to Repeater and try callback values that close the call early, so your own JavaScript becomes part of the response.", "Load the tampered URL in Burp's browser so the injected code runs. The data object carries a per-session token; echo it to /jsonp/beacon-xss and the beacon shows the flag."],
    tools: "BZ, B",
    how: 'Break out of the function-call context in the callback parameter (experiment in Repeater) so the response runs your own code when loaded as a script. Read the per-session token from the data object, echo it to /jsonp/beacon-xss?v=callback-xss&n=<token>, and the beacon response shows the flag.',
    link: '/jsonp#callback-xss',
    start: 'Browse to /jsonp/user?callback=hello through Burp Proxy and intercept the feed request, then send it to Repeater. Experiment with the callback parameter until your tampering runs when the response is loaded as a script, then load the tampered URL in the Burp browser so the injected code echoes the per-session token to /jsonp/beacon-xss?v=callback-xss&n=<token>.',
  },
  router,
};
