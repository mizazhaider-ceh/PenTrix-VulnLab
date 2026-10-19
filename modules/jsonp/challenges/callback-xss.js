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
    hint: 'The callback parameter is dropped straight into executable JavaScript. It does not have to stay a function name. The response data carries a per-session token your payload must echo back to /jsonp/beacon-xss.',
    hints: ["The callback parameter is reflected into JavaScript. What if it's not a function name?", "Break out: callback=x);alert(1);// turns the response into your code.", "The injected script must echo the per-session token to the beacon."],
    tools: "B",
    how: 'Load /jsonp/user?callback=... as a script with a breakout payload that reads the token from the data object and beacons it, e.g. callback=(d=>fetch(\'/jsonp/beacon-xss?v=callback-xss&n=\'+d.token)).',
    link: '/jsonp#callback-xss',
    start: 'curl -s "http://localhost:3000/jsonp/user?callback=hello"\n# then load /jsonp/user?callback=<breakout> as a <script> and beacon the token to /jsonp/beacon-xss',
  },
  router,
};
