'use strict';
// Shared helpers for the Open Redirect module challenges. Created during the
// challenge-split migration; logic copied verbatim from
// modules/redirect/router.js. Imported by modules/redirect/challenges/*.js.
const { page } = require('../../lib/page');

// Every lab answers with a real 302 plus a readable body, so `curl -i` shows the
// Location header and the explanation page at the same time.
function sendRedirect(res, target, innerHtml) {
  res.status(302).set('Location', target);
  res.send(page('Redirecting', innerHtml));
}

module.exports = { sendRedirect };
