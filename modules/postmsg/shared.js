'use strict';
// Shared helpers for the postmsg module: per-session, per-vuln tokens issued
// when a victim page loads. The victim page's beacon script echoes the token
// back, binding the award to a real victim-page load in this session.
// Single-use tokens: each one is consumed the first time it wins a flag.
const crypto = require('crypto');
const { tokenScriptParts } = require('../../lib/jstoken');

function pmNonce(req, v) {
  if (!req.session.pmNonce) req.session.pmNonce = {};
  // hasOwnProperty: never trust a plain truthiness check on a keyed map.
  if (!Object.prototype.hasOwnProperty.call(req.session.pmNonce, v)) {
    req.session.pmNonce[v] = crypto.randomBytes(16).toString('hex');
  }
  return req.session.pmNonce[v];
}

// Script fragment for a victim page: PM_NONCE computed at runtime from two
// share arrays. The raw token never appears in the page HTML.
function pmNonceScript(req, v) {
  const p = tokenScriptParts(pmNonce(req, v));
  return p.decl + '\n      var PM_NONCE = ' + p.combine + ';';
}

module.exports = { pmNonce, pmNonceScript };
