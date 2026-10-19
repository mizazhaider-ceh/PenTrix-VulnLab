'use strict';
// Shared JSONP module helpers: per-session tokens that bind each beacon to a
// real feed load, so a forged beacon with no feed load earns nothing.
const crypto = require('crypto');

// Per-session, per-vuln nonce embedded in the JSONP response data of the
// three reflection labs (callback-xss, filter-bypass, mimetype). The injected
// script must echo it back to /jsonp/beacon-xss, proving it really executed
// with the response data.
function jsonpNonce(req, v) {
  if (!req.session.jsonpNonce) req.session.jsonpNonce = {};
  // hasOwnProperty: never trust a plain truthiness check on a keyed map.
  if (!Object.prototype.hasOwnProperty.call(req.session.jsonpNonce, v)) {
    req.session.jsonpNonce[v] = crypto.randomBytes(16).toString('hex');
  }
  return req.session.jsonpNonce[v];
}

// Consume a nonce: single-use, so replaying a beacon earns nothing.
function jsonpConsumeNonce(req, v, n) {
  const m = req.session.jsonpNonce;
  const cur = m && Object.prototype.hasOwnProperty.call(m, v) ? m[v] : null;
  const ok = !!cur && cur === n && n.length > 0;
  if (ok) delete m[v]; // single-use
  return ok;
}

// Per-session secret stolen via the JSONP feed (was a module constant: anyone
// reading source knew it without a single request). The /beacon route only
// accepts the secret this session's feed actually served.
function jsonpSecret(req) {
  if (!req.session.jsonpSecret) req.session.jsonpSecret = crypto.randomBytes(16).toString('hex');
  return req.session.jsonpSecret;
}

// Per-session token appended to the legacy Array feed; the hijack beacon must
// carry it back, proving the feed was actually loaded and hijacked in this
// session.
function jsonpArrayToken(req) {
  if (!req.session.jsonpArrayToken) req.session.jsonpArrayToken = crypto.randomBytes(16).toString('hex');
  return req.session.jsonpArrayToken;
}

module.exports = { jsonpNonce, jsonpConsumeNonce, jsonpSecret, jsonpArrayToken };
