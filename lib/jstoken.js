'use strict';
// Page-token beacon tokens, split into two XOR shares before serving.
//
// What this does: the raw token is never rendered into a page or a feed
// response. The server renders two random share arrays instead, and a small
// inline script XORs them back together at runtime to rebuild the token in
// a JavaScript variable. This stops verbatim scraping: a share array on its
// own, or a guessed token, is rejected by the beacon (HTTP 400), and a bare
// beacon with no prior page or feed load has no token at all. Per-session
// binding, per-vuln binding and single-use consumption are enforced by the
// modules' own nonce stores, not by this helper, which is stateless.
//
// What this does not do, and must never be described as doing: it does not
// prove that any JavaScript executed, in a browser or anywhere else. Both
// shares and the recombination computation are served to anyone holding a
// session, so the token is fully determined by the served bytes. Anyone who
// fetches the page or feed can recompute the token outside any JavaScript
// context (for example in Python with two XOR loops) and submit a beacon
// the server will accept. That recomputation is the accepted bar for
// page-token beacon challenges: the intended exploit path is in-page
// execution, and off-browser recomputation is a known, accepted residual,
// not execution proof. Challenges that need execution proof must use a
// model whose secret never leaves the server for the claimant (the
// victim-bound model used by the stored and upload challenges) or evidence
// the server can verify independently of the token; no deterministic
// computation over served material can provide it.
const crypto = require('crypto');

// Split a token string into two number arrays whose XOR is the token's
// character codes. Both arrays are random-looking; neither leaks the token.
function tokenShares(token) {
  const codes = [];
  for (let i = 0; i < token.length; i++) codes.push(token.charCodeAt(i));
  const key = crypto.randomBytes(codes.length);
  const a = codes.map((c, i) => c ^ key[i]);
  return { a, k: Array.from(key) };
}

// Script fragments for a page: `decl` declares the two share arrays once,
// `combine` is the JavaScript expression that rebuilds the token from them.
function tokenScriptParts(token) {
  const s = tokenShares(token);
  return {
    decl: `var __tkA=${JSON.stringify(s.a)},__tkK=${JSON.stringify(s.k)};`,
    combine: "__tkA.map(function(b,i){return String.fromCharCode(b^__tkK[i]);}).join('')",
  };
}

// Same split, encoded as hex strings for URL parameters: a document that
// cannot see the page's variables (an uploaded SVG opened on its own) reads
// pxa/pxk from its own URL and rebuilds the token the same way.
function tokenShareParams(token) {
  const s = tokenShares(token);
  const hex = (arr) => arr.map((b) => b.toString(16).padStart(2, '0')).join('');
  return { pxa: hex(s.a), pxk: hex(s.k) };
}

// Rebuild a token from hex share parameters (server-side mirror of the
// client computation; used by tests and by pages that combine shares).
function combineHexShares(pxa, pxk) {
  let out = '';
  for (let i = 0; i + 1 < pxa.length && i + 1 < pxk.length; i += 2) {
    out += String.fromCharCode(parseInt(pxa.substr(i, 2), 16) ^ parseInt(pxk.substr(i, 2), 16));
  }
  return out;
}

// Client-side expression that rebuilds a token from URL share parameters.
const COMBINE_FROM_SEARCH_JS = "(function(){var p=new URLSearchParams(location.search);"
  + "var a=p.get('pxa')||'',k=p.get('pxk')||'',t='';"
  + "for(var i=0;i+1<a.length&&i+1<k.length;i+=2){t+=String.fromCharCode(parseInt(a.substr(i,2),16)^parseInt(k.substr(i,2),16));}"
  + "return t;})()";

// Small deterministic string hash (djb2), shared by the CSTI constructor
// lab: the beacon data must be this hash of the page token. This binds the
// beacon data to the rebuilt token, and nothing more: anyone who recomputes
// the token from the served shares, in any language, can compute this hash
// too. It is not execution proof (see the accepted bar at the top).
function djb2Hex(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

// The same hash as a JavaScript snippet a lab page can define for payloads.
const DJB2_JS = "function cstiDjb2(s){var h=5381;for(var i=0;i<s.length;i++){h=((h<<5)+h+s.charCodeAt(i))>>>0;}return h.toString(16);}";

// Client-side helper for feed data: rebuild a token from two hex share
// strings inside a JavaScript execution context (used by the JSONP labs,
// whose feeds carry shares instead of a raw token).
const COMBINE_HEX_JS = "function combineHex(a,b){var s='';for(var i=0;i+1<a.length&&i+1<b.length;i+=2){s+=String.fromCharCode(parseInt(a.substr(i,2),16)^parseInt(b.substr(i,2),16));}return s;}";

module.exports = { tokenShares, tokenScriptParts, tokenShareParams, combineHexShares, COMBINE_FROM_SEARCH_JS, COMBINE_HEX_JS, djb2Hex, DJB2_JS };
