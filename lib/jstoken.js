'use strict';
// Page-bound beacon tokens that only exist once the page's own script runs.
//
// The raw token is never rendered into a page or a feed response. Instead the
// server renders two random share arrays; a small inline script XORs them
// back together at runtime to rebuild the token in a JavaScript variable.
// Scraping the raw HTML (or a feed body) with curl yields only the shares,
// which are useless on their own: the beacon accepts only the rebuilt token,
// so the value has to be produced by executing the page's script (or by
// running the same computation in a real JavaScript context).
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
// lab: the beacon data must be this hash of the page token, a value only
// code executing in the page can produce from the token it rebuilt.
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
