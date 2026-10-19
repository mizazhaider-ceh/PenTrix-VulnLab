'use strict';
module.exports = {
  module: 'xss',
  vulnId: 'xss-js-context',
  title: 'XSS in a JavaScript String',
  language: 'javascript',
  vulnerableCode: `
// VULNERABLE: user input is interpolated raw inside a single-quoted
// JavaScript string literal, so a single quote breaks out of the string.
function vulnFn(input) {
  return "var q = '" + input + "';\\n" +
    "document.getElementById('greet').textContent = q ? 'Hello, ' + q + '!' : 'Enter a name to see your greeting.';";
}
`,
  fixedCode: `
// FIXED: the input is JSON-encoded before it enters the script, so it is
// always a safe string literal and quotes can never break out of it.
function vulnFn(input) {
  return 'var q = ' + JSON.stringify(input) + ';\\n' +
    "document.getElementById('greet').textContent = q ? 'Hello, ' + q + '!' : 'Enter a name to see your greeting.';";
}
`,
  testExploit: `(function () {
// Exploit check: the payload ';__pwn();// must NOT execute __pwn().
// Returns true when the exploit SUCCEEDS (input broke out of the string).
var __pwned = false;
var __document = { getElementById: function () { return { set textContent(v) {} }; } };
var __code = vulnFn("';__pwn();//");
try { new Function('document', '__pwn', __code)(__document, function () { __pwned = true; }); } catch (e) {}
return __pwned;
})()`,
  testLegit: `(function () {
// Legit check: a normal name must stay a harmless string literal and the
// greeting must render. Returns true when legitimate use still works.
var __got = null;
var __document = {
  getElementById: function () {
    var el = {};
    Object.defineProperty(el, 'textContent', { set: function (v) { __got = v; } });
    return el;
  }
};
var __code = vulnFn('Alex');
new Function('document', __code)(__document);
return __got === 'Hello, Alex!';
})()`,
  exploitDescription: "Input lands raw inside a single-quoted JS string (var q = '...'). A single quote breaks out of the string, a semicolon ends the statement, injected code runs, and // comments out the leftover quote.",
  fixHint: 'Do not interpolate raw input into a script. Encode the value as a proper JS string literal with JSON.stringify (or a JS-string encoder) so quotes and backslashes can never break out.',
};
