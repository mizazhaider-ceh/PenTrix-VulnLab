'use strict';
// Break-then-fix block for modules/xss/challenges/dom.js (DOM-based XSS).
// The student must stop the location.hash fragment from being parsed as HTML
// when it reaches the innerHTML sink, either by writing it with textContent
// or by fully encoding it before it touches innerHTML.
module.exports = {
  module: 'xss',
  vulnId: 'dom',
  title: 'DOM XSS: never feed the URL fragment into innerHTML',
  language: 'javascript',
  vulnerableCode: `// VULNERABLE: the URL fragment (location.hash.slice(1)) is decoded and
// assigned straight into innerHTML, so markup in the fragment is parsed.
function vulnFn(input) {
  var raw = String(input);
  try { raw = decodeURIComponent(raw); } catch (e) { /* keep the raw fragment */ }
  return raw; // sink: document.getElementById('out').innerHTML = raw;
}
`,
  fixedCode: `// FIXED: the fragment is HTML entity encoded before it reaches the sink.
// Markup is now displayed as text instead of being parsed. The equivalent
// client-side fix is: document.getElementById('out').textContent = raw;
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c];
  });
}
function vulnFn(input) {
  var raw = String(input);
  try { raw = decodeURIComponent(raw); } catch (e) { /* keep the raw fragment */ }
  return escapeHtml(raw); // safe: sink receives encoded text, never live markup
}
`,
  testExploit: `vulnFn(encodeURIComponent('<img src=x onerror=alert(1)>')).indexOf('<img src=x onerror=') !== -1`,
  testLegit: `vulnFn(encodeURIComponent('Welcome back, Sam')).indexOf('Welcome back, Sam') !== -1`,
  exploitDescription: 'A greeting link of the form /xss/dom#<img src=x onerror=...> is crafted so the URL fragment contains an image tag with an event handler. The page copies location.hash into innerHTML without encoding, so the handler executes in the victim browser (a <script> tag would not run when inserted through innerHTML, which is why an event handler payload is used). The server never sees the fragment, so this is purely client-side.',
  fixHint: 'Treat the URL fragment as untrusted text, never as HTML. Two correct fixes: (1) write the fragment with textContent instead of innerHTML, which never parses markup; or (2) HTML entity encode &, <, >, double quotes and single quotes before it reaches innerHTML, so any markup is displayed as plain text.',
};
