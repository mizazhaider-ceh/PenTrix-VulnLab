'use strict';
// Break-then-fix block for modules/xss/challenges/reflected.js (Reflected XSS).
// The student must replace unencoded interpolation of the search query with
// proper HTML entity encoding, so markup in the query is shown as text.
module.exports = {
  module: 'xss',
  vulnId: 'reflected',
  title: 'Reflected XSS: encode the echoed search term',
  language: 'javascript',
  vulnerableCode: `// VULNERABLE: the search term is echoed into the results page with no encoding.
function vulnFn(input) {
  var q = String(input);
  if (q) {
    return '<h3>Results for: ' + q + '</h3>';
  }
  return '<h3>Search the catalog</h3>';
}
`,
  fixedCode: `// FIXED: the search term is HTML entity encoded before it is rendered.
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
  var q = String(input);
  if (q) {
    return '<h3>Results for: ' + escapeHtml(q) + '</h3>';
  }
  return '<h3>Search the catalog</h3>';
}
`,
  testExploit: `vulnFn('<script>alert(1)</script>').indexOf('<script>') !== -1`,
  testLegit: `vulnFn('hello world').indexOf('hello world') !== -1`,
  exploitDescription: 'A classic reflected XSS payload like <script>alert(1)</script> typed into the search box is interpolated straight into the results page HTML, so the browser executes it when the page renders.',
  fixHint: 'Encode the untrusted search term before inserting it into the HTML. Convert &, <, >, double quotes and single quotes to their HTML entities (&amp;, &lt;, &gt;, &quot;, &#39;) so user input is always displayed as text, never parsed as markup.',
};
