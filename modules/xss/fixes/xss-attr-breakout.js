'use strict';
module.exports = {
  module: 'xss',
  vulnId: 'xss-attr-breakout',
  title: 'XSS via Attribute Breakout: Encode Before Reflecting into an Attribute',
  language: 'javascript',
  vulnerableCode: `function vulnFn(input) {
  return '<input type="text" id="preview-nick" value="' + String(input) + '" readonly>';
}`,
  fixedCode: `function escAttr(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function vulnFn(input) {
  return '<input type="text" id="preview-nick" value="' + escAttr(input) + '" readonly>';
}`,
  testExploit: `vulnFn('" onmouseover="alert(1)').indexOf('onmouseover="alert(1)"') !== -1`,
  testLegit: `vulnFn('nightowl42').indexOf('value="nightowl42"') !== -1`,
  exploitDescription: 'User input is reflected raw inside a double-quoted HTML attribute (value="..."). The payload " onmouseover="alert(1) closes the value attribute with an unescaped quote, then injects a live event-handler attribute that runs JavaScript on hover. A raw <script> tag payload like "><script>...</script> also breaks out of the attribute into the page body.',
  fixHint: 'Context matters. Before placing untrusted input inside an HTML attribute, attribute-encode it: replace & with &amp;, < with &lt;, > with &gt;, and the double quote with &quot;, then always wrap the attribute value in double quotes. Encoding the quote stops the breakout, encoding < stops tag injection, and encoding & first prevents double-encoding bugs.',
};
