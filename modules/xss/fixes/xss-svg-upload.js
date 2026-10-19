'use strict';
// M11 fix block: Stored XSS via SVG upload.
// Vulnerable behavior: the upload check only verifies the markup contains an
// <svg> element, then the file is stored and served as image/svg+xml, so any
// embedded script or event handler runs when the file is opened directly.
// Correct fix: validate the CONTENT of the SVG and reject active content.
module.exports = {
  module: 'xss',
  vulnId: 'xss-svg-upload',
  title: 'Stored XSS via SVG Upload: validate SVG content, reject active content',
  language: 'javascript',
  vulnerableCode: `// Self-contained model of the vulnerable SVG avatar upload.
// Mirrors modules/xss/challenges/xss-svg-upload.js: the only validation is
// that the markup contains an <svg> element. The stored file is later served
// as image/svg+xml, so any script or event handler inside runs when the file
// is opened directly in the browser.
function vulnFn(svgText) {
  const raw = String(svgText ?? '').slice(0, 20000);
  return /<svg[\\s>]/i.test(raw);
}`,
  fixedCode: `// Reference solution: validate the CONTENT of the SVG, not just its wrapper.
// Reject active content: script elements, event-handler attributes, javascript:
// URLs, foreignObject (which can embed HTML), and data: HTML payloads. Clean
// SVGs and raster PNGs are still accepted, so legitimate avatars keep working.
// Defense in depth on the real route: serve uploads with a safe content type
// (never image/svg+xml), Content-Disposition: attachment, or convert them to
// raster images on upload.
function vulnFn(svgText) {
  const raw = String(svgText ?? '').slice(0, 20000);
  // Raster images carry no active content; the real app stores and serves them
  // with an image/png content type.
  if (raw.charCodeAt(0) === 0x89 && raw.slice(1, 8) === 'PNG\\r\\n\\x1a\\n') return true;
  if (!/<svg[\\s>]/i.test(raw)) return false;
  const lower = raw.toLowerCase();
  if (/<script[\\s>]/.test(lower)) return false;
  if (/<foreignobject[\\s>]/.test(lower)) return false;
  if (/\\son[a-z]+\\s*=/i.test(raw)) return false;
  if (/javascript\\s*:/i.test(lower)) return false;
  if (/data\\s*:\\s*text\\/html/i.test(lower)) return false;
  return true;
}`,
  testExploit: `(() => {
  const viaScript = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
  const viaOnload = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="10" height="10"/></svg>';
  const viaJsUrl = '<svg xmlns="http://www.w3.org/2000/svg"><image href="javascript:alert(1)"/></svg>';
  return vulnFn(viaScript) || vulnFn(viaOnload) || vulnFn(viaJsUrl);
})()`,
  testLegit: `(() => {
  const cleanSvg = '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="40" fill="blue"/></svg>';
  return vulnFn(cleanSvg);
})()`,
  exploitDescription: 'The avatar upload only checks that the submitted markup contains an <svg> element. An attacker uploads an SVG with an embedded script tag (or an onload event handler, or a javascript: URL in an href). The file is stored and served back with Content-Type image/svg+xml, so when a victim opens the file link directly, the browser parses it as an XML document and the injected script runs in the site origin, where it can read cookies and call the flag claim endpoint.',
  fixHint: 'Checking for the <svg> wrapper is not validation, it is a wrapper check. Parse and validate the content: reject script elements, event-handler attributes (onload, onerror, and friends), javascript: URLs, foreignObject, and data: HTML payloads, using a real XML/HTML parser or sanitizer rather than ad-hoc string checks. As extra defense, serve uploaded files with a safe content type (never image/svg+xml), add Content-Disposition: attachment, or rasterize SVGs to PNG on upload.',
};
