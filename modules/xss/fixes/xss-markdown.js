'use strict';
module.exports = {
  module: 'xss',
  vulnId: 'xss-markdown',
  title: 'XSS via Naive Markdown Links: Allowlist URL Schemes',
  language: 'javascript',
  vulnerableCode: `function vulnFn(input) {
  var html = String(input);
  // VULN: link targets pass through with no scheme validation,
  // so javascript: URLs survive and run when the link is clicked.
  html = html.replace(/\\[([^\\]]+)\\]\\(((?:[^()\\s]|\\([^()\\s]*\\))+)\\)/g, '<a href="$2">$1</a>');
  html = html.replace(/\\*\\*([^*]+)\\*\\*/g, '<b>$1</b>');
  html = html.replace(/\\n/g, '<br>');
  return html;
}`,
  fixedCode: `function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
// Decode the HTML entities an attacker can hide the scheme behind
// (e.g. &#106;avascript: or &amp;#x6a;avascript:), repeatedly until stable.
function decodeEntities(s) {
  var prev = String(s);
  for (var i = 0; i < 5; i++) {
    var next = prev
      .replace(/&(amp|lt|gt|quot);/g, function (m, name) {
        return { amp: '&', lt: '<', gt: '>', quot: '"' }[name];
      })
      .replace(/&#x([0-9a-fA-F]+);?/g, function (m, h) {
        return String.fromCharCode(parseInt(h, 16));
      })
      .replace(/&#([0-9]+);?/g, function (m, d) {
        return String.fromCharCode(parseInt(d, 10));
      });
    if (next === prev) return next;
    prev = next;
  }
  return prev;
}
// Allowlist check: only http, https, mailto and scheme-relative/relative
// URLs are safe. javascript:, data:, vbscript: and friends are rejected,
// even when obfuscated with entities, case tricks or hidden whitespace.
function isSafeUrl(url) {
  var cleaned = decodeEntities(url).replace(/[\\u0000-\\u0020]/g, '');
  var m = cleaned.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (!m) return true;
  var scheme = m[1].toLowerCase();
  return scheme === 'http' || scheme === 'https' || scheme === 'mailto';
}
function vulnFn(input) {
  // Escape everything first so raw HTML and link text cannot inject markup.
  var html = escHtml(String(input));
  html = html.replace(/\\[([^\\]]+)\\]\\(((?:[^()\\s]|\\([^()\\s]*\\))+)\\)/g, function (m, text, url) {
    if (!isSafeUrl(url)) return text; // drop the link, keep plain text
    return '<a href="' + url + '">' + text + '</a>';
  });
  html = html.replace(/\\*\\*([^*]+)\\*\\*/g, '<b>$1</b>');
  html = html.replace(/\\n/g, '<br>');
  return html;
}`,
  testExploit: `(function () {
// A browser decodes entities inside href and strips hidden
// whitespace/control chars, so these all run as javascript: URLs.
function browserJsUrl(href) {
  var u = href
    .replace(/&(amp|lt|gt|quot);/g, function (m, n) {
      return { amp: '&', lt: '<', gt: '>', quot: '"' }[n];
    })
    .replace(/&#x([0-9a-fA-F]+);?/g, function (m, h) {
      return String.fromCharCode(parseInt(h, 16));
    })
    .replace(/&#([0-9]+);?/g, function (m, d) {
      return String.fromCharCode(parseInt(d, 10));
    })
    .replace(/[\\u0000-\\u0020]/g, '');
  return /^javascript:/i.test(u);
}
function anyJsLink(html) {
  var m = /href="([^"]*)"/g, hit;
  while ((hit = m.exec(html)) !== null) {
    if (browserJsUrl(hit[1])) return true;
  }
  return false;
}
return anyJsLink(vulnFn('[x](javascript:alert(1))')) ||
anyJsLink(vulnFn('[x](&#106;avascript:alert(1))')) ||
anyJsLink(vulnFn('[x](jav&#x09;ascript:alert(1))')) ||
anyJsLink(vulnFn('[x](JaVaScRiPt:alert(1))'));
})()`,
  testLegit: `(function () {
var out = vulnFn('Meeting notes: **agenda** and a [link](https://example.com)\\nnext line');
return out.indexOf('<b>agenda</b>') !== -1 &&
out.indexOf('<a href="https://example.com">link</a>') !== -1 &&
out.indexOf('<br>') !== -1;
})()`,
  exploitDescription: 'The naive markdown renderer turns [text](url) into <a href="url">text</a> without checking the URL scheme. The payload [x](javascript:alert(1)) renders as a live javascript: link that runs code when clicked. Obfuscated variants work too: &#106;avascript: (entity-encoded "j"), jav&#x09;ascript: (hidden tab inside the scheme) and JaVaScRiPt: (case trick) all decode to javascript: once the browser parses the href.',
  fixHint: 'Validate every link target against an allowlist of safe schemes (http, https, mailto, plus relative URLs). Before checking, decode HTML entities in the URL (repeatedly, until stable) and strip hidden control characters and whitespace, because the browser does the same when it parses href. Reject anything else by rendering the link text without the anchor. Also HTML-escape all input up front so link text and stray markup cannot inject tags.',
};
