'use strict';
// M11 fix block: Stored XSS in the Maple Street Cafe guestbook.
// Vulnerable behavior: author and body are stored verbatim and rendered
// into the page with no output encoding, so a submitted script runs for
// every later visitor. Correct fix: HTML-encode untrusted data on output.
module.exports = {
  module: 'xss',
  vulnId: 'stored',
  title: 'Stored XSS: encode guestbook output',
  language: 'javascript',
  vulnerableCode: `// Self-contained model of the vulnerable guestbook.
// Comments are stored verbatim, then rendered raw into the page.
const guestbook = [];
function vulnFn(entry) {
  const author = String(entry.author ?? '').slice(0, 80);
  const body = String(entry.body ?? '').slice(0, 2000);
  guestbook.push({ author, body });
  return guestbook.map((c) =>
    '<article class="card">' +
    '<p><b>' + c.author + '</b></p>' +
    '<p>' + c.body + '</p>' +
    '</article>'
  ).join('\\n');
}`,
  fixedCode: `// Reference solution: encode author and body on OUTPUT.
// The store still keeps the original text; only the rendering is encoded,
// so no user data is lost and markup can never execute.
const guestbook = [];
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}
function vulnFn(entry) {
  const author = String(entry.author ?? '').slice(0, 80);
  const body = String(entry.body ?? '').slice(0, 2000);
  guestbook.push({ author, body });
  return guestbook.map((c) =>
    '<article class="card">' +
    '<p><b>' + esc(c.author) + '</b></p>' +
    '<p>' + esc(c.body) + '</p>' +
    '</article>'
  ).join('\\n');
}`,
  testExploit: `vulnFn({ author: 'attacker', body: '<script>alert(1)</script>' }).includes('<script>alert(1)</script>')`,
  testLegit: `(() => { const out = vulnFn({ author: 'izaz', body: 'The flat white was excellent.' }); return out.includes('<b>izaz</b>') && out.includes('<p>The flat white was excellent.</p>'); })()`,
  exploitDescription: 'An attacker posts a guestbook comment containing a script tag. Because the comment is stored verbatim and rendered unencoded, the script runs in every visitor\'s browser each time the guestbook page loads.',
  fixHint: 'The data is stored correctly; the flaw is at render time. Apply HTML output encoding to the author and body when building the article markup, so angle brackets and quotes become inert text instead of live markup.',
};
