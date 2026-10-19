'use strict';
module.exports = {
  module: 'xss',
  vulnId: 'xss-dom-clobber',
  title: 'DOM Clobbering: Never Trust window Properties You Did Not Set',
  language: 'javascript',
  vulnerableCode: `function stripScripts(html) {
  return String(html).replace(/<script\\b[^>]*>[\\s\\S]*?<\\/script\\s*>/gi, '');
}
// Models what the browser does: an element with id or name becomes a
// property of window, so a form with id="settings" containing an input
// named isAdmin makes window.settings.isAdmin truthy.
function wouldClobber(html) {
  var formSettings = /<form\\b[^>]*\\bid\\s*=\\s*["']?settings["']?[^>]*>/i.test(html);
  var namedControl = /<(?:input|img|select|textarea|button|object|embed|fieldset)\\b[^>]*(?:\\bname\\s*=\\s*["']?isAdmin["']?|\\bid\\s*=\\s*["']?isAdmin["']?)[^>]*>/i.test(html);
  return formSettings && namedControl;
}
// VULN: the sanitizer only strips <script> tags, so clobbering markup is
// stored and rendered raw, and the page script reads window.settings.isAdmin.
function vulnFn(html) {
  var rendered = stripScripts(html);
  return { rendered: rendered, adminSeen: wouldClobber(rendered) };
}`,
  fixedCode: `function sanitizeProfileHtml(html) {
  var s = String(html).replace(/<script\\b[^>]*>[\\s\\S]*?<\\/script\\s*>/gi, '');
  // FIX: remove any markup that could stand in for the page's settings object.
  s = s.replace(/<form\\b[^>]*\\bid\\s*=\\s*["']?settings["']?[^>]*>[\\s\\S]*?<\\/form\\s*>/gi, '');
  s = s.replace(/\\bname\\s*=\\s*["']?isAdmin["']?/gi, 'data-name="removed"');
  s = s.replace(/\\bid\\s*=\\s*["']?settings["']?/gi, 'data-id="removed"');
  return s;
}
// FIX: the admin decision no longer reads a clobberable window property.
// isAdmin comes from a server-controlled value the page markup cannot reach,
// so injected elements can never flip it.
function vulnFn(html) {
  var rendered = sanitizeProfileHtml(html);
  var serverIsAdmin = false; // set by the server session, never from DOM ids/names
  return { rendered: rendered, adminSeen: serverIsAdmin };
}`,
  testExploit: `vulnFn('<form id="settings"><input name="isAdmin" value="1"></form>').adminSeen === true`,
  testLegit: `(function () {
  var r = vulnFn('<b>Nothing here yet.</b>');
  return r.rendered.indexOf('<b>Nothing here yet.</b>') !== -1 && r.adminSeen === false;
})()`,
  exploitDescription: 'The profile HTML sanitizer only strips <script> tags, so <form id="settings"><input name="isAdmin" value="1"> is stored and rendered raw. Named and id-bearing elements become window properties, so the form shadows the page\'s own window.settings and window.settings.isAdmin reads the attacker\'s input, a truthy string. The page script sees a truthy isAdmin and reveals the admin panel, with no script tag and no beacon needed.',
  fixHint: 'Two layers. First, stop trusting window.settings: read the admin flag from a server-controlled value (a closure variable or session value) that page markup cannot reach through id or name attributes. Second, sanitize stored HTML against clobbering shapes too: strip or rewrite any element with id="settings", any control named isAdmin, and any form that could stand in for your globals. Stripping <script> tags alone never stops DOM clobbering because the attack uses plain form and input markup.',
};
