'use strict';
module.exports = {
  module: 'xss',
  vulnId: 'xss-backtick',
  title: 'XSS in a Template Literal',
  language: 'javascript',
  vulnerableCode: `// Simulates the vulnerable server code: user input is reflected
// raw inside a JavaScript template literal.
function vulnFn(userInput) {
  return 'var msg = \`' + userInput + '\`;\\n      document.getElementById("status").textContent = msg || "No status set.";';
}`,
  fixedCode: `// Reference fix: escape user input for the template literal context
// before reflecting it. Backslash first, then backtick, then the \${ sequence.
function jsTemplateEscape(s) {
  return String(s)
    .replace(/\\\\/g, '\\\\\\\\')
    .replace(/\`/g, '\\\\\`')
    .replace(/\\$\\{/g, '\\\\\\$\\{');
}
function vulnFn(userInput) {
  return 'var msg = \`' + jsTemplateEscape(userInput) + '\`;\\n      document.getElementById("status").textContent = msg || "No status set.";';
}`,
  testExploit: `(function () {
// True means THE EXPLOIT SUCCEEDED: the beacon fetch to /xss/collect fired.
var fetched = null;
var fetch = function (u) { fetched = u; };
var document = { cookie: 'session=xyz', getElementById: function (id) { return {}; } };
var window = { __px: 'nonce-1' };
var msg;
try {
  eval(vulnFn('\${' + "fetch('/xss/collect?c='+document.cookie+'&v=xss-backtick&n='+window.__px)" + '}'));
} catch (e) {}
return fetched !== null && fetched.indexOf('/xss/collect') === 0 && fetched.indexOf('v=xss-backtick') !== -1;
})()`,
  testLegit: `(function () {
// True means LEGITIMATE use still works: a normal status message
// renders as the page message under both the old and fixed code.
var document = { cookie: '', getElementById: function (id) { return {}; } };
var msg;
var m1, m2;
try { eval(vulnFn('Heads down until 3pm, ping me later')); } catch (e) {}
m1 = msg;
try { eval(vulnFn("Lunch at 12? Don't wait up!")); } catch (e) {}
m2 = msg;
return m1 === 'Heads down until 3pm, ping me later' && m2 === "Lunch at 12? Don't wait up!";
})()`,
  exploitDescription: 'User input is reflected raw inside a JavaScript template literal, so a ${...} expression injected as the status message is evaluated as code when the page runs var msg = `...`. The payload ${fetch(...)} fires the beacon to /xss/collect without needing to break out of anything.',
  fixHint: 'Escape the input for the template literal context before reflecting it: escape backslashes first, then backticks, then the ${ sequence. Injected text then renders as a literal string and can never start an expression.',
};
