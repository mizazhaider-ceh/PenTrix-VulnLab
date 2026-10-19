// Shared SSTI engine for the ssti module challenges.
// (No 'use strict' here: the vulnerable renderer relies on `with`, which
// strict mode forbids. This keeps behavior identical to the pre-split router.)
// VULN: with(scope) puts server-side secret variables in the eval scope chain,
// mirroring how the basic lab leaks its closure variables.
function sstiRender(tpl, scope) {
  // VULN: naive template engine eval()s anything inside {{ }} with attacker input in the template
  return tpl.replace(/\{\{(.*?)\}\}/g, (_, e) => {
    try {
      with (scope) { return eval(e); }
    } catch (err) { return ''; }
  });
}

module.exports = { sstiRender };
