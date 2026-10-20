'use strict';
// Shared helpers for the Command Injection challenges: the ping form, the
// command runner, the exploit-evidence check, and the page chrome that every
// challenge file below reuses. No routes, no vuln, so it is not a challenge.
const { exec } = require('child_process');
const { appShell, brief, esc, hintLadder, page, payloadBlock } = require('../../lib/page');

const APP_NAME = 'NetProbe Ops Console';
const APP_NAV = ['Dashboard', 'Diagnostics', 'Incidents'];

// Clay-styled ping form, posted as a GET so the host value shows up in the URL.
function pingForm(action, host) {
  return `<form method="get" action="${esc(action)}" class="clay-card">
    <div class="clay-field">
      <label for="host">Host to ping</label>
      <input class="clay-input" id="host" name="host" value="${esc(host)}" size="48" autocomplete="off" />
    </div>
    <button class="clay-btn clay-btn-primary" type="submit">Run diagnostic</button>
  </form>`;
}

// Shared ping runner. Calls done(outputHtml, rawOutput).
function runPing(host, done) {
  // VULN: user input is concatenated into a shell command with no escaping.
  exec(`ping -c 1 ${host}`, { timeout: 8000 }, (err, stdout, stderr) => {
    const out = (stdout || '') + (stderr || '');
    let html = `<h3>Command output</h3><pre>${esc(out)}</pre>`;
    if (err && !out) {
      // ping binary may be missing on the host; show the raw error so the
      // injected command output is still visible to the learner.
      html = `<h3>Command output</h3><pre>${esc(String(err.message || err))}</pre>`;
    }
    done(html, out);
  });
}

// Decide whether the injection actually went through.
// Verification model: the flag is awarded only when the shell output proves a
// second command really ran. Real-output-shaped regexes are used: structure
// that genuine command output has and shell error text never does.
//   id             -> "uid=1000(user) gid=..." (digits plus the name in parens)
//   cat /etc/passwd -> a full passwd line anchored at line start, e.g.
//                   "root:x:0:0:root:/root:/bin/bash"
//   ls -l          -> "total 1234" at line start
//
// Anti-spoof rule (quoted echo): any evidence-shaped text that also appears
// in the student's own input, in raw form or with its quote marks stripped,
// cannot count. A payload like ;echo "uid=1000(root)" makes the shell print
// exactly that string (the shell removes the quotes), so the evidence in the
// output is just the student's own text coming back. Variants cover single
// quotes, double quotes, backticks, backslash escapes and $'...' quoting:
// the text is compared after stripping those characters from the input, so
// an echoed copy never matches, while genuine command output (which is
// nowhere in the input) always does.
const ID_EVIDENCE = /\b[ug]id=\d+\([^()\n]*\)/;
const PASSWD_EVIDENCE = /^(?:root|daemon):[^:\r\n]*:\d+:\d+:/m;
const EXEC_EVIDENCE = [ID_EVIDENCE, PASSWD_EVIDENCE, /^total \d+/m];

function inputVariants(inputs) {
  const variants = [];
  for (const i of inputs || []) {
    if (!i) continue;
    const raw = String(i);
    variants.push(raw);
    const noQuotes = raw.replace(/["'`]/g, '');
    if (noQuotes !== raw) variants.push(noQuotes);
    const noEscapes = raw.replace(/["'`\\$]/g, '');
    if (noEscapes !== raw && noEscapes !== noQuotes) variants.push(noEscapes);
  }
  return variants;
}

// True when `out` contains at least one evidence-shaped match that is NOT
// contained in any input variant (i.e. not a quoted echo of the input).
function evidenceInOutput(out, inputs, evidence) {
  const list = (Array.isArray(evidence) ? evidence : [evidence]).filter(Boolean);
  const variants = inputVariants(inputs);
  const s = String(out || '');
  for (const re of list) {
    const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
    const global = new RegExp(re.source, flags);
    for (const m of s.matchAll(global)) {
      const hit = m[0];
      if (!hit) continue;
      if (!variants.some((v) => v.includes(hit))) return true;
    }
  }
  return false;
}

function executedSomething(out, inputs) {
  // Kept for the gadgets that accept any of the standard evidences; now uses
  // the echo-proof check above.
  return evidenceInOutput(out, inputs, EXEC_EVIDENCE);
}

// Full page for a ping gadget challenge. opts:
//   v: the vuln metadata object (used for title, hint ladder)
//   route: the path segment under /cmdi (e.g. 'ping3')
//   host: the raw value the student submitted (undefined on first load)
//   briefHtml: the challenge-specific explanation of what changed
//   filtered: the value actually sent to the shell, if different from host
//   resultHtml: the rendered command-output block, once run
//   flagHtml: the flag banner plus fix panel, once captured
function gadgetPage(opts) {
  const v = opts.v;
  const action = '/cmdi/' + opts.route;
  const host = opts.host !== undefined ? opts.host : '127.0.0.1';
  const showFiltered = opts.filtered !== undefined && opts.filtered !== opts.host;
  const body = `
    ${brief('Diagnostic tool', opts.briefHtml)}
    ${pingForm(action, host)}
    ${showFiltered ? payloadBlock('Sanitized value sent to the shell', opts.filtered) : ''}
    ${opts.resultHtml || ''}
    ${opts.flagHtml || ''}
    ${hintLadder(v)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/cmdi">Back to Command Injection</a></p>
  `;
  return page(v.name, appShell(APP_NAME, body, { crumb: 'Diagnostics / ' + v.name, nav: APP_NAV }));
}

module.exports = { APP_NAME, APP_NAV, pingForm, runPing, executedSomething, evidenceInOutput, gadgetPage, ID_EVIDENCE, PASSWD_EVIDENCE };
