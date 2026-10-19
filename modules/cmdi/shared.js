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
// second command really ran. The student's own input is scrubbed from the
// output first, so merely echoing a marker (e.g. ?host=uid= with no injection)
// cannot award. Plain substring checks used to false-positive on shell error
// text (e.g. "sh: 1: uid=: not found" contains the bare text "uid=" with zero
// real command output), so every check below is a real-output-shaped regex:
// structure that genuine command output has and shell error text never does.
//   id             -> "uid=1000(user) gid=..." (digits plus the name in parens;
//                   a failed "uid=999" attempt only yields "sh: 1: uid=999:
//                   not found", which has no parens)
//   cat /etc/passwd -> a full passwd line anchored at line start, e.g.
//                   "root:x:0:0:root:/root:/bin/bash" (bare "root:" from an
//                   echo never matches)
//   ls -l          -> "total 1234" at line start
const ID_EVIDENCE = /\b[ug]id=\d+\([^()\n]*\)/;
const PASSWD_EVIDENCE = /^(?:root|daemon):[^:\r\n]*:\d+:\d+:/m;
const EXEC_EVIDENCE = [ID_EVIDENCE, PASSWD_EVIDENCE, /^total \d+/m];
function executedSomething(out, inputs) {
  let s = String(out || '');
  for (const i of inputs) if (i) s = s.split(i).join('');
  return EXEC_EVIDENCE.some((re) => re.test(s));
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

module.exports = { APP_NAME, APP_NAV, pingForm, runPing, executedSomething, gadgetPage, ID_EVIDENCE, PASSWD_EVIDENCE };
