'use strict';
// Security Misconfiguration: a verbose debug error page. The app's status page
// says debug mode is off, but appending ?err=1 flips it into a build that dumps
// a full stack trace plus the internal config (with secrets) to any visitor.
const express = require('express');
const { appShell, esc, fixPanel, flagBox, hintLadder, page, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'debug',
  name: 'Verbose Debug Errors',
  difficulty: 'Easy',
  hint: 'The debug page behaves differently when the err query parameter is set. Try appending ?err=1 to the URL. Debug switches also hide behind other obvious parameter names.',
  hints: ["The debug page says 'off'. But there's a link to 'Simulate an error'. What does ?err=1 do?", "The err parameter triggers a verbose stack trace with a full config dump, including secrets.", "Open /misconfig/debug?err=1 and read the leaked config."],
  tools: 'B',
  how: 'Request /misconfig/debug?err=1 to trigger a verbose stack trace with a config dump.',
  link: '/misconfig#debug',
  start: 'curl -s "http://localhost:3000/misconfig/debug?err=1"',
};

// GET /misconfig/debug -> service status page for the (fictional) NovaPay
// merchant console. ?err=1 simulates an application error.
router.get('/debug', (req, res) => {
  if (req.query.err === '1') {
    // VULN: verbose error page leaks a full stack trace and internal config (secrets) to any visitor
    const flag = award(req, 'misconfig', 'debug');
    const stack = `Error: ENOENT: no such file or directory, open '/app/config/secrets.json'
    at Object.openSync (node:fs:596:3)
    at Object.readFileSync (node:fs:464:35)
    at loadConfig (/app/server.js:42:19)
    at Object.<anonymous> (/app/server.js:118:14)
    at Module._compile (node:internal/modules/cjs/loader:1378:14)
    at Module._extensions..js (node:internal/modules/cjs/loader:1437:10)
    at Module.load (node:internal/modules/cjs/loader:1212:32)
    at Function.executeUserEntryPoint [as runMain] (node:internal/modules/run_main:174:12) {
  errno: -2,
  code: 'ENOENT',
  syscall: 'open',
  path: '/app/config/secrets.json'
}

--- app config (debug build) ---
env: staging
node: v22.9.0
config: { dbPassword: 'Sup3rS3cretDb!', debugToken: 'dbg_live_token_9f2c41', apiKey: 'pk_live_9f2c41aa77' }
sessionSecret: 'keyboard-cat-do-not-use-in-prod'`;
    res.send(
      page(
        'Debug error',
        appShell('NovaPay Merchant Console', `
          <h2>Debug output</h2>
          <p class="dim">The request failed and the app printed everything it knew. In a staging
          build this is handy; in production it is a leak.</p>
          <div class="payload"><div class="payload-head"><span>Traceback</span></div><pre class="payload-body">${esc(stack)}</pre></div>
          ${flagBox(flag)}${fixPanel('misconfig', 'debug')}
          <p><a class="clay-btn clay-btn-secondary" href="/misconfig/debug">Back to status page</a></p>
        `, { nav: ['Dashboard', 'Payments', 'Support'], crumb: 'Support / Error details' })
      )
    );
    return;
  }
  res.send(
    page(
      'Debug page',
      appShell('NovaPay Merchant Console', `
        <h2>System status</h2>
        <p>All systems nominal. Debug mode is <b>off</b>: the console runs with safe
        defaults and error details are hidden from visitors.</p>
        ${hintLadder(vuln)}
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/misconfig/debug?err=1">Simulate an error</a></p>
        ${payloadBlock('Try from your terminal', 'curl -s "http://localhost:3000/misconfig/debug?err=1" | head -30')}
      `, { nav: ['Dashboard', 'Payments', 'Support'], crumb: 'Support / System status' })
    )
  );
});

module.exports = { vuln, router };
