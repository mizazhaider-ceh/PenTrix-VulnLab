'use strict';
// Process Environ Leak: the filename is appended to /proc/self/ with no
// validation, and /proc/self/environ exposes the whole process environment.
const express = require('express');
const path = require('path');
const { esc, page, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { PROC_TELL, docsPage, showCaptured, readFileCapped } = require('../shared');

const router = express.Router();

// ---- v8: /proc/self/environ ----
router.get('/procinfo', (req, res) => {
  const f = req.query.f || 'status';
  // VULN: the filename is appended to /proc/self/ with no validation, and
  // environ exposes the process environment, including secrets.
  const target = path.join('/proc/self', f);
  let body = `
    <p>Inspect this process. Pick a file, or pass your own:</p>
    <form class="clay-card" method="get" action="/lfi/procinfo">
      <div class="clay-field">
        <label for="lfi-procinfo-f">File</label>
        <input class="clay-input" type="text" id="lfi-procinfo-f" name="f" placeholder="status" value="${esc(f === 'status' ? '' : f)}">
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Inspect</button>
    </form>
    <p>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/lfi/procinfo?f=status">status</a>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/lfi/procinfo?f=cmdline">cmdline</a>
    </p>
    ${showCaptured(req, 'proc-self')}
  `;
  try {
    const r = readFileCapped(target);
    if (!r.ok) throw new Error(r.error);
    const data = r.data;
    body += `<h2>/proc/self/${esc(f)}</h2><pre>${esc(data)}</pre>`;
    // Real success only: the actual process environment was read.
    if (data.includes(PROC_TELL)) {
      const flag = award(req, 'lfi', 'proc-self');
      body += flagBox(flag) + fixPanel('lfi', 'proc-self');
    }
  } catch (e) {
    body += `<h2>Error reading <code>/proc/self/${esc(f)}</code></h2><pre>${esc(e.message)}</pre>`;
  }
  res.send(page('LFI - Process Info', docsPage('Settings / Process Info', `<h1>Process Info</h1>${body}`)));
});

module.exports = {
  vuln: {
    id: 'proc-self', name: 'Process Environ Leak', difficulty: 'Medium',
    hint: 'The process-info page appends your filename to <code>/proc/self/</code> with no checks. Most files there are boring. What does the process itself know that you would like to read?',
    hints: ["Linux exposes process info via /proc. What does /proc/self/environ contain?", "One file under /proc/self holds the process environment, in NUL-separated entries. Environments are where services keep the values they were started with. Read it via the filename parameter.", "Shape: the filename is appended straight onto /proc/self/. Send the request to Burp Repeater, name the environment file, and search the output for entries only the real process could have provided."],
    tools: "BZ, B",
    est: 'about 10 to 20 minutes',
    how: 'A filename parameter rooted at /proc/self turns a status page into a window on the process itself, environment included.',
    link: '/lfi/procinfo',
    start: 'Point your browser through Burp Proxy at your lab address, open /lfi/procinfo, and send the request to Repeater so you can tamper with the f parameter.',
  },
  router,
};
