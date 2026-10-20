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
    hint: 'The process-info page appends your filename to <code>/proc/self/</code> with no checks. Most files there are boring, but one of them holds the whole environment, secrets included. Its entries are NUL-separated.',
    hints: ["Linux exposes process info via /proc. What does /proc/self/environ contain?", "The environ file has the process environment, including secrets. Read it via the filename parameter.", "The filename is appended straight onto /proc/self/. Send the request to Burp Repeater, ask for the file that holds the entire process environment (NUL-separated), and search the output for the marker."],
    tools: "BZ, B",
    how: 'Read /proc/self/environ through /lfi/procinfo with Burp Repeater.',
    link: '/lfi/procinfo',
    start: 'Point your browser through Burp Proxy at your lab address, open /lfi/procinfo, and send the request to Repeater so you can tamper with the f parameter.',
  },
  router,
};
