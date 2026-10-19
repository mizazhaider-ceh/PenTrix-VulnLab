'use strict';
// Log Poisoning Chain: the raw User-Agent header is appended to the access
// log with no filtering, and the document viewer (traversal.js) can read that
// log back via a traversal payload, chaining injection into disclosure.
const express = require('express');
const fs = require('fs');
const { esc, page } = require('../../../lib/page');
const { LOG_PATH, LOG_MARKER, docsPage, showCaptured, readTailCapped, MAX_READ_BYTES } = require('../shared');

const router = express.Router();

// ---- v7: log poisoning chain ----
router.get('/log-demo', (req, res) => {
  const ua = req.get('User-Agent') || '-';
  try {
    // VULN: the raw User-Agent header is appended to the access log with no filtering.
    // Keep the log from growing without bound (every visit appends a line):
    // past 1 MiB, retain only the tail before appending.
    try {
      const st = fs.statSync(LOG_PATH);
      if (st.size > 1024 * 1024) {
        const tail = fs.readFileSync(LOG_PATH, 'utf8').slice(-262144);
        fs.writeFileSync(LOG_PATH, tail);
      }
    } catch (e) { /* no log yet, or unreadable: append anyway */ }
    fs.appendFileSync(LOG_PATH, new Date().toISOString() + ' ' + (req.ip || '-') +
      ' "' + ua.replace(/[\r\n"]/g, "'") + '"\n');
  } catch (e) { /* render the page anyway */ }
  let tail = '(log is empty so far)';
  try {
    const r = readTailCapped(LOG_PATH, MAX_READ_BYTES);
    if (r.ok) tail = r.data.trim().split('\n').slice(-10).join('\n');
  } catch (e) { /* keep placeholder */ }
  res.send(page('LFI - Access Log Demo', docsPage('Settings / Access Log', `
    <h1>Access Log Demo</h1>
    <p>Every visit here appends your <code>User-Agent</code> header to the server's
    access log, exactly as sent. The log lives at <code>lfi_access.log</code> next to
    this module, and the document viewer can read it with a traversal payload.</p>
    <p>Your marker for this lab: <code>${esc(LOG_MARKER)}</code>. Plant it in your
    User-Agent: intercept the request in Burp Proxy, edit the
    <code>User-Agent</code> header, then forward it. Then read the log back
    through
    <a href="/lfi/view?file=readme.txt">the document viewer</a> with
    <code>?file=../lfi_access.log</code>. The flag is awarded when your marker
    shows up in the file the LFI returns.</p>
    <h2>Recent log lines</h2>
    <pre>${esc(tail)}</pre>
    ${showCaptured(req, 'log-poison')}
  `)));
});

module.exports = {
  vuln: {
    id: 'log-poison', name: 'Log Poisoning Chain', difficulty: 'Hard',
    hint: 'Two steps: first, plant a recognizable marker string in the access log by visiting <code>/lfi/log-demo</code> with a custom User-Agent. Then read that log back through the document viewer using traversal, so the poisoned entry is included.',
    hints: ["You need to read a file you can write to. What files does the app write that you influence? The /lfi/log-demo page names it.", "The access log records your User-Agent. In Repeater, re-send the log-demo request with a recognizable marker string in the User-Agent header, then include the log via traversal.", "You control your User-Agent, and the access log is just a file you can include. Poison it in Repeater with a recognizable marker, then pull the log back through the viewer with traversal so the poisoned entry gets read."],
    tools: "BZ, C",
    how: 'In Repeater, poison the access log by editing the User-Agent header on /lfi/log-demo, then read the log back through /lfi/view with a traversal payload.',
    link: '/lfi/log-demo',
    start: 'Visit /lfi/log-demo through Burp Proxy, send the request to Repeater (Ctrl+R), then edit the User-Agent header there to plant your marker and send it.',
  },
  router,
};
