'use strict';
// HTTP TRACE Enabled (XST): TRACE /misconfig/trace reflects the entire
// request back to the sender, headers included (the classic XST primitive).
const express = require('express');
const { page, esc, hintBox, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'trace',
  name: 'HTTP TRACE Enabled (XST)',
  difficulty: 'Easy',
  hint: 'TRACE echoes the request back to the sender. Browsers cannot send it, but curl can: curl -X TRACE.',
  hints: ["The TRACE method echoes your request. Why is that dangerous?", "TRACE reflects headers, enabling XST (cross-site tracing) to steal HttpOnly cookies via XSS.", "Send TRACE /misconfig/ and watch your headers come back."],
  tools: 'C',
  how: 'Send a TRACE request to /misconfig/trace and read the reflected request.',
  link: '/misconfig/trace',
  start: 'curl -s -X TRACE -H "Cookie: session=abc123" http://localhost:3000/misconfig/trace',
};

// GET /trace -> explainer page: browsers cannot send TRACE, curl can.
router.get('/trace', (req, res) => {
  res.send(
    page(
      'TRACE endpoint',
      `<h2>TRACE is enabled here</h2>
      <p>A <code>TRACE</code> request to this URL gets the full request reflected
      back, headers included. That is the setup for a cross-site tracing (XST)
      attack: trick a victim's browser into sending one, and the reflected
      <code>Cookie</code> header leaks their session.</p>
      <p class="dim">Browsers cannot send TRACE; use curl:</p>
      <pre><code>curl -X TRACE http://localhost:3000/misconfig/trace -H "Cookie: session=abc123"</code></pre>
      ${hintBox('Send the TRACE request and watch your headers come back at you.')}`
    )
  );
});

// TRACE /trace -> reflects the whole request, the classic XST primitive.
router.trace('/trace', (req, res) => {
  // VULN: TRACE is enabled and reflects the entire request, the classic XST primitive
  const flag = award(req, 'misconfig', 'trace');
  const head = Object.entries(req.headers)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`)
    .join('\n');
  res.send(
    page(
      'TRACE reflection',
      `<h2>TRACE /misconfig/trace</h2>
      <p class="dim">The server reflected your exact request. Note the
      <code>Cookie</code> header coming straight back: that is what XST steals.</p>
      <pre>TRACE /misconfig/trace HTTP/1.1\n${esc(head)}</pre>
      ${flagBox(flag)}${fixPanel('misconfig', 'trace')}`
    )
  );
});

module.exports = { vuln, router };
