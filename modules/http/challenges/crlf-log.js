'use strict';
// CRLF Log Injection: GET /http/track writes ?ref= raw into the access log,
// and GET /http/admin/log renders the log with no output encoding. The flag
// lands in the log viewer, only when this session's injected ref is present
// in the log AND the injection actually forged extra rendered lines.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { award, captured } = require('../../../lib/flags');
const {
  page, esc, brief, flagBox, fixPanel, hintLadder, toolsPill, payloadBlock,
} = require('../../../lib/page');

const router = express.Router();

// NOTE: created here with IF NOT EXISTS so this challenge file is
// self-contained; router.js used to create it at module load time.
getDb().exec(`CREATE TABLE IF NOT EXISTS http_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT, ref TEXT, ts TEXT
)`);

const vuln = {
  id: 'crlf-log',
  name: 'CRLF Log Injection',
  difficulty: 'Medium',
  hint: 'The ?ref= value is written raw into the access log. What happens to stored text that manages to contain line breaks?',
  hints: ["The ?ref= parameter is logged raw. In Burp Repeater, request /http/track with a plain ref value, then open the log viewer and see exactly what lands there.", "A log entry ends where a line break begins. URL encoding can carry characters that never appear literally in an address bar: think about which encoded bytes become a carriage return and a line feed once the server decodes them.", "Shape: a ref value, then encoded CR and LF bytes (%0d%0a), then the text of the line you want to forge. Send it in Repeater, then confirm in the log viewer that one stored entry renders as more lines than were written."],
  tools: 'BZ, B, C',
  est: 'about 10 to 20 minutes',
  how: 'A user-controlled value is written into a log without sanitizing line breaks, so a single entry can pretend to be several.',
  link: '/http#crlf-log',
  start: 'Send your browser through Burp Proxy. 1) Visit /http/track?ref=homepage and send the request to Repeater. 2) In Repeater, experiment with what the ref value can carry beyond plain text. 3) Request /http/admin/log in the same session and compare what the viewer renders with what you actually sent.',
};

// GET /http/track -> records this visit in the access log.
router.get('/track', (req, res) => {
  const ref = (req.query.ref || '').toString().slice(0, 500);
  const ip = req.ip || 'unknown';
  const ts = new Date().toISOString();
  getDb().prepare('INSERT INTO http_log (ip, ref, ts) VALUES (?, ?, ?)').run(ip, ref, ts);
  // VULN: the raw ref, CR/LF bytes included, is written to the access log with
  // no sanitization, so %0d%0a forges extra log lines (and HTML in the viewer).
  // No flag here: the award lands in the log viewer, only when the forged line
  // is actually observed there (evidence-based, not input-pattern-based).
  if (/[\r\n]/.test(ref)) {
    req.session.crlf_probe = ref;
  }
  res.send(page('Visit tracker', `
    ${brief('Visit tracker', `
      This demo site records every visit in its access log, along with the
      <code>ref</code> label you pass in the URL. The admins review the raw log
      in the log viewer.`)}
    <div class="clay-card">
      <h3>Visit tracked</h3>
      <p>Logged this visit from <code>${esc(ip)}</code> at <code>${esc(ts)}</code>.</p>
      ${/[\r\n]/.test(ref)
        ? '<p class="clay-well">CR/LF bytes were written straight into the access log. <a href="/http/admin/log"><b>Open the log viewer</b></a> and confirm your forged line appears there.</p>'
        : ''}
    </div>
    ${payloadBlock('Request shape', '/http/track?ref=<label><encoded line break><text for the forged line>')}
    ${hintLadder(vuln)}
    ${toolsPill(vuln)}
    <p class="next-steps">
      <a class="clay-btn clay-btn-primary" href="/http/admin/log">View the access log</a>
      <a class="clay-btn clay-btn-secondary" href="/http">Module index</a>
    </p>
  `));
});

// GET /http/admin/log -> raw access log viewer.
router.get('/admin/log', (req, res) => {
  const rows = getDb().prepare('SELECT ip, ref, ts FROM http_log ORDER BY id DESC LIMIT 100').all();
  // VULN: log lines are rendered raw; injected CR/LF splits lines and any HTML
  // in the ref value is parsed by the browser.
  const lines = rows.map((r) => `${r.ts} ${r.ip} ref=${r.ref}`).join('\n');
  let extra = '';
  // Evidence-based award (M7): the flag lands only when THIS session's injected
  // ref is present in the log AND the injection actually forged extra lines
  // (rendered lines outnumber stored rows). Visiting the viewer without a
  // successful injection earns nothing.
  const probe = req.session.crlf_probe;
  if (!captured(req, 'http', 'crlf-log') && probe &&
      rows.some((r) => r.ref === probe) &&
      lines.split('\n').length > rows.length) {
    const flag = award(req, 'http', 'crlf-log');
    extra = `<div class="clay-card">
      <h3>Forged log line confirmed</h3>
      <p>Your injected CR/LF bytes split the log: the viewer renders
      <b>${lines.split('\n').length}</b> lines from <b>${rows.length}</b> stored
      entries. The forged entry is really in there.</p>
      ${flagBox(flag)}${fixPanel('http', 'crlf-log')}
    </div>`;
  }
  res.send(page('Access log', `
    ${brief('Access log (admin view)', `
      Raw log, newest first. No output encoding is applied here.`)}
    <div class="clay-card">
      <div class="clay-well"><pre>${lines}</pre></div>
    </div>
    ${extra}
    <p class="next-steps">
      <a class="clay-btn clay-btn-secondary" href="/http">Module index</a>
    </p>
  `));
});

module.exports = { vuln, router };
