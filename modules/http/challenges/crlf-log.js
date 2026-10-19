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
  hint: 'The ?ref= value is written raw into the access log. What do %0d and %0a become after URL decoding?',
  hints: ["The ?ref= parameter is logged raw. What are %0d and %0a?", "CR/LF bytes. They split the log line and forge new entries.", "The server URL-decodes your ref before logging, so encoded carriage return and line feed characters become real line breaks in the log file. Put them inside a ref value so text after them lands on new forged lines, then open the log viewer and confirm your forged entry actually renders there."],
  tools: 'C',
  how: 'Send CR/LF bytes in ref so a forged line appears in the admin log view.',
  link: '/http#crlf-log',
  start: 'curl -s -c jar -b jar "http://localhost:3000/http/track?ref=homepage"\ncurl -s -c jar -b jar http://localhost:3000/http/admin/log',
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
    ${payloadBlock('Try this payload', '/http/track?ref=homepage%0d%0a2026-10-02 FAKE admin login from 10.9.9.9')}
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
