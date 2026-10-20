'use strict';
// Excessive data exposure: GET /api/users returns whole database rows.
const express = require('express');
const { esc, brief, flagBox, fixPanel, page } = require('../../../lib/page');
const { award, captured, flagFor } = require('../../../lib/flags');
const { userTable } = require('../shared');

const router = express.Router();

// The admin row's secret is a real per-deployment credential and the sqli
// labs' exfiltration target. It is masked here in every response: the
// demonstrated vulnerability is the leaked password field, not the secret.
function maskedRows() {
  return userTable().map((row) => ({ ...row, secret: '[REDACTED]' }));
}

// GET /api/users -> v2 excessive data exposure.
// VULN: the API returns full user rows; every field except the secret leaks,
// including the password, because the response is the raw row, not a DTO.
router.get('/users', (req, res) => {
  const rows = maskedRows();
  const json = JSON.stringify(rows);
  if (json.includes('"password"')) {
    const flag = award(req, 'api', 'exposure');
    res.set('X-Pentrix-Flag', flag);
  }
  res.json(rows);
});

// GET /api/users/view -> browser-friendly rendering of the same endpoint.
// This page NEVER awards the flag: it is only a viewer. Capturing the flag
// requires fetching the raw API (GET /api/users) and reading the leaked
// fields, which is the documented starting exploit. The secret field stays
// masked here too.
router.get('/users/view', (req, res) => {
  const rows = maskedRows();
  const json = JSON.stringify(rows, null, 2);
  let flagHtml = '';
  if (captured(req, 'api', 'exposure')) {
    flagHtml = flagBox(flagFor('api', 'exposure')) + fixPanel('api', 'exposure');
  }
  res.send(page('API: excessive data', `
    ${brief('Excessive Data Exposure', `This page renders the response of <code>GET /api/users</code>.
      Real APIs often return whole database rows; the <code>password</code> field
      below was never meant to leave the server. The <code>secret</code> field is
      masked in this viewer; only fetching the raw API response earns the flag.`)}
    ${flagHtml}
    <pre>${esc(json)}</pre>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/api">Back to the module index</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'exposure',
    name: 'Excessive Data Exposure',
    difficulty: 'Easy',
    est: '5-10 minutes',
    hint: 'GET /api/users runs SELECT * and returns the rows as JSON. The viewer page renders only part of that story, so fetch the raw response in Burp and compare it with what the viewer chooses to show.',
    hints: ["Browse /api/users/view with Burp Proxy on, then find the GET /api/users request in the Proxy history.", "Send that request to Repeater and resend it: compare what the viewer rendered against the full JSON response.", "Read the whole Repeater response from the first line down, not only the part the viewer rendered. The API sends more than the page ever displays."],
    tools: 'BZ, B',
    how: 'The viewer shows a cleaned-up picture of the user list. The raw API response tells a fuller story: compare them field by field.',
    link: '/api/users/view',
    start: 'Browse to /api/users/view with Burp Proxy enabled, find GET /api/users in the Proxy history, send it to Repeater, and inspect the full response.',
  },
  router,
};
