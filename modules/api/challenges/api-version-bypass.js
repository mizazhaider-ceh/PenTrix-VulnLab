'use strict';
// API version authorization bypass: v2 was copied from v1 without its ownership check.
const express = require('express');
const { award } = require('../../../lib/flags');
const { requireLogin, userRow } = require('../shared');

const router = express.Router();

router.get('/v1/users/:id', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const target = userRow(req.params.id);
  if (!target) return res.status(404).json({ ok: false, error: 'No such user.' });
  // v1 does it right: you may read your own record, or any record as admin.
  if (Number(req.params.id) !== user.id && user.role !== 'admin') {
    return res.status(403).json({ ok: false, error: 'Forbidden: you can only view your own record.' });
  }
  res.json({ ok: true, user: target });
});

router.get('/v2/users/:id', (req, res) => {
  const user = requireLogin(req, res);
  if (!user) return;
  const target = userRow(req.params.id);
  if (!target) return res.status(404).json({ ok: false, error: 'No such user.' });
  // VULN: v2 was copy-pasted from v1 but the authorization check never made
  // it over, so any logged-in user can read anyone's full record.
  let flag = null;
  if (Number(req.params.id) !== user.id && user.role !== 'admin') {
    flag = award(req, 'api', 'api-version-bypass');
  }
  res.json({ ok: true, user: target, flag });
});

module.exports = {
  vuln: {
    id: 'api-version-bypass',
    name: 'API Version AuthZ Bypass',
    difficulty: 'Medium',
    hint: 'GET /api/v1/users/:id checks that you only read your own record (unless admin). Somebody copy-pasted the route for v2 and forgot the check.',
    hints: [
      "Log in as alice with Burp's Proxy on, then browse to /api/v1/users/3 and read the 403 response.",
      "Send that v1 request to Repeater (Ctrl+R) and tweak the version segment in the path. Compare the two responses.",
      "v1 checks ownership before answering. v2 was copy-pasted from v1, but the check never made it over."
    ],
    tools: 'BZ, C',
    how: 'Log in as alice, send a request for user 3 to Repeater, confirm v1 answers 403, then flip the path version to v2 and resend to read the record and collect the flag.',
    link: '/api#api-version-bypass',
    start: 'Route your browser through Burp Proxy, visit http://localhost:3000/api/login/alice to log in, then browse to http://localhost:3000/api/v1/users/3 and send that request to Repeater (Ctrl+R).',
  },
  router,
};
