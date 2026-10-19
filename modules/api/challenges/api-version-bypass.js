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
    hints: ["v1 checks that you only read your own record. v2 was added later by copying v1.", "Compare the authorization logic between versions. Copy-paste often drops the check.", "Request the same user id through v1 and v2; one of them forgets to verify ownership."],
    tools: 'C',
    how: 'Log in as alice, confirm v1 blocks you from reading user 3, then read the same record through v2.',
    link: '/api#api-version-bypass',
    start: 'curl -s -b jar -c jar http://localhost:3000/api/login/alice\ncurl -s -b jar http://localhost:3000/api/v1/users/3',
  },
  router,
};
