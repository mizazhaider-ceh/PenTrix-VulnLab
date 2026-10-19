'use strict';
// Exposed .env: GET /misconfig/.env serves production secrets as plain text.
const express = require('express');
const { award } = require('../../../lib/flags');

const router = express.Router();

// GET /.env -> the production environment file ended up web-accessible and is served raw.
router.get('/.env', (req, res) => {
  // VULN: environment file with production secrets served to anyone who asks
  const flag = award(req, 'misconfig', 'env');
  res.type('text/plain').send(
    `# production environment - DO NOT COMMIT\n` +
    `NODE_ENV=production\n` +
    `DB_URL=postgres://app:Sup3rS3cretDb!@db.internal:5432/app\n` +
    `STRIPE_SECRET_KEY=sk_live_9f2c41aa77\n` +
    `SESSION_SECRET=keyboard-cat-do-not-use-in-prod\n` +
    `ADMIN_API_TOKEN=${flag}\n`
  );
});

module.exports = {
  vuln: {
    id: 'env',
    name: 'Exposed .env File',
    difficulty: 'Medium',
    hint: 'Twelve-factor apps keep secrets in environment files. One of them ended up web-accessible.',
    hints: ["Is there a .env file in the web root?", ".env has production secrets (DB passwords, API keys). It's served as plain text.", "Work out the URL of the exposed environment file (a well-known hidden filename served from the web root), request it, and scan the output for production secrets."],
    tools: 'C',
    how: 'Download /misconfig/.env and read the secrets inside.',
    link: '/misconfig#env',
    start: 'curl -s http://localhost:3000/misconfig/.env',
  },
  router,
};
