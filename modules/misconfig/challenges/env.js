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
    hints: ["Use Burp to request a .env file in the web root (a well-known hidden filename). Check what the response returns.", ".env files hold production secrets (DB passwords, API keys). Scan the plain-text response body line by line in Repeater.", "The URL is /misconfig/.env. Read the ADMIN_API_TOKEN line in the response, that value is the flag."],
    tools: 'BZ, C',
    how: 'Request /misconfig/.env in Burp Repeater and read the secrets in the response.',
    link: '/misconfig#env',
    start: 'In Burp, with Proxy interception off, browse to the /misconfig page, then send GET /misconfig/.env to Repeater and forward it.',
  },
  router,
};
