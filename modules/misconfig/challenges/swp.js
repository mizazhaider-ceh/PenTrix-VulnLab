'use strict';
// Vim Swap File Leak: GET /misconfig/app.js.swp serves a leftover editor
// backup artifact whose recovered source contains secrets.
const express = require('express');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'swp',
  name: 'Vim Swap File Leak',
  difficulty: 'Easy',
  hint: 'Editors leave backup artifacts next to the files they edit. The running app is app.js; what would its swap file be called?',
  hints: ["Vim swap files end in .swp. Is there one in the web root?", "The .swp file has the source with secrets. It's a backup the editor left behind.", "Vim builds the swap name by wrapping the edited filename: a leading dot, then the filename, then .swp. The app entry file here is app.js. Build that name, request it from the web root, and read the recovered source for the embedded secret."],
  tools: 'C',
  how: 'Download /misconfig/app.js.swp and read the recovered source for secrets.',
  link: '/misconfig/app.js.swp',
  start: 'curl -s http://localhost:3000/misconfig/app.js.swp',
};

// GET /app.js.swp -> the leftover vim swap file, served as plain text.
router.get('/app.js.swp', (req, res) => {
  // VULN: editor backup artifact left in the web root, recoverable source included
  const flag = award(req, 'misconfig', 'swp');
  res.type('text/plain').send(
    `b0VIM 9.0  swap file for "app.js" - recovered, do not delete\n` +
    `# local dev notes - DO NOT COMMIT\n` +
    `const db = connect(process.env.DB_URL); // postgres://app:Sup3rS3cretDb!@db.internal:5432/app\n` +
    `const STRIPE_KEY = 'sk_live_9f2c41aa77';\n` +
    `// TODO: rotate before prod - backup token ${flag}\n`
  );
});

module.exports = { vuln, router };
