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
  hints: ["Vim swap files end in .swp. Proxy a request to the web root: the running app is app.js, so build the swap filename Vim would create for it.", "Send your filename guess through Burp Repeater. The .swp file has the recovered source with secrets: it's a backup the editor left behind.", "Shape: Vim builds the swap name by wrapping the edited filename: a leading dot, then the filename, then .swp. Build that name for the app entry file, request it from the web root in Repeater, and read the recovered source."],
  tools: 'BZ, C',
  est: 'about 5 to 10 minutes',
  how: 'An editor swap file left in the web root serves the recovered source of the file it was editing, secrets included.',
  link: '/misconfig/app.js.swp',
  start: 'In Burp: browse to /misconfig with Proxy on, then build the Vim swap filename for app.js in Repeater and read the recovered source.',
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
