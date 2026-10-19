'use strict';
// Exposed .git Directory: the server answers /.git/HEAD, /.git/refs/heads/main
// and the loose-object store over plain HTTP, so anyone can walk from the
// branch ref to the commit object and read the leaked secret in its diff.
const express = require('express');
const { esc, page, hintBox } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

// Fake commit hash for the exposed .git lab.
const GIT_COMMIT = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4';

router.get('/.git/HEAD', (req, res) => {
  // VULN: version-control metadata is served over HTTP; HEAD reveals the branch ref
  res.type('text/plain').send('ref: refs/heads/main\n');
});

router.get('/.git/refs/heads/main', (req, res) => {
  // VULN: refs are readable, leaking the latest commit hash
  res.type('text/plain').send(GIT_COMMIT + '\n');
});

router.get('/.git/objects/', (req, res) => {
  // VULN: the object store is browsable, so loose objects can be enumerated
  res.send(
    page(
      'Index of /.git/objects/',
      `<h2>Index of /.git/objects/</h2>
      <p class="dim">Loose objects, one directory per hash prefix.</p>
      <ul><li><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/misconfig/.git/objects/${GIT_COMMIT.slice(0, 2)}/">${GIT_COMMIT.slice(0, 2)}/</a></li></ul>
      ${hintBox('The directory name is the first two hex characters of the commit hash. Open it.')}`
    )
  );
});

router.get('/.git/objects/:dir/', (req, res) => {
  if (req.params.dir !== GIT_COMMIT.slice(0, 2)) {
    return res.status(404).send(page('Not found', '<h2>404</h2><p>No such object directory.</p>'));
  }
  const rest = GIT_COMMIT.slice(2);
  res.send(
    page(
      `Index of /.git/objects/${esc(req.params.dir)}/`,
      `<h2>Index of /.git/objects/${esc(req.params.dir)}/</h2>
      <ul><li><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/misconfig/.git/objects/${esc(req.params.dir)}/${rest}">${rest}</a></li></ul>
      ${hintBox('That file is the commit object. Fetch it and read the diff.')}`
    )
  );
});

router.get('/.git/objects/:dir/:file', (req, res) => {
  if (req.params.dir + req.params.file !== GIT_COMMIT) {
    return res.status(404).send(page('Not found', '<h2>404</h2><p>No such object.</p>'));
  }
  // VULN: the leaked commit object contains a production secret in its diff
  const flag = award(req, 'misconfig', 'git');
  res.type('text/plain').send(
    `commit 312\n` +
    `tree 8f2e41aa77c09d31\n` +
    `author deploy <deploy@pentrix.lab> 1790000000 +0000\n` +
    `committer deploy <deploy@pentrix.lab> 1790000000 +0000\n` +
    `\n` +
    `    rotate production secrets\n` +
    `\n` +
    `    diff --git a/config/prod.env b/config/prod.env\n` +
    `    -STRIPE_KEY=sk_live_OLDKEY\n` +
    `    +ADMIN_BACKUP_TOKEN=${flag}\n`
  );
});

module.exports = {
  vuln: {
    id: 'git',
    name: 'Exposed .git Directory',
    difficulty: 'Medium',
    hint: 'The repository metadata is served over HTTP. Start at /.git/HEAD, follow the ref, then walk the object store to the commit.',
    hints: ["There's a .git directory over HTTP. What does that give you?", "HEAD, refs, and objects are all fetchable. The commit object has the secret.", "Treat the exposed .git directory like a repository you clone by hand over HTTP: follow the chain from HEAD to the branch ref to the commit object, then reconstruct the file the commit added. The secret hides in that change."],
    tools: 'C',
    how: 'Read .git/HEAD, resolve refs/heads/main, then fetch the commit object and read the leaked secret.',
    link: '/misconfig#git',
    start: 'curl -s http://localhost:3000/misconfig/.git/HEAD',
  },
  router,
};
