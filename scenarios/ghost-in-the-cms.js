'use strict';
// Kill-chain scenario: Ghost in the CMS.
// Four stages chained into one narrative: slip in unseen through a leaked
// .git directory, take over an account with a forged reset token, plant a
// webshell past the upload filter, then haunt the front page with stored XSS.
module.exports = {
  id: 'ghost-in-the-cms',
  name: 'Ghost in the CMS',
  tagline: 'Slip in unseen, take an account, haunt the front page.',
  difficulty: 'Intermediate',
  story: '<p>The Maple Press CMS runs a sleepy news site nobody has patched since launch day. Its deployer commits like nobody will ever look, its password reset flow prints its own recipe on the page, and the front page renders whatever readers post.</p>' +
    '<p>You are the ghost. Tonight you slip in unseen through the cracks in its configuration, take over an account without ever knowing a password, and plant something that outlives your visit.</p>' +
    '<p>By morning the front page carries your mark. Not vandalism. A calling card. Make them remember.</p>',
  stages: [
    {
      id: 'footprint',
      title: 'Dig up the buried past',
      moduleId: 'misconfig',
      vulnId: 'git',
      briefing: '<p>The CMS serves its version control metadata over plain HTTP, and a repository is its own full history. The deployer once committed a production secret they never meant to publish. Reconstruct the repository from what the web server exposes, dig through its past, and take the secret.</p>',
    },
    {
      id: 'mask',
      title: 'Wear someone else\'s face',
      moduleId: 'auth',
      vulnId: 'reset-predictable',
      briefing: '<p>The password reset flow builds its tokens from public data, and the page prints the exact recipe for everyone to read. Watch one real reset, then mint a token for the admin account yourself and walk in wearing their identity. No phishing, no password cracking.</p>',
    },
    {
      id: 'nest',
      title: 'Plant your shell',
      moduleId: 'upload',
      vulnId: 'upload-double-ext',
      briefing: '<p>The file drop guards its gates with a blacklist, but the viewer decides content type by a different rule than the filter uses. Find the gap between what the filter checks and what the viewer believes, and smuggle active content through it. Open the served file, and your script wakes up: a shell nested in the walls.</p>',
    },
    {
      id: 'haunt',
      title: 'Haunt the front page',
      moduleId: 'xss',
      vulnId: 'stored',
      briefing: '<p>The CMS guestbook saves every comment verbatim and renders it raw for every visitor. Leave a comment that carries your mark, something every browser that views the page will run. The moment it fires, the front page itself bears your signature.</p>',
    },
  ],
};
