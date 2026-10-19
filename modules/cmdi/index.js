'use strict';
// Command Injection: intentionally vulnerable ping gadgets for a fictional
// network diagnostics console. Each challenge chains an extra shell command
// through a progressively tighter (and progressively bypassable) filter.
const express = require('express');
const {
  brief, difficultyPill, esc, hintLadder, page, payloadBlock, toolsPill, trackBanner,
} = require('../../lib/page');
const { APP_NAME } = require('./shared');

const challenges = [
  require('./challenges/basic'),
  require('./challenges/bypass'),
  require('./challenges/cmdi-ifs'),
  require('./challenges/cmdi-braces'),
  require('./challenges/cmdi-newline'),
  require('./challenges/cmdi-backtick'),
  require('./challenges/cmdi-wildcard'),
  require('./challenges/cmdi-pipe'),
  require('./challenges/cmdi-tab'),
];

const router = express.Router();

// GET /cmdi -> module index page (catalog for the fictional NetProbe console).
router.get('/', (req, res) => {
  const rows = challenges.map(({ vuln: v }) => `
    <tr>
      <td><code>GET /cmdi/${esc(v.link.split('/').pop())}</code></td>
      <td>${esc(v.name)}</td>
      <td>${difficultyPill(v.difficulty)}</td>
    </tr>`).join('');

  const cards = challenges.map(({ vuln: v }) => `
    <article class="vuln-card" id="${esc(v.id)}">
      <h3><a href="${esc(v.link)}">${esc(v.name)}</a> ${difficultyPill(v.difficulty)}</h3>
      <p>${esc(v.how)}</p>
      ${v.start ? payloadBlock('Starting point', v.start) : ''}
      ${hintLadder(v)}
      ${toolsPill(v)}
    </article>`).join('');

  res.send(page('Command Injection', `
    <h1>${esc(APP_NAME)}: Command Injection</h1>
    ${brief('Briefing', `
      ${esc(APP_NAME)} is a small internal tool that lets on-call engineers run a
      quick reachability check against a host. A command-injection flaw happens
      when an application builds a shell command out of user input without
      sanitising it: special shell characters (<code>;</code>, <code>&amp;&amp;</code>,
      <code>||</code>, <code>|</code>, backticks, <code>$()</code>, newlines)
      let you smuggle extra commands into the string. Nine gadgets below start
      with no filtering at all, then add one naive blacklist rule at a time;
      your job is to find the gap in each one.`)}
    ${trackBanner(module.exports)}

    <h2>Diagnostic endpoints</h2>
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">NetProbe diagnostic endpoints</caption>
      <thead><tr><th scope="col">Route</th><th scope="col">Gadget</th><th scope="col">Difficulty</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>

    <h2>Challenges</h2>
    <p>Nine flaws hide in the endpoints above. Each challenge card has a hint
    ladder: level 1 nudges, level 2 teaches the technique, level 3 shows the
    payload shape.</p>
    ${cards}
  `));
});

for (const c of challenges) router.use(c.router);

module.exports = {
  id: 'cmdi',
  name: 'Command Injection',
  tagline: 'Smuggle extra commands into a ping gadget.',
  description: 'Learn how unescaped user input becomes shell commands: first with no filtering at all, then against naive blacklists you have to bypass one shell trick at a time ($IFS, braces, newlines, backticks, glob wildcards, pipes, and tabs).',
  difficulty: 'Intermediate',
  track: 'Injection',
  prerequisites: ['sqli'],
  vulns: challenges.map((c) => c.vuln),
  router,
};
