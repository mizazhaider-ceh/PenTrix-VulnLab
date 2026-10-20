'use strict';
// Query-string pollution: GET /proto/query parses the raw query string into
// nested objects and deep-merges them into the global app config.
// The finisher wires this up: ../shared must export the module-level helpers
// { merge, parseNested, rawQuery, config } (moved from router.js), and the
// module mount (index.js) must apply the urlencoded/json/text body parsers.
const express = require('express');
const { esc, page, brief, flagBox, fixPanel, hintLadder, toolsPill, difficultyPill, payloadBlock, appShell } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { merge, parseNested, rawQuery, protoStateFor, freshUser } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'proto-query',
  name: 'Query-String Pollution',
  difficulty: 'Medium',
  hint: 'The merge endpoint folds every query parameter into the app config with no key checks. Think about which parameter name could reach the shared prototype.',
  hints: ["Proxy /proto/query in Burp and look at the raw query string the browser sends. The merge folds every parameter into the app config. Which parameter name could climb from a normal key to the shared prototype?", "Replay the merge in Repeater with that prototype-climbing parameter name, setting the role the admin check tests. The 'Keys merged this request' line confirms the merge ran.", "Reload the admin check in the proxied browser: a fresh {} now reads the polluted role."],
  tools: "BZ, B",
  how: 'Pollute Object.prototype.role through the query-string merge, then verify it with the admin check.',
  link: '/proto#proto-query',
  start: 'Set Burp as your browser proxy and open /proto/query in the browser. Type the query string that climbs from a normal key to the shared prototype into the merge field and click Merge, then open /proto/query/admin and reload it.',
};

// GET /proto/query -> the merge console. Parses the raw query string into
// nested objects and deep-merges them into the app config.
router.get('/query', (req, res) => {
  const data = parseNested(rawQuery(req));
  // VULN: every query parameter is deep-merged into the per-session config object.
  merge(protoStateFor(req).config, data);
  res.send(page('Query-String Pollution', `
    ${brief('App config console', `ConfigDesk is the admin console for a small demo shop.
      The merge console below folds query parameters into the running app config,
      so operators can tweak behavior without a restart. Bracket notation nests:
      <code>a[b]=c</code> becomes a nested object before merging.`)}
    <p>${difficultyPill(vuln.difficulty)}</p>
    ${toolsPill(vuln)}
    ${appShell('ConfigDesk', `
      <h2>Merge query parameters into the app config</h2>
      <p>This console runs your raw query string through a nested parser and
      deep-merges the result into the global config. The merge trusts every key it sees.</p>
      <p><b>Try it:</b>
        <a href="/proto/query?__proto__[role]=admin"><code>?__proto__[role]=admin</code></a>
      </p>
      <form onsubmit="location='/proto/query?'+document.getElementById('qs').value; return false;">
        <label class="clay-field" for="qs">Query string</label>
        <input class="clay-input" id="qs" size="55" placeholder="__proto__[role]=admin" />
        <button class="clay-btn clay-btn-primary" type="submit">Merge</button>
      </form>
      <p>Keys merged this request: <code>${esc(Object.keys(data).join(', ') || '(none)')}</code></p>
      <hr />
      <p>Step 2: the admin check creates a brand-new <code>{}</code> and tests
      <code>user.role === 'admin'</code>.</p>
      <p><a class="clay-btn clay-btn-secondary" href="/proto/query/admin">Open admin check</a></p>
    `, { mark: '&#9881;', nav: ['Dashboard', 'Config', 'Users'], crumb: 'Admin > Config > Merge console' })}
    ${payloadBlock('Burp Repeater', 'GET /proto/query?__proto__[role]=admin HTTP/1.1\nHost: <your-lab-address>\n\nGET /proto/query/admin HTTP/1.1\nHost: <your-lab-address>\n')}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto">Back to the module</a></p>
  `));
});

// GET /proto/query/admin -> the admin check. A fresh {} is created and
// user.role is read; prototype pollution can inject that value.
router.get('/query/admin', (req, res) => {
  // Per-session admin check: a fresh object inheriting this session's
  // polluted prototype stand-in (P1-1). No role is assigned anywhere here.
  const user = freshUser(req);
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-query');
    return res.send(page('Admin panel', `
      ${brief('Admin panel', `A fresh <code>{}</code> just passed the
        <code>role === 'admin'</code> check. <code>Object.prototype.role</code> is polluted.`)}
      ${flagBox(flag)}
      ${fixPanel('proto', 'proto-query')}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto">Back to the module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    ${brief('Admin panel', `Access denied. A fresh <code>{}</code> has
      <code>role = ${esc(String(user.role))}</code>. Pollute
      <code>Object.prototype.role</code> via the merge console, then reload this page.`)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto/query">Back to the merge console</a></p>
  `));
});

module.exports = {
  vuln,
  router,
};
