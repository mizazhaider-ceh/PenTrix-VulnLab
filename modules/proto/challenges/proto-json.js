'use strict';
// JSON body pollution: POST /proto/json/merge deep-merges a parsed JSON body
// into the global app config.
// The finisher wires this up: ../shared must export the module-level helpers
// { merge, config } (moved from router.js), and the module mount (index.js)
// must apply the json body parser so POST /json/merge sees req.body.
const express = require('express');
const { esc, page, brief, flagBox, fixPanel, hintLadder, toolsPill, difficultyPill, payloadBlock, appShell } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { merge, protoStateFor, freshUser } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'proto-json',
  name: 'JSON Body Pollution',
  difficulty: 'Medium',
  hint: 'Capture the merge POST in Burp Proxy and replay it in Repeater. The endpoint accepts a JSON body, and JSON.parse happily creates an own property literally named __proto__.',
  hints: ["On the merge console page, click Merge with Burp Proxy intercepting, then send the POST to Repeater. The JSON body is deep-merged with no key filtering, same idea as query-string pollution, different vector.", "In Repeater, change the request body to a JSON object whose top-level key targets the prototype, with a nested object setting the property the admin check reads.", "After Repeater confirms the merge, open the admin check URL in the browser to claim the flag."],
  tools: "BZ, C",
  how: 'Use Burp Repeater to POST a polluting JSON body to /proto/json/merge that sets the admin-check property through the prototype, then open the admin check.',
  link: '/proto#proto-json',
  start: 'In Burp, open the merge console (/proto/json), click Merge so the POST lands in the proxy history, send it to Repeater, replay it with a polluting JSON body, then open the admin check in the browser.',
};

// GET /proto/json -> the JSON merge console.
router.get('/json', (req, res) => {
  res.send(page('JSON Body Pollution', `
    ${brief('Config import', `ConfigDesk also accepts config updates as a JSON body, so
      automation scripts can push settings. The parsed body is deep-merged into
      the global config with the same merge routine. Remember: <code>JSON.parse</code>
      happily creates an own property literally named <code>__proto__</code>.`)}
    <p>${difficultyPill(vuln.difficulty)}</p>
    ${toolsPill(vuln)}
    ${appShell('ConfigDesk', `
      <h2>Merge a JSON body into the app config</h2>
      <label class="clay-field" for="jb">JSON body (Content-Type: application/json)</label><br />
      <textarea class="clay-input" id="jb" rows="6" cols="60">{"__proto__": {"role": "admin"}}</textarea><br /><br />
      <button class="clay-btn clay-btn-primary" onclick="fetch('/proto/json/merge', {method:'POST', headers:{'Content-Type':'application/json'}, body: document.getElementById('jb').value}).then(r => r.text()).then(t => document.getElementById('out').innerHTML = t);">Merge JSON</button>
      <div id="out"></div>
      <hr />
      <p>Or in Burp Repeater:</p>
      ${payloadBlock('Burp Repeater', 'POST /proto/json/merge HTTP/1.1\nHost: <your-lab-address>\nContent-Type: application/json\n\n{"__proto__": {"role": "admin"}}')}
      <p>Step 2: <a class="clay-btn clay-btn-secondary" href="/proto/json/admin">Open admin check</a></p>
    `, { mark: '&#9881;', nav: ['Dashboard', 'Config', 'Users'], crumb: 'Admin > Config > JSON import' })}
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto">Back to the module</a></p>
  `));
});

// POST /proto/json/merge -> deep-merge the parsed JSON body into the config.
router.post('/json/merge', (req, res) => {
  const data = req.body;
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return res.status(400).send('<p>Send a JSON object.</p>');
  }
  // VULN: parsed JSON body is deep-merged with no key filtering.
  merge(protoStateFor(req).config, data);
  res.send(`<p>Merged keys: <code>${esc(Object.keys(data).join(', '))}</code>.
  Now <a href="/proto/json/admin">open the admin check</a>.</p>`);
});

// GET /proto/json/admin -> the admin check. A fresh {} is created and
// user.role is read; prototype pollution can inject that value.
router.get('/json/admin', (req, res) => {
  // Per-session admin check: a fresh object inheriting this session's
  // polluted prototype stand-in (P1-1). No role is assigned anywhere here.
  const user = freshUser(req);
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-json');
    return res.send(page('Admin panel', `
      ${brief('Admin panel', `A fresh <code>{}</code> just passed the
        <code>role === 'admin'</code> check. The JSON body polluted
        <code>Object.prototype</code>.`)}
      ${flagBox(flag)}
      ${fixPanel('proto', 'proto-json')}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto">Back to the module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    ${brief('Admin panel', `Access denied. A fresh <code>{}</code> has
      <code>role = ${esc(String(user.role))}</code>. POST a polluting JSON body
      first, then reload this page.`)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto/json">Back to the merge console</a></p>
  `));
});

module.exports = {
  vuln,
  router,
};
