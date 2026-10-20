'use strict';
// Unicode Escape Bypass: POST /proto/unicode/merge scans the RAW request text
// for __proto__ and rejects it with 400, but JSON.parse decodes \uXXXX escapes
// AFTER the scan, so the forbidden key materializes post-blacklist and the
// naive merge pollutes Object.prototype.
// The finisher wires this up: ../shared must export { merge, config } (moved
// from router.js), and the module mount (index.js) must apply
// express.text({ type: 'text/plain' }) so req.body arrives as the raw string.
const express = require('express');
const { appShell, esc, fixPanel, flagBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { merge, protoStateFor, freshUser } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'proto-unicode-bypass',
  name: 'Unicode Escape Bypass',
  difficulty: 'Hard',
  hint: 'The blacklist scans the raw JSON text for __proto__. JSON string escapes are decoded after that scan.',
  hints: ["Proxy the importer in Burp and note the Content-Type the server needs: it only trusts the raw bytes when they arrive as text/plain. The blacklist scans that raw text for the forbidden literal.", "In Repeater, build the JSON document so the forbidden key never appears in the raw bytes: JSON string escapes are decoded by JSON.parse after the scan. A 200 reply means the merge ran.", "Open the admin check in the browser: a fresh {} now reads the polluted role."],
  tools: "BZ, B",
  how: 'Replay the merge in Repeater with the key hidden behind JSON string escapes, then verify it with the admin check.',
  link: '/proto#proto-unicode-bypass',
  start: 'Set Burp as your browser proxy and open /proto/unicode in the browser. Study the sample JSON document in the importer box, then copy it into Repeater as a POST to /proto/unicode/merge with Content-Type: text/plain, send it, and open /proto/unicode/admin in the browser.',
};

// GET /proto/unicode -> the config importer page.
router.get('/unicode', (req, res) => {
  res.send(page('JSON config importer · MergeDesk', `
    ${appShell('MergeDesk', `
      <h2>Import a JSON config document</h2>
      <p>MergeDesk imports a JSON config document into the application config.
      This endpoint is stricter: it scans the <b>raw request text</b> and
      rejects it with 400 if it contains the literal string
      <code>__proto__</code> anywhere. Only then does it
      <code>JSON.parse</code> the body and merge it.</p>
      <p>The catch: JSON string escapes like <code>\\u005f</code> are decoded by
      <code>JSON.parse</code> <i>after</i> the blacklist scan. The raw text never
      contains <code>__proto__</code>, but the parsed object does.</p>
      <p>Send the body as <code>text/plain</code> so the server sees your exact bytes.</p>
      <div class="clay-field">
        <label for="jb">JSON document (sent as text/plain)</label>
        <textarea class="clay-input" id="jb" rows="6" cols="70">{"\\u005f\\u005fproto\\u005f\\u005f": {"role": "admin"}}</textarea>
      </div>
      <p><button class="clay-btn clay-btn-primary" type="button" onclick="fetch('/proto/unicode/merge', {method:'POST', headers:{'Content-Type':'text/plain'}, body: document.getElementById('jb').value}).then(r => r.text()).then(t => document.getElementById('out').innerHTML = t);">Import config</button></p>
      <div id="out"></div>
      <hr />
      <p>Or in Burp Repeater:</p>
      <pre><code>POST /proto/unicode/merge HTTP/1.1
Host: <your-lab-address>
Content-Type: text/plain

{"\\u005f\\u005fproto\\u005f\\u005f": {"role": "admin"}}</code></pre>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto/unicode/admin">Open admin check</a></p>
    `, { crumb: 'JSON config importer', nav: ['Home', 'Configs', 'Admin'] })}
  `));
});

// POST /proto/unicode/merge -> raw-text blacklist, then JSON.parse, then merge.
// VULN: the blacklist inspects the raw text, but JSON.parse decodes \uXXXX
// escapes afterwards, so the forbidden key materializes post-scan and the
// merge walks it into Object.prototype.
router.post('/unicode/merge', (req, res) => {
  const raw = req.body;
  if (typeof raw !== 'string') {
    return res.status(400).send('<p>Send the JSON document as text/plain.</p>');
  }
  if (raw.includes('__proto__')) {
    return res.status(400).send('<p><b>Blocked:</b> raw request text contains "__proto__".</p><p><a href="/proto/unicode">Back</a></p>');
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    return res.status(400).send(`<p>Invalid JSON: <code>${esc(e.message)}</code></p>`);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return res.status(400).send('<p>Send a JSON object.</p>');
  }
  // VULN: parsed JSON body is deep-merged into the shared app config with no
  // key filtering.
  merge(protoStateFor(req).config, data);
  res.send(`<p>Blacklist passed. Merged keys: <code>${esc(Object.keys(data).join(', '))}</code>.
  Now <a href="/proto/unicode/admin">open the admin check</a>.</p>`);
});

// GET /proto/unicode/admin -> creates a brand-new {} and tests user.role.
router.get('/unicode/admin', (req, res) => {
  // Per-session admin check: a fresh object inheriting this session's
  // polluted prototype stand-in (P1-1). No role is assigned anywhere here.
  const user = freshUser(req);
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-unicode-bypass');
    return res.send(page('Admin panel · MergeDesk', `
      ${appShell('MergeDesk', `
        <h2>Welcome, admin</h2>
        <p>Your <code>\\u005f</code> escapes slipped past the raw-text blacklist
        and <code>JSON.parse</code> rebuilt the forbidden key. A fresh
        <code>{}</code> now reads <code>role = 'admin'</code>.</p>
        ${flagBox(flag)}
        ${fixPanel('proto', 'proto-unicode-bypass')}
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto">Back to the module</a></p>
      `, { crumb: 'Admin panel', nav: ['Home', 'Configs', 'Admin'] })}
    `));
  }
  res.send(page('Admin panel · MergeDesk', `
    ${appShell('MergeDesk', `
      <h2>Access denied</h2>
      <p>A fresh <code>{}</code> has <code>role = ${esc(String(user.role))}</code>.
      Smuggle <code>__proto__</code> past the raw-text blacklist, then reload.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto/unicode">Back to the importer</a></p>
    `, { crumb: 'Admin panel', nav: ['Home', 'Configs', 'Admin'] })}
  `));
});

module.exports = { vuln, router };
