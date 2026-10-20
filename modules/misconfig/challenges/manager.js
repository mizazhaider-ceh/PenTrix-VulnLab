'use strict';
// Default credentials: the manager panel trusts HTTP Basic auth admin:admin.
const express = require('express');
const { flagBox, fixPanel, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

// GET /manager -> the VulnLab Manager control panel, gated by HTTP Basic auth.
router.get('/manager', (req, res) => {
  const hdr = req.headers.authorization || '';
  const m = /^Basic (.+)$/.exec(hdr);
  let ok = false;
  if (m) {
    try {
      ok = Buffer.from(m[1], 'base64').toString('utf8') === 'admin:admin';
    } catch (e) {
      ok = false;
    }
  }
  // VULN: the management panel is protected only by the vendor default credential admin:admin
  if (!ok) {
    res.set('WWW-Authenticate', 'Basic realm="VulnLab Manager"');
    return res
      .status(401)
      .send(page('Manager', `
        <div class="clay-card">
          <h2>401 Unauthorized</h2>
          <p>This management panel requires authentication.</p>
        </div>`));
  }
  const flag = award(req, 'misconfig', 'manager');
  res.send(page('Manager panel', `
    <div class="clay-card">
      <h2>VulnLab Manager</h2>
      <p>Welcome, admin. Server status: <b>running</b>. Deploys today: 3.</p>
      <div class="stats">
        <div class="stat"><b>running</b><span class="dim">status</span></div>
        <div class="stat"><b>3</b><span class="dim">deploys today</span></div>
        <div class="stat"><b>admin</b><span class="dim">role</span></div>
      </div>
      <p class="dim">Default credentials still in place. Change them.</p>
      ${flagBox(flag)}${fixPanel('misconfig', 'manager')}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/misconfig">Back to module index</a></p>
    </div>`));
});

module.exports = {
  vuln: {
    id: 'manager',
    name: 'Default Credentials',
    difficulty: 'Easy',
    hint: 'The manager panel uses HTTP Basic auth and the vendor default was never changed. Try the most common pair there is.',
    hints: ["The manager panel uses HTTP Basic auth. What are the vendor defaults?", "The panel still runs the vendor's factory default login, unchanged. The most common default pair will open it.", "In Burp Proxy, browse to the manager panel and send the 401 request to Repeater. Re-issue it with an Authorization: Basic header for the unchanged factory default pair, then read the flag the panel displays."],
    tools: 'BZ, B',
    how: 'Replay the manager request in Burp Repeater with HTTP Basic auth set to the vendor default admin:admin (or answer the browser login prompt with the same pair).',
    link: '/misconfig#manager',
    start: 'In Burp Proxy, browse to /misconfig/manager. The panel answers 401 and asks for HTTP Basic credentials. Send that request to Repeater.',
  },
  router,
};
