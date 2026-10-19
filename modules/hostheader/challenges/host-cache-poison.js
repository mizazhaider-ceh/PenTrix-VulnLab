'use strict';
// Cache Poisoning via Host: GET /hostheader/app caches the portal page keyed
// by path only. The cached page embeds the Host header, so a page rendered
// under the attacker's Host is later served to legitimate visitors.
const express = require('express');
const { award } = require('../../../lib/flags');
const { esc, fixPanel, flagBox, page } = require('../../../lib/page');
const { isLocalHost } = require('../shared');

const router = express.Router();

// Naive cache: keyed by path only, never by host. Private to this challenge.
const pageCache = {};

// GET /app -> password reset portal (cached).
router.get('/app', (req, res) => {
  const key = req.path;
  const curHost = req.headers.host || '';
  const entry = pageCache[key];
  if (entry) {
    // VULN: the cached page is served to everyone regardless of Host, so a page
    // rendered under the attacker's Host is later served to legitimate users.
    let flagHtml = '';
    if (isLocalHost(curHost) && !isLocalHost(entry.host)) {
      const flag = award(req, 'hostheader', 'host-cache-poison');
      flagHtml = `<div class="clay-card"><p><b>Cache poison demonstrated:</b> you
        asked with the normal host <code>${esc(curHost)}</code> but received the
        page cached under <code>${esc(entry.host)}</code>. Every visitor now gets
        the attacker's links.</p>${flagBox(flag)}${fixPanel('hostheader', 'host-cache-poison')}</div>`;
    }
    return res.send(page('Reset portal (cached)', entry.html + flagHtml));
  }
  // VULN: absolute portal link built from the Host header, then cached by path only.
  const host = curHost;
  const html = `
    <div class="clay-card">
      <h2>Password reset portal</h2>
      <p>Start a reset here:<br />
      <a href="http://${esc(host)}/hostheader/forgot">http://${esc(host)}/hostheader/forgot</a></p>
      <p class="note dim">This page is cached for performance. The cache key is the path
      only: the Host header is not part of it.</p>
      <p>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader/app/clear">Clear the cache</a>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader">Back to the module</a>
      </p>
    </div>`;
  pageCache[key] = { html, host };
  res.send(page('Reset portal', html));
});

// GET /app/clear -> empty this challenge's cache.
router.get('/app/clear', (req, res) => {
  delete pageCache['/app'];
  res.send(page('Cache cleared', `
    <div class="clay-card">
      <p>Cache cleared.</p>
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/hostheader/app">Reload the portal</a></p>
    </div>
  `));
});

module.exports = {
  vuln: {
    id: 'host-cache-poison',
    name: 'Cache Poisoning via Host',
    difficulty: 'Hard',
    hint: 'The portal page is cached by path only, not by host. Poison it first, then visit as a normal user.',
    hints: ["The cache is keyed by path only. What if the cached page contains the Host?", "Poison the cache with Host: evil.com. The next victim gets your poisoned page.", "Request with Host: evil.com to poison, then fetch with a normal Host to see the poisoned entry."],
    tools: 'C',
    how: 'GET /hostheader/app with Host: evil.com to poison the cache, then GET it again with the normal host.',
    link: '/hostheader#host-cache-poison',
    start: 'curl -s -H "Host: evil.com" http://localhost:3000/hostheader/app\ncurl -s http://localhost:3000/hostheader/app',
  },
  router,
};
