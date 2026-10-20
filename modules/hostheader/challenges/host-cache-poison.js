'use strict';
// Cache Poisoning via Host: GET /hostheader/app caches the portal page keyed
// by path only. The cached page embeds the Host header, so a page rendered
// under the attacker's Host is later served to legitimate visitors.
const express = require('express');
const { award } = require('../../../lib/flags');
const { esc, fixPanel, flagBox, page } = require('../../../lib/page');
const { isLocalHost } = require('../shared');

const router = express.Router();

// Naive cache: keyed by path only, never by host. Private to this challenge,
// and per session (P1-1): one student's poisoned page is served to nobody
// else. The poisoner's own follow-up request with the normal host still sees
// their planted page, which is the demonstrated attack.
const { createSessionState } = require('../../../lib/session-state');
const pageCaches = createSessionState(() => ({}));

// GET /app -> password reset portal (cached).
router.get('/app', (req, res) => {
  const pageCache = pageCaches.get(req);
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
      only: the Host header is not part of it. (Each browser session has its own cache, so a planted page only ever comes back to you.)</p>
      <p>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader/app/clear">Clear the cache</a>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/hostheader">Back to the module</a>
      </p>
    </div>`;
  pageCache[key] = { html, host };
  res.send(page('Reset portal', html));
});

// GET /app/clear -> empty this session's cache.
router.get('/app/clear', (req, res) => {
  delete pageCaches.get(req)['/app'];
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
    hints: ["Open /hostheader/app in Repeater. The page is cached by path only, so whatever your first request's Host header says gets baked into the cached copy.", "Poison first, victim second: send the request once with the Host header rewritten to a domain you control, then send the SAME path again with the normal host restored.", "Compare the second response to the first. The key insight: the cache key ignores Host entirely, so the second visitor receives whatever host the first visitor planted."],
    tools: 'BZ',
    how: 'In Burp Repeater, request GET /hostheader/app with the Host header rewritten to a domain you control to plant the poisoned page, then resend the same path with the normal Host header. The cache is keyed by path only, so the second request is served your poisoned copy and the flag lands.',
    link: '/hostheader#host-cache-poison',
    start: 'Route the app through Burp Proxy, then open Repeater. Request GET /hostheader/app twice: once with the Host header rewritten to a domain you control, then again with the normal host. Compare the two responses and look at where the page got its reset link.',
  },
  router,
};
