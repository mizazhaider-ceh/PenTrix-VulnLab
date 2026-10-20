'use strict';
// Per-request context shared by lib/flags.js and lib/page.js. Module
// handlers award flags and immediately render the capture banner, but the
// banner helper only receives the flag string, so the award is recorded
// here and lib/page.js resolves the "Next challenge" link from it.
//
// It also holds two process-wide registrations made once at boot: the
// challenge catalog (ordered module/vuln list, for "next challenge"
// resolution) and the session store (so lib/flags can re-read the stored
// session and repair the stale per-request snapshot after parallel
// bursts). Everything degrades to "absent" outside a request, so unit
// tests and CLI callers keep working unchanged.
const { AsyncLocalStorage } = require('node:async_hooks');

const als = new AsyncLocalStorage();

let catalog = [];       // [{ id, vulns: [{ id, link }] }] in registry order
let sessionStore = null;

function setCatalog(entries) {
  catalog = Array.isArray(entries) ? entries : [];
}

function setSessionStore(store) {
  sessionStore = store || null;
}

function getSessionStore() {
  return sessionStore;
}

// Open the request scope. app.js wraps each request in this via middleware
// so award()/flagBanner() calls deep inside module routers stay connected.
function run(req, next) {
  return als.run({ req: req || null, lastAward: null }, next);
}

function context() {
  return als.getStore() || null;
}

function recordAward(modId, vulnId) {
  const c = context();
  if (c) c.lastAward = { modId: String(modId), vulnId: String(vulnId) };
}

function lastAward() {
  const c = context();
  return c ? c.lastAward : null;
}

// The challenge after (modId, vulnId) in catalog order, crossing module
// boundaries at the end of a module. Returns { href, modId, vulnId } or
// null when the pair is unknown or was the very last challenge.
function nextChallengeAfter(modId, vulnId) {
  const flat = [];
  for (const m of catalog) {
    const vulns = Array.isArray(m.vulns) ? m.vulns : [];
    for (const v of vulns) flat.push({ modId: m.id, vulnId: v.id, link: v.link });
  }
  const i = flat.findIndex((e) => e.modId === modId && e.vulnId === vulnId);
  if (i < 0 || i + 1 >= flat.length) return null;
  const n = flat[i + 1];
  return { href: n.link || ('/' + n.modId + '#' + n.vulnId), modId: n.modId, vulnId: n.vulnId };
}

module.exports = {
  run, context,
  recordAward, lastAward, nextChallengeAfter,
  setCatalog, setSessionStore, getSessionStore,
};
