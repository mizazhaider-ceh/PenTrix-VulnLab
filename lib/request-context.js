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
  return als.run({
    req: req || null, lastAward: null,
    awardsByFlag: null, renderedFlags: null,
  }, next);
}

function context() {
  return als.getStore() || null;
}

// Record an award made in this request. `detail` (optional, from
// lib/flags.js) carries the flag string and whether this award was the
// first capture of that flag in the session. The banner renderer uses it
// to show each capture banner exactly once per capture (P1A): an award
// that re-satisfies an already-captured flag records first=false, and a
// banner for that flag in this request is then suppressed, while banners
// rendered from flagFor() with no award in the request (the
// already-captured display on module pages) are unaffected.
function recordAward(modId, vulnId, detail) {
  const c = context();
  if (!c) return;
  c.lastAward = { modId: String(modId), vulnId: String(vulnId) };
  if (detail && detail.flag) {
    c.awardsByFlag = c.awardsByFlag || Object.create(null);
    const k = String(detail.flag);
    const prev = c.awardsByFlag[k];
    // Firstness is sticky within a request: if any award of this flag in
    // this request was the session's first capture, a banner rendered
    // later in this request is the capture banner, even when a second
    // award of the same flag landed in between.
    c.awardsByFlag[k] = { first: !!detail.first || !!(prev && prev.first) };
  }
}

// Claim the one banner render for a flag in this request. Returns true
// when the caller should render the banner, false when it must not:
// either this request already rendered a banner for the same flag, or
// an award of this flag was already recorded in this request as a
// duplicate (not the first capture in the session, as recorded by
// recordAward). A suppressed claim does not consume the render slot: a
// display claim made before any duplicate award is recorded in the same
// request can still render (the LFI traversal showCaptured-before-award
// ordering relies on this), but a display that follows a duplicate award
// in the same request stays suppressed. Outside a request (unit tests,
// CLI callers) every banner renders, as before.
function claimBannerRender(flag) {
  const c = context();
  if (!c) return true;
  const key = String(flag);
  c.renderedFlags = c.renderedFlags || Object.create(null);
  if (c.renderedFlags[key]) return false;
  const info = c.awardsByFlag ? c.awardsByFlag[key] : null;
  if (info && !info.first) return false;
  c.renderedFlags[key] = true;
  return true;
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
  recordAward, lastAward, nextChallengeAfter, claimBannerRender,
  setCatalog, setSessionStore, getSessionStore,
};
