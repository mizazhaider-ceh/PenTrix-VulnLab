// Central flag helpers. Flags are random per deployment (PENTRIX{<32 hex>}),
// generated on first boot. Reading the source never reveals a flag.

const { getDb } = require('./db');
const rctx = require('./request-context');

function flagFor(modId, vulnId) {
  const row = getDb()
    .prepare('SELECT flag FROM flags WHERE module_id = ? AND vuln_id = ?')
    .get(modId, vulnId);
  if (!row) {
    // Should not happen: app.js seeds every registered vuln at boot.
    throw new Error(`no flag registered for ${modId}:${vulnId} (was ensureFlags run?)`);
  }
  return row.flag;
}

// P1-6: a request holds a session snapshot taken when it started. Under a
// parallel burst (the race module's whole point), another request may have
// captured flags and saved in the meantime; this request's snapshot is then
// stale and disagrees with the scoreboard. Flags only ever become true, so
// union the stored flags into the snapshot once per request before reading
// or writing them. The store-side merge in lib/session-store.js is the
// second half of the fix: together they keep the chip, the module pages
// and the scoreboard showing exactly the same captures.
function refreshFlags(req) {
  if (!req || !req.session || req.__pxFlagsSynced) return;
  req.__pxFlagsSynced = true;
  try {
    const store = rctx.getSessionStore();
    if (!store || !req.sessionID || typeof store.getFlags !== 'function') return;
    const stored = store.getFlags(req.sessionID);
    if (!stored) return;
    req.session.flags = req.session.flags || {};
    for (const k of Object.keys(stored)) {
      if (stored[k]) req.session.flags[k] = true;
    }
  } catch (e) { /* the snapshot alone is still usable */ }
}

// P1A: banner-once claims. Captures are monotonic (a flag, once true,
// stays true), but under a parallel burst every request holds a session
// snapshot taken before any peer saved, so neither the snapshot nor the
// stored session can tell the later burst members that the capture
// already happened. This in-memory registry closes that window: award()
// checks and claims a (session id, flag) pair in one synchronous step,
// which the single-threaded event loop cannot interleave, so exactly one
// request in the burst is the first award. The snapshot and stored
// session checks in award() cover everything else (sequential repeats,
// restarts with persisted sessions). Entries live as long as the session
// store's own TTL; an hourly sweep drops idle ones so the map stays
// bounded by live sessions times the challenge count.
const BANNER_CLAIM_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const bannerClaims = new Map(); // `${sid}\n${key}` -> last award time (ms)
const bannerClaimSweep = setInterval(() => {
  const now = Date.now();
  for (const [k, t] of bannerClaims) {
    if (now - t > BANNER_CLAIM_TTL_MS) bannerClaims.delete(k);
  }
}, 60 * 60 * 1000);
bannerClaimSweep.unref();

// Fresh read of the stored capture map (refreshFlags syncs only once per
// request; a peer in a parallel burst may have saved since then). Also
// unions the stored flags into this request's snapshot, like refreshFlags.
function storedHas(req, key) {
  try {
    const store = rctx.getSessionStore();
    if (!store || !req.sessionID || typeof store.getFlags !== 'function') return false;
    const stored = store.getFlags(req.sessionID);
    if (!stored) return false;
    if (req.session) {
      req.session.flags = req.session.flags || {};
      for (const k of Object.keys(stored)) {
        if (stored[k]) req.session.flags[k] = true;
      }
    }
    return !!stored[key];
  } catch (e) { return false; }
}

function award(req, modId, vulnId) {
  refreshFlags(req);
  req.session.flags = req.session.flags || {};
  const key = `${modId}:${vulnId}`;
  // Firstness is decided before this award marks the flag, from every
  // layer that can know about an earlier capture: this request's session
  // snapshot, the stored session (fresh read), and the burst claim
  // registry. award() itself stays synchronous, so the check-and-claim
  // below is atomic against other requests in the same process.
  let first = !req.session.flags[key] && !storedHas(req, key);
  const sid = (req && (req.sessionID || (req.session && req.session.id))) || null;
  if (sid) {
    const claimKey = sid + '\n' + key;
    if (bannerClaims.has(claimKey)) first = false;
    bannerClaims.set(claimKey, Date.now());
  }
  req.session.flags[key] = true;
  const flag = flagFor(modId, vulnId);
  // The flag string is always returned, first award or duplicate, so
  // call sites that store it (JSON bodies, response headers, variables
  // rendered later) keep working exactly as before. Only the banner
  // renderer treats a duplicate differently (lib/page.js, via the
  // request context): the first award renders the capture banner and
  // later re-awards in the same session do not render it again. The flag
  // stays viewable through the already-captured flagFor display paths.
  rctx.recordAward(modId, vulnId, { flag, first });
  return flag;
}

function captured(req, modId, vulnId) {
  if (req && req.session) refreshFlags(req);
  return !!(req.session.flags && req.session.flags[`${modId}:${vulnId}`]);
}

module.exports = { flagFor, award, captured };
