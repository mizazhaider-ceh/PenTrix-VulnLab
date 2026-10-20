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

function award(req, modId, vulnId) {
  refreshFlags(req);
  req.session.flags = req.session.flags || {};
  req.session.flags[`${modId}:${vulnId}`] = true;
  rctx.recordAward(modId, vulnId);
  return flagFor(modId, vulnId);
}

function captured(req, modId, vulnId) {
  if (req && req.session) refreshFlags(req);
  return !!(req.session.flags && req.session.flags[`${modId}:${vulnId}`]);
}

module.exports = { flagFor, award, captured };
