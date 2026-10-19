// Central flag helpers. Flags are random per deployment (PENTRIX{<32 hex>}),
// generated on first boot. Reading the source never reveals a flag.

const { getDb } = require('./db');

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

function award(req, modId, vulnId) {
  req.session.flags = req.session.flags || {};
  req.session.flags[`${modId}:${vulnId}`] = true;
  return flagFor(modId, vulnId);
}

function captured(req, modId, vulnId) {
  return !!(req.session.flags && req.session.flags[`${modId}:${vulnId}`]);
}

module.exports = { flagFor, award, captured };
