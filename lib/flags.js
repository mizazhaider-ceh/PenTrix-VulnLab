// Central flag helpers. Flag format is fixed: PENTRIX{<moduleId>_<vulnId>}
// Modules declare vulns in their router.js; this file awards and tracks captures.

function flagFor(modId, vulnId) {
  return `PENTRIX{${modId}_${vulnId}}`;
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
