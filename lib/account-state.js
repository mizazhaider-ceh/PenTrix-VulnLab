'use strict';
// Per-session account overrides for the shared demo accounts (P1-1).
//
// The lab's demo accounts (alice, bob, admin) live in one shared users
// table. Several challenges legitimately change an account's password or
// role as their exploit: a password reset, a no-verify password change, a
// mass-assignment role promotion. Done against the shared table, one
// student's exploit rewrites the credentials for every other student (their
// brute-force lab suddenly targets a password somebody else chose).
//
// These helpers keep the exploit's effect inside the attacker's own
// session: the change is recorded as an override in req.session (persisted
// by the normal session store), and every credential or role check the lab
// performs for that session sees the override. The users table itself keeps
// the seeded values, so every other session sees pristine accounts.

function overrides(req, key, create) {
  if (!req.session) return null;
  if (!req.session[key] && create) req.session[key] = {};
  return req.session[key] || null;
}

// ---- passwords -----------------------------------------------------------

function setPasswordOverride(req, username, password) {
  const map = overrides(req, 'pwOverrides', true);
  if (map) map[String(username)] = String(password);
}

// The password this session should accept for the account: the override if
// this session changed it, else the seeded database value.
function effectivePassword(req, username, dbPassword) {
  const map = overrides(req, 'pwOverrides', false);
  if (map && Object.prototype.hasOwnProperty.call(map, String(username))) {
    return map[String(username)];
  }
  return dbPassword;
}

function passwordMatches(req, user, candidate) {
  if (!user) return false;
  return effectivePassword(req, user.username, user.password) === String(candidate);
}

// ---- roles ---------------------------------------------------------------

function setRoleOverride(req, userId, role) {
  const map = overrides(req, 'roleOverrides', true);
  if (map) map[String(userId)] = String(role);
}

// The role this session should see for the account id: the override if this
// session promoted (or demoted) it, else the database value.
function effectiveRole(req, userId, dbRole) {
  const map = overrides(req, 'roleOverrides', false);
  if (map && Object.prototype.hasOwnProperty.call(map, String(userId))) {
    return map[String(userId)];
  }
  return dbRole;
}

// ---- emails ---------------------------------------------------------------

function setEmailOverride(req, userId, email) {
  const map = overrides(req, 'emailOverrides', true);
  if (map) map[String(userId)] = String(email);
}

// The email this session should see for the account id: the override if
// this session changed it, else the database value.
function effectiveEmail(req, userId, dbEmail) {
  const map = overrides(req, 'emailOverrides', false);
  if (map && Object.prototype.hasOwnProperty.call(map, String(userId))) {
    return map[String(userId)];
  }
  return dbEmail;
}

module.exports = { setPasswordOverride, effectivePassword, passwordMatches, setRoleOverride, effectiveRole, setEmailOverride, effectiveEmail };
