'use strict';
module.exports = {
  module: 'sqli',
  vulnId: 'second-order',
  title: 'Second-Order SQL Injection: Parameterize the Reused Value',
  language: 'javascript',
  vulnerableCode: `
// Mock tables: a members table (stores display names) and a users table.
const users = [
  { username: 'admin', role: 'admin', email: 'admin@pentrix.local', secret: 'TOP-SECRET-ADMIN-ONLY' },
  { username: 'bob', role: 'member', email: 'bob@pentrix.local', secret: null },
];
const members = [];

// Tiny naive query engine that behaves like real SQL string interpolation:
// everything between the outer quotes is the literal, and any extra quote
// inside means the attacker broke out of the string, so the predicate is no
// longer a plain equality and every row is returned.
function query(sql) {
  const m = /^SELECT \\* FROM users WHERE username='(.*)'$/.exec(sql);
  if (!m) return [];
  const inner = m[1];
  if (inner.indexOf("'") !== -1) return users.slice(); // injection: full table
  return users.filter(function (u) { return u.username === inner; });
}

// Step 1 stores the display name safely (verbatim, like a prepared insert).
// Step 2 reuses that stored value UNSAFELY by interpolating it into a new
// query, which is where the second-order payload wakes up.
function vulnFn(username, displayName) {
  members.push({ username: username, display_name: displayName });
  const member = members.filter(function (m) { return m.username === username; })[0];
  const sql = "SELECT * FROM users WHERE username='" + member.display_name + "'";
  return query(sql);
}
`,
  fixedCode: `
// Same mock tables as the vulnerable version.
const users = [
  { username: 'admin', role: 'admin', email: 'admin@pentrix.local', secret: 'TOP-SECRET-ADMIN-ONLY' },
  { username: 'bob', role: 'member', email: 'bob@pentrix.local', secret: null },
];
const members = [];

// Parameterized query: the bound value is data, never SQL.
function queryParam(param) {
  return users.filter(function (u) { return u.username === param; });
}

// FIXED: the stored display name is bound as a parameter, so a payload that
// sleeps in the members table can never become SQL when it is reused.
function vulnFn(username, displayName) {
  members.push({ username: username, display_name: displayName });
  const member = members.filter(function (m) { return m.username === username; })[0];
  return queryParam(member.display_name);
}
`,
  testExploit: `(function () { var rows = vulnFn('attacker', "' OR '1'='1"); return rows.length > 1 && rows.some(function (r) { return r.username === 'admin' && r.role === 'admin'; }); })()`,
  testLegit: `(function () { var rows = vulnFn('bob', 'bob'); return rows.length === 1 && rows[0].username === 'bob' && rows[0].role === 'member'; })()`,
  exploitDescription: 'Register with the display name \' OR \'1\'=\'1. It is stored safely at registration, but the profile page later interpolates that stored value into SELECT * FROM users WHERE username=\'...\', where the quote breakout turns the predicate into \'1\'=\'1\' and returns every user row, including the admin account.',
  fixHint: 'The stored value is data, not SQL. Do not concatenate it into the second query: bind it as a parameter (prepared statement placeholder) exactly like the registration step already does, so even a malicious stored value can only ever match literally.',
};
