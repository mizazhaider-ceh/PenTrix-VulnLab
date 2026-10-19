'use strict';
// M11 break-then-fix block for the SQLi Login Bypass challenge.
// A sandboxed runner executes `vulnerableCode` / `fixedCode` in a bare vm
// (no require, no process, no DB), then evaluates `testExploit` and
// `testLegit` as JS expressions against the resulting context.
module.exports = {
  module: 'sqli',
  vulnId: 'login-bypass',
  title: 'SQLi Login Bypass: fix it',
  language: 'javascript',
  vulnerableCode: `// Tiny in-memory users table (stands in for the SQLite 'users' table).
const users = [
  { username: 'admin', password: 'Sup3rS3cret!', role: 'admin' },
  { username: 'bob',   password: 'bobspass',     role: 'user' }
];

// Mini evaluator that behaves like the real SQLite WHERE clause for this
// challenge: it strips SQL comments, then evaluates AND/OR over string
// comparisons. This is exactly what makes a quote breakout work here.
function sqlLiteral(s) {
  const a = s.indexOf("'");
  const b = s.lastIndexOf("'");
  return (a >= 0 && b > a) ? s.slice(a + 1, b) : s;
}
function evalTerm(term, row) {
  const parts = term.split('=');
  const lhs = parts[0].trim().toLowerCase();
  const rhs = sqlLiteral(parts.slice(1).join('='));
  if (lhs === 'username') return row.username === rhs;
  if (lhs === 'password') return row.password === rhs;
  return sqlLiteral(parts[0]) === rhs;
}
function evalWhere(where, row) {
  const noComment = where.split('--')[0];
  return noComment.split(/\\s+OR\\s+/i).some(function (group) {
    return group.split(/\\s+AND\\s+/i).every(function (term) {
      return evalTerm(term.trim(), row);
    });
  });
}

function vulnFn(username, password) {
  // VULN: user input is interpolated straight into the SQL string, so a quote
  // breakout can rewrite the WHERE clause and skip the password check.
  const sql = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
  const where = sql.slice(sql.indexOf('WHERE') + 5);
  const row = users.find(function (u) { return evalWhere(where, u); }) || null;
  if (!row) return null;
  return (row.username === 'admin' || row.role === 'admin') ? row.username : null;
}`,
  fixedCode: `// Same tiny in-memory users table.
const users = [
  { username: 'admin', password: 'Sup3rS3cret!', role: 'admin' },
  { username: 'bob',   password: 'bobspass',     role: 'user' }
];

function vulnFn(username, password) {
  // FIX: parameterized query. The '?' placeholders are bound as data, so
  // quotes in the input can never break out and rewrite the WHERE clause.
  // (Shown here as direct value comparison, which is exactly what parameter
  // binding reduces to: input is compared as data, never executed as code.)
  const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';
  void sql;
  const bound = [username, password];
  const row = users.find(function (u) {
    return u.username === bound[0] && u.password === bound[1];
  }) || null;
  if (!row) return null;
  return (row.username === 'admin' || row.role === 'admin') ? row.username : null;
}`,
  testExploit: `vulnFn("admin' OR '1'='1' -- ", 'anything') === 'admin'`,
  testLegit: `vulnFn('admin', 'Sup3rS3cret!') === 'admin'`,
  exploitDescription: 'Log in as admin without the password using a SQL injection payload.',
  fixHint: 'Use a parameterized query or proper escaping instead of string concatenation.',
};
