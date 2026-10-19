'use strict';
// M11 fix block: Boolean Blind SQL Injection (boolean oracle).
// The vulnerable page only answers exists / not found, but that single bit
// of information lets an attacker evaluate any true/false SQL condition,
// for example extracting the admin secret one character at a time.
module.exports = {
  module: 'sqli',
  vulnId: 'blind',
  title: 'Boolean Blind SQL Injection (boolean oracle)',
  language: 'javascript',
  vulnerableCode: `// Mock tables (in-memory stand-ins for the real database).
var products = [
  { id: '1', name: 'Widget' },
  { id: '2', name: 'Gadget' }
];
var users = [
  { username: 'admin', secret: 's3cret-key-99' }
];

// Tiny evaluator for the limited SQL the page builds. It understands
//   SELECT * FROM products WHERE id='<input>'
// where <input> may smuggle:  1' AND (SELECT substr(secret,N,1) FROM users
// WHERE username='admin')='<guess>' --
// This mirrors the real page: it answers only 'exists' or 'not found'.
function evalCondition(cond) {
  var m = cond.match(/^\\(?\\s*SELECT\\s+substr\\(secret,(\\d+),1\\)\\s+FROM\\s+users\\s+WHERE\\s+username='([^']+)'\\s*\\)?\\s*(=|>|<|>=|<=|<>|!=)\\s*'([^']*)'\\s*$/i);
  if (!m) return false;
  var n = parseInt(m[1], 10), uname = m[2], op = m[3], rhs = m[4];
  var u = null;
  for (var i = 0; i < users.length; i++) {
    if (users[i].username === uname) u = users[i];
  }
  if (!u) return false;
  var ch = u.secret.substr(n - 1, 1);
  if (op === '=') return ch === rhs;
  if (op === '<>') return ch !== rhs;
  if (op === '!=') return ch !== rhs;
  if (op === '>') return ch > rhs;
  if (op === '<') return ch < rhs;
  if (op === '>=') return ch >= rhs;
  if (op === '<=') return ch <= rhs;
  return false;
}

function vulnFn(input) {
  // VULN: the raw input is pasted into the SQL text.
  // Real app: db.prepare("SELECT * FROM products WHERE id='" + input + "'").all()
  var sql = "SELECT * FROM products WHERE id='" + input + "'";
  var s = sql;
  var cut = s.indexOf('--');           // strip the injected comment
  if (cut !== -1) s = s.slice(0, cut);
  var m = s.match(/WHERE id='([^']*)'(.*)$/i);
  var idPart = m ? m[1] : '';
  var rest = m ? m[2].replace(/[;\\s]+$/, '') : '';
  var rows = products.filter(function (p) { return p.id === idPart; });
  var andMatch = rest.match(/^\\s*AND\\s+(.+)$/i);   // injected boolean condition
  if (andMatch && !evalCondition(andMatch[1])) rows = [];
  return rows.length > 0 ? 'exists' : 'not found';
}`,
  fixedCode: `// Mock tables (same data, flaw fixed).
var products = [
  { id: '1', name: 'Widget' },
  { id: '2', name: 'Gadget' }
];
var users = [
  { username: 'admin', secret: 's3cret-key-99' }
];

function vulnFn(input) {
  // FIX: parameterized query. The input is bound as a value, it is never
  // pasted into the SQL text, so injected SQL becomes a harmless literal.
  // Real app: db.prepare('SELECT * FROM products WHERE id=?').all(input)
  var rows = products.filter(function (p) { return p.id === input; });
  return rows.length > 0 ? 'exists' : 'not found';
}`,
  testExploit: `(function () {
  var guess = "1' AND (SELECT substr(secret,1,1) FROM users WHERE username='admin')='s' -- ";
  var wrong = "1' AND (SELECT substr(secret,1,1) FROM users WHERE username='admin')='z' -- ";
  var hit = vulnFn(guess);
  var miss = vulnFn(wrong);
  // The oracle leaks: the right guess says 'exists', the wrong one 'not found'.
  return hit === 'exists' && miss === 'not found';
})()`,
  testLegit: `(function () {
  return vulnFn('1') === 'exists' && vulnFn('2') === 'exists' && vulnFn('999') === 'not found';
})()`,
  exploitDescription: 'The page only answers exists or not found, but that one bit of information builds a true/false oracle: inject a condition that is true only when your guess about the secret is right (for example, the first character is "s"). The page yes/no answer tells you whether the guess was right, so the secret can be extracted one character at a time.',
  fixHint: 'The problem is string concatenation: user input becomes part of the SQL text. Fix it with a parameterized query (placeholder + bound value, for example id=? with the input passed separately), so the input is always treated as data and can never change the query structure.',
};
