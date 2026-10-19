'use strict';
module.exports = {
  module: 'sqli',
  vulnId: 'insert-inject',
  title: 'INSERT injection in the feedback form',
  language: 'javascript',
  vulnerableCode: `// Self-contained mock of the feedback form flaw.
// Bare vm sandbox: no require, no process, no real DB.
// Tables: users (the admin row holds the exfiltration target)
// and sqli_feedback (the feedback wall).
var db = {
  users: [{ username: 'admin', secret: 'MOCK_ADMIN_SECRET' }],
  feedback: []
};

// Tiny mock SQL engine. It understands exactly one shape:
//   INSERT INTO sqli_feedback(name, message) VALUES (<v1>, <v2>)
// where each value is a quoted string literal or a scalar subquery
// (SELECT secret FROM users WHERE username='admin'). Comments started
// by -- run to end of line, like in SQLite.
function splitTopLevel(list) {
  var parts = [], depth = 0, inStr = false, cur = '';
  for (var i = 0; i < list.length; i++) {
    var ch = list[i];
    if (inStr) {
      cur += ch;
      if (ch === "'") {
        if (list[i + 1] === "'") { cur += "'"; i++; }
        else inStr = false;
      }
    } else if (ch === "'") { inStr = true; cur += ch; }
    else if (ch === '(') { depth++; cur += ch; }
    else if (ch === ')') { depth--; cur += ch; }
    else if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; }
    else cur += ch;
  }
  parts.push(cur);
  return parts;
}

function evalValue(part) {
  var s = part.trim();
  var strM = s.match(/^'(.*)'$/s);
  if (strM) return strM[1].replace(/''/g, "'");
  var subM = s.match(/^\\(\\s*SELECT\\s+secret\\s+FROM\\s+users\\s+WHERE\\s+username\\s*=\\s*'admin'\\s*\\)$/i);
  if (subM) return db.users[0].secret;
  throw new Error('mock db: unsupported value ' + s);
}

function mockExec(sql) {
  var noComment = sql.split('--')[0];
  var m = noComment.match(/^\\s*INSERT\\s+INTO\\s+sqli_feedback\\s*\\(\\s*name\\s*,\\s*message\\s*\\)\\s*VALUES\\s*\\(([\\s\\S]*)\\)\\s*;?\\s*$/i);
  if (!m) throw new Error('mock db: unsupported SQL: ' + sql);
  var parts = splitTopLevel(m[1]);
  if (parts.length !== 2) throw new Error('mock db: expected 2 VALUES, got ' + parts.length);
  db.feedback.push({ name: evalValue(parts[0]), message: evalValue(parts[1]) });
}

// THE FLAW: name and msg are glued straight into the SQL text, so input
// can break out of the VALUES list.
function vulnFn(name, msg) {
  var sql = "INSERT INTO sqli_feedback(name, message) VALUES ('" + name + "', '" + msg + "')";
  mockExec(sql);
}`,
  fixedCode: `// Reference fix: same mock tables, but the insert uses placeholders
// so user input is bound as data and never becomes part of the SQL text.
var db = {
  users: [{ username: 'admin', secret: 'MOCK_ADMIN_SECRET' }],
  feedback: []
};

function dbInsert(sql, params) {
  // Parameterised execution: only the fixed statement shape is accepted,
  // and every ? placeholder is bound literally, so a subquery hidden in
  // user input stays plain text and never runs.
  var m = sql.match(/^\\s*INSERT\\s+INTO\\s+sqli_feedback\\s*\\(\\s*name\\s*,\\s*message\\s*\\)\\s*VALUES\\s*\\(\\s*\\?,\\s*\\?\\s*\\)\\s*;?\\s*$/i);
  if (!m || !params || params.length !== 2) throw new Error('mock db: bad prepared statement');
  db.feedback.push({ name: String(params[0]), message: String(params[1]) });
}

function vulnFn(name, msg) {
  dbInsert('INSERT INTO sqli_feedback(name, message) VALUES (?, ?)', [name, msg]);
}`,
  testExploit: `(() => {
  // Real INSERT injection: break out of the name value, smuggle a
  // subquery in as the message value, comment out the tail. Success
  // means the admin secret landed in our feedback row.
  var n = db.feedback.length;
  vulnFn("attacker', (SELECT secret FROM users WHERE username='admin')) -- ", 'ignored');
  var row = db.feedback[n];
  return !!row && typeof row.message === 'string' && row.message.indexOf(db.users[0].secret) !== -1;
})()`,
  testLegit: `(() => {
  // Legitimate use: a normal feedback post is stored exactly as typed.
  var n = db.feedback.length;
  vulnFn('izaz', 'Great lab, learned a lot.');
  var row = db.feedback[n];
  return !!row && row.name === 'izaz' && row.message === 'Great lab, learned a lot.';
})()`,
  exploitDescription: 'The name field breaks out of the VALUES list with a quote, then injects (SELECT secret FROM users WHERE username=\'admin\') as the message value and comments out the rest with --, so the admin secret is written into the attacker\'s own feedback row and appears on the wall.',
  fixHint: 'Stop building the SQL string by hand. Use a parameterised query with ? placeholders and bind name and message as values, so user input can never become SQL.',
};
