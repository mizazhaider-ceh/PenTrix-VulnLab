'use strict';
module.exports = {
  module: 'sqli',
  vulnId: 'error',
  title: 'Error-based Injection',
  language: 'javascript',
  vulnerableCode: `// Mock data: a tiny products catalog and a secret kept in the "database".
var products = [
  { id: 1, name: 'Widget', price: 10 },
  { id: 2, name: 'Gadget', price: 20 }
];
var users = [
  { id: 1, name: 'admin', secret: 'DB-SECRET-9f31' }
];

// Tiny mock of the sqlite layer used by the real challenge.
function runQuery(sql) {
  var m = /^SELECT \\* FROM products WHERE id=(.*)$/.exec(sql);
  var tail = m[1];
  if (/^\\d+$/.test(tail)) {
    var id = parseInt(tail, 10);
    for (var i = 0; i < products.length; i++) {
      if (products[i].id === id) return products[i];
    }
    return null;
  }
  // Error oracle 1 (parse time): a stray quote breaks the SQL syntax.
  if (tail.indexOf("'") !== -1) {
    throw new Error('unrecognized token: "\\'" in: SELECT * FROM products WHERE id=' + tail);
  }
  // Error oracle 2 (runtime): a bad CAST fails at runtime and the error
  // text carries the actual value, so the error itself leaks data.
  var cast = /CAST\\s*\\(\\s*\\(\\s*SELECT\\s+secret\\s+FROM\\s+users\\s*\\)\\s*AS\\s+INTEGER\\s*\\)/i.exec(tail);
  if (cast) {
    throw new Error("datatype mismatch: cannot cast '" + users[0].secret + "' to INTEGER");
  }
  throw new Error('syntax error near: ' + tail);
}

function vulnFn(input) {
  var sql = 'SELECT * FROM products WHERE id=' + input; // VULN: raw interpolation
  try {
    return { row: runQuery(sql) };
  } catch (e) {
    return { error: e.message }; // VULN: raw DB error shown to the visitor
  }
}`,
  fixedCode: `// Mock data (same as the vulnerable version).
var products = [
  { id: 1, name: 'Widget', price: 10 },
  { id: 2, name: 'Gadget', price: 20 }
];
var users = [
  { id: 1, name: 'admin', secret: 'DB-SECRET-9f31' }
];

// FIX: parameterize. The id is validated as an integer and passed as a
// bound value, never concatenated into SQL text. No raw database error is
// ever shown to the visitor: failures get one generic message.
function vulnFn(input) {
  if (!/^\\d+$/.test(String(input))) {
    return { error: 'Invalid product id.' };
  }
  var id = parseInt(input, 10); // bound parameter, not SQL text
  var row = null;
  for (var i = 0; i < products.length; i++) {
    if (products[i].id === id) row = products[i];
  }
  return { row: row };
}`,
  testExploit: `vulnFn('1 UNION SELECT CAST((SELECT secret FROM users) AS INTEGER)').error.indexOf(users[0].secret) !== -1`,
  testLegit: `JSON.stringify(vulnFn('1').row) === JSON.stringify(products[0])`,
  exploitDescription: 'The detail page interpolates the id straight into the query and prints raw database errors. A runtime error payload such as 1 UNION SELECT CAST((SELECT secret FROM users) AS INTEGER) makes the error text carry the secret value, so the error message itself leaks data.',
  fixHint: 'Bind the id as a parameter instead of interpolating it into the SQL string, and never show raw database errors to the user: log them server-side and return one generic message.',
};
