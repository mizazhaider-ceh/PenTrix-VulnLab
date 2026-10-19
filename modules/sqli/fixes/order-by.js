'use strict';
// Fix block for sqli/order-by (ORDER BY Injection).
// Standard correct fix: strict allowlist of sort columns, direction ASC/DESC only.
module.exports = {
  module: 'sqli',
  vulnId: 'order-by',
  title: 'ORDER BY Injection: allowlist the sort column',
  language: 'javascript',
  vulnerableCode: `// self-contained mock: sort text goes straight into ORDER BY,
// which accepts full expressions like CASE WHEN (a boolean oracle).
const PRODUCTS = [
  { id: 1, name: 'Widget', price: 10 },
  { id: 2, name: 'Gadget', price: 25 },
  { id: 3, name: 'Gizmo', price: 5 }
];
const COLUMNS = ['id', 'name', 'price'];
function mockExecuteOrderBy(expr) {
  // Mock "database": if the ORDER BY expression carries a CASE WHEN oracle
  // over the users table, the condition controls the row order (oracle ran).
  var m = /^\\s*CASE\\s+WHEN\\s*\\((.+?)\\)\\s*=\\s*'([^']*)'\\s*THEN\\s+(\\w+)\\s+ELSE\\s+(\\w+)\\s+END/i.exec(expr);
  if (m && /\\busers\\b/i.test(m[1])) {
    // mock secret first char is 'P'; the condition outcome picks the column
    var col = (m[2] === 'P') ? m[3] : m[4];
    return { rows: sortRows(PRODUCTS, col), oracleRan: true };
  }
  return { rows: sortRows(PRODUCTS, expr), oracleRan: false };
}
function sortRows(rows, expr) {
  var parts = String(expr).trim().split(/\\s+/);
  var col = parts[0];
  var dir = (parts[1] && parts[1].toUpperCase() === 'DESC') ? -1 : 1;
  var key = COLUMNS.indexOf(col) >= 0 ? col : 'id';
  return rows.slice().sort(function (a, b) {
    var r = (a[key] < b[key] ? -1 : (a[key] > b[key] ? 1 : 0));
    return r * dir;
  });
}
function vulnFn(sort) {
  var expr = (sort === undefined) ? 'name' : String(sort);
  return mockExecuteOrderBy(expr);
}`,
  fixedCode: `// Reference solution: never interpolate user input into ORDER BY.
// Allowlist the column name, and only allow ASC or DESC as direction.
const PRODUCTS = [
  { id: 1, name: 'Widget', price: 10 },
  { id: 2, name: 'Gadget', price: 25 },
  { id: 3, name: 'Gizmo', price: 5 }
];
var ALLOWED = { id: true, name: true, price: true };
function fixedSortRows(rows, col, dir) {
  var key = ALLOWED[col] ? col : 'name';
  var mult = (dir === 'DESC') ? -1 : 1;
  return rows.slice().sort(function (a, b) {
    var r = (a[key] < b[key] ? -1 : (a[key] > b[key] ? 1 : 0));
    return r * mult;
  });
}
function vulnFn(sort) {
  var raw = (sort === undefined) ? 'name' : String(sort).trim();
  var parts = raw.split(/\\s+/);
  var col = ALLOWED[parts[0]] ? parts[0] : 'name';
  var dir = (parts[1] && parts[1].toUpperCase() === 'DESC') ? 'DESC' : 'ASC';
  return { rows: fixedSortRows(PRODUCTS, col, dir), oracleRan: false };
}`,
  testExploit: `vulnFn("CASE WHEN (SELECT substr(secret,1,1) FROM users WHERE username='admin')='P' THEN name ELSE price END").oracleRan === true`,
  testLegit: `vulnFn('price DESC').rows[0].price === 25 && vulnFn('name').rows[0].name === 'Gadget' && vulnFn('price DESC').oracleRan === false`,
  exploitDescription: 'The sort query parameter is interpolated directly into the ORDER BY clause. ORDER BY accepts full SQL expressions, so an attacker injects CASE WHEN (SELECT substr(secret,1,1) FROM users WHERE username=\'admin\')=\'P\' THEN name ELSE price END: the resulting row order reveals whether the guessed secret character matches, building a boolean oracle one character at a time.',
  fixHint: 'User input can never be trusted inside ORDER BY because placeholders cannot be used for identifiers. Validate the input against a strict allowlist of known column names (id, name, price), accept only ASC or DESC as the direction, and fall back to a safe default when the input does not match.',
};
