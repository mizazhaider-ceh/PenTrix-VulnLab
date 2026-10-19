'use strict';
module.exports = {
  module: 'sqli',
  vulnId: 'union',
  title: 'UNION-based Injection in Product Search',
  language: 'javascript',
  vulnerableCode: `// Vulnerable: the search term is interpolated straight into the SQL string.
// A tiny in-sandbox mock DB that behaves like the real one: it evaluates
// whatever SQL text it is given, so injected UNION SELECTs really leak rows.
var PRODUCTS = [
  { id: 1, name: 'Red Hoodie', price: 39.99, description: 'Warm red hoodie' },
  { id: 2, name: 'Blue Hoodie', price: 34.99, description: 'Cool blue hoodie' },
  { id: 3, name: 'PenTrix Cap', price: 19.99, description: 'Embroidered cap' }
];
var USERS = [
  { id: 1, username: 'admin', password: 'pbkdf2$admin-hash', secret: 'ADMIN_SECRET_VALUE' },
  { id: 2, username: 'izaz', password: 'pbkdf2$student-hash', secret: 'user-secret' }
];
// Mock engine: runs the raw SQL text (no binding). Honors -- comments and
// UNION SELECT <cols> FROM <table>, just like the real database would.
function runRaw(sql) {
  var cut = sql.indexOf('--');
  if (cut !== -1) sql = sql.slice(0, cut);
  var out = [];
  var likeIdx = sql.indexOf("LIKE '%");
  if (likeIdx !== -1) {
    var termStart = likeIdx + 7;
    var termEnd = sql.indexOf("%'", termStart);
    var unionIdx = sql.indexOf('UNION', termStart);
    var term;
    if (unionIdx !== -1 && (termEnd === -1 || unionIdx < termEnd)) {
      term = sql.slice(termStart, unionIdx);
    } else {
      term = sql.slice(termStart, termEnd === -1 ? sql.length : termEnd);
    }
    term = term.toLowerCase().replace(/%/g, '');
    for (var i = 0; i < PRODUCTS.length; i++) {
      var p = PRODUCTS[i];
      if (term === '' || p.name.toLowerCase().indexOf(term) !== -1) {
        out.push([p.id, p.name, p.price, p.description]);
      }
    }
  }
  var um = sql.match(/UNION\\s+SELECT\\s+(.+?)\\s+FROM\\s+(\\w+)/i);
  if (um) {
    var cols = um[1].split(',').map(function (c) { return c.trim(); });
    var tbl = um[2].toLowerCase() === 'users' ? USERS : PRODUCTS;
    for (var j = 0; j < tbl.length; j++) {
      out.push(cols.map(function (c) { return tbl[j][c]; }));
    }
  }
  return out;
}
function vulnFn(input) {
  var q = String(input);
  var sql = "SELECT id, name, price, description FROM products WHERE name LIKE '%" + q + "%'";
  return runRaw(sql);
}`,
  fixedCode: `// Fixed: parameterized query. The search term is bound as a value (LIKE ?)
// so the database treats it as data and never as part of the SQL text.
var PRODUCTS = [
  { id: 1, name: 'Red Hoodie', price: 39.99, description: 'Warm red hoodie' },
  { id: 2, name: 'Blue Hoodie', price: 34.99, description: 'Cool blue hoodie' },
  { id: 3, name: 'PenTrix Cap', price: 19.99, description: 'Embroidered cap' }
];
// Mock DB layer with a placeholder API (like better-sqlite3). The engine
// never evaluates the parameter as SQL; it only compares it to names.
var db = {
  prepare: function (sql) {
    return {
      all: function (params) {
        var term = String(params[0]).replace(/^%|%$/g, '').toLowerCase();
        var out = [];
        for (var i = 0; i < PRODUCTS.length; i++) {
          var p = PRODUCTS[i];
          if (term === '' || p.name.toLowerCase().indexOf(term) !== -1) {
            out.push([p.id, p.name, p.price, p.description]);
          }
        }
        return out;
      }
    };
  }
};
function vulnFn(input) {
  var sql = 'SELECT id, name, price, description FROM products WHERE name LIKE ?';
  return db.prepare(sql).all(['%' + String(input) + '%']);
}`,
  testExploit: `vulnFn("' UNION SELECT id, username, password, secret FROM users -- ").some(function (r) { return r.indexOf('admin') !== -1; })`,
  testLegit: `vulnFn('hoodie').length === 2 && vulnFn('hoodie')[0][1] === 'Red Hoodie'`,
  exploitDescription: "Submit the search term `' UNION SELECT id, username, password, secret FROM users -- ` (note the space after the dashes). The quote closes the LIKE string, the UNION appends a second 4-column SELECT against the users table, and the comment kills the trailing quote. The result table now shows user rows with usernames, password hashes and secrets, including the admin secret.",
  fixHint: 'Do not build SQL with string concatenation. Use a placeholder: `... WHERE name LIKE ?` and pass the search term (`%` + input + `%`) as a bound parameter. The database then treats the input purely as data, so quotes and UNION keywords in it can never change the query structure.',
};
