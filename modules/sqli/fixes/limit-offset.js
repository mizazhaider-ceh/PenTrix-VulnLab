'use strict';
module.exports = {
  module: 'sqli',
  vulnId: 'limit-offset',
  title: 'LIMIT/OFFSET Injection in Paged Catalog',
  language: 'javascript',
  vulnerableCode: `// Vulnerable: the limit parameter is interpolated raw into the LIMIT clause.
// SQLite's LIMIT accepts more than a plain page size: negative numbers mean
// "no limit" and comma syntax means "LIMIT offset,count". A tiny in-sandbox
// mock DB evaluates the raw SQL text, so those tricks really dump rows.
var PRODUCTS = [
  { id: 1, name: 'Pen', price: 2.50 },
  { id: 2, name: 'Notebook', price: 5.00 },
  { id: 3, name: 'Backpack', price: 40.00 },
  { id: 4, name: 'Headphones', price: 60.00 },
  { id: 5, name: 'Keyboard', price: 80.00 }
];
// Mock engine: runs the raw SQL text (no binding), honoring SQLite LIMIT
// semantics: LIMIT count, LIMIT offset,count, and negative = unlimited.
function runRaw(sql) {
  var m = sql.match(/LIMIT\\s+(-?[\\d\\s,]+)\\s*$/i);
  if (!m) throw new Error('near "LIMIT": syntax error');
  var parts = m[1].split(',').map(function (s) { return s.trim(); });
  for (var i = 0; i < parts.length; i++) {
    if (!/^-?\\d+$/.test(parts[i])) throw new Error('near "LIMIT": syntax error');
  }
  var offset = 0, count;
  if (parts.length === 1) {
    count = parseInt(parts[0], 10);
  } else {
    offset = parseInt(parts[0], 10);
    count = parseInt(parts[1], 10);
  }
  if (count < 0) count = PRODUCTS.length; // SQLite: LIMIT -1 means no limit
  if (offset < 0) offset = 0;
  return PRODUCTS.slice(offset, offset + count);
}
function vulnFn(input) {
  var limit = input !== undefined ? String(input) : '2';
  var sql = 'SELECT id, name, price FROM products ORDER BY id LIMIT ' + limit;
  return runRaw(sql);
}`,
  fixedCode: `// Fixed: strict integer validation plus a bound parameter. The limit is checked
// to be a non-negative integer and clamped to a sane page size, then passed
// as a bound parameter (LIMIT ?), so it can never become SQL syntax.
var PRODUCTS = [
  { id: 1, name: 'Pen', price: 2.50 },
  { id: 2, name: 'Notebook', price: 5.00 },
  { id: 3, name: 'Backpack', price: 40.00 },
  { id: 4, name: 'Headphones', price: 60.00 },
  { id: 5, name: 'Keyboard', price: 80.00 }
];
var MAX_LIMIT = 10;
// Mock DB layer with a placeholder API (like better-sqlite3). The engine
// only ever receives a validated integer, never raw user text.
var db = {
  prepare: function (sql) {
    return {
      all: function (params) {
        var n = params[0];
        if (!Number.isInteger(n) || n < 0) throw new Error('invalid limit');
        return PRODUCTS.slice(0, Math.min(n, MAX_LIMIT));
      }
    };
  }
};
function vulnFn(input) {
  var raw = input !== undefined ? String(input).trim() : '2';
  if (!/^\\d+$/.test(raw)) {
    throw new Error('Invalid limit: must be a non-negative integer');
  }
  var limit = Math.min(parseInt(raw, 10), MAX_LIMIT);
  var sql = 'SELECT id, name, price FROM products ORDER BY id LIMIT ?';
  return db.prepare(sql).all([limit]);
}`,
  testExploit: `(() => { try { return vulnFn('0,100').length > 2; } catch (e) { return false; } })()`,
  testLegit: `vulnFn('2').length === 2 && vulnFn('2')[0].id === 1 && vulnFn('2')[1].id === 2`,
  exploitDescription: 'Pass limit=0,100. The value is interpolated raw into the LIMIT clause, so the query becomes LIMIT 0,100 (offset 0, count 100) and returns every product instead of the 2-row page. Negative values also work: limit=-1 means "no limit" in SQLite.',
  fixHint: 'Validate the limit strictly before the query: allow only non-negative integer digits (/^\\d+$/), reject anything else (commas, dashes, SQL text), clamp to a sane maximum, then pass it as a bound parameter (LIMIT ?) instead of interpolating it into the SQL string.',
};
