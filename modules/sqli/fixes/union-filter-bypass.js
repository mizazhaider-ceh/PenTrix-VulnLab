'use strict';
module.exports = {
  module: 'sqli',
  vulnId: 'union-filter-bypass',
  title: 'UNION Filter Bypass',
  language: 'javascript',
  vulnerableCode: `
'use strict';
// Mock data for the vulnerable "Filtered Shop" search.
const PRODUCTS = [
  { id: 1, name: 'Hoodie', price: 40, description: 'A cozy hoodie' },
  { id: 2, name: 'Cap', price: 15, description: 'A plain cap' },
  { id: 3, name: 'Sticker', price: 2, description: 'A laptop sticker' },
];
// Mock secret standing in for the guarded admin secret. This is fake data,
// not a real flag.
const ADMIN_SECRET = 'M0CK-4DM1N-S3CR3T';
// Tiny stand-in for a real SQL engine: SQL keywords are case-insensitive,
// so UNION SELECT smuggles the secret row into the results when it reaches
// the query string.
function fakeDb(sql) {
  const lower = sql.toLowerCase();
  if (lower.indexOf('union') !== -1 && lower.indexOf('select') !== -1 && lower.indexOf('secret') !== -1) {
    return PRODUCTS.concat([{ id: 0, name: 'admin-secret', price: 0, description: ADMIN_SECRET }]);
  }
  const m = lower.match(/like\\s*'%([^%]*)%'/);
  const needle = m ? m[1] : '';
  return PRODUCTS.filter(function (p) { return p.name.toLowerCase().indexOf(needle) !== -1; });
}
// VULNERABLE: naive case-sensitive blacklist (strips only lowercase
// 'union') plus string-interpolated SQL.
function vulnFn(term) {
  const filtered = String(term).split('union').join('');
  const sql = "SELECT id, name, price, description FROM products WHERE name LIKE '%" + filtered + "%'";
  return fakeDb(sql);
}
`,
  fixedCode: `
'use strict';
// Mock data for the fixed "Filtered Shop" search (same catalog, same secret).
const PRODUCTS = [
  { id: 1, name: 'Hoodie', price: 40, description: 'A cozy hoodie' },
  { id: 2, name: 'Cap', price: 15, description: 'A plain cap' },
  { id: 3, name: 'Sticker', price: 2, description: 'A laptop sticker' },
];
// Mock secret standing in for the guarded admin secret. This is fake data,
// not a real flag.
const ADMIN_SECRET = 'M0CK-4DM1N-S3CR3T';
// FIXED: parameterized query. The search term is bound as a plain value
// (never concatenated into SQL), so UNION and friends stay inert text and
// can never change the query structure. LIKE wildcards in the term are also
// inert here because the term is matched as a literal value.
function vulnFn(term) {
  const needle = String(term).toLowerCase();
  return PRODUCTS.filter(function (p) { return p.name.toLowerCase().indexOf(needle) !== -1; });
}
`,
  testExploit: `vulnFn("' UnIoN SELECT id, username, password, secret FROM users -- ").some(function (r) { return r.description === ADMIN_SECRET; })`,
  testLegit: `(function () { var rows = vulnFn('hoodie'); return rows.length === 1 && rows[0].name === 'Hoodie'; })()`,
  exploitDescription: 'The shop strips only the exact lowercase word "union" from the search term, but SQL keywords are case-insensitive. Mixed case (UnIoN) or SQL comments (Un/**/ION) pass through the filter untouched, so an injected UNION SELECT runs as real SQL and appends the admin secret row to the search results.',
  fixHint: 'Stop building SQL by string concatenation. Use a parameterized query: put a placeholder in the SQL and bind the search term as a value, so user input is never parsed as SQL. A blacklist is not a fix: attackers always find another spelling of the keyword.',
};
