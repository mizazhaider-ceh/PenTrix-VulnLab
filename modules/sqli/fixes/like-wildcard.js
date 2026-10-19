'use strict';
module.exports = {
  module: 'sqli',
  vulnId: 'like-wildcard',
  title: 'LIKE Wildcard Injection: Bind Parameters and Escape Wildcards',
  language: 'javascript',
  vulnerableCode: `'use strict';
// Self-contained mock of the vulnerable /sqli/wildcard endpoint.
// Mirrors the real code: the search term q is interpolated into
//   SELECT id, name, price FROM products WHERE name LIKE '%<q>%'
// with LIKE wildcards (% and _) never escaped. The page only
// reveals the number of matching rows.
const products = [
  { id: 1, name: 'Red Hoodie', price: 39 },
  { id: 2, name: 'Blue Jeans', price: 59 },
  { id: 3, name: 'Green T-Shirt', price: 19 },
];
const users = [
  { username: 'admin', secret: 'Purple-Harbor-9921' },
];

const REGEX_SPECIAL = '.*+?^$\\{}()|[]\\\\';
function escapeRegExpChar(c) {
  return REGEX_SPECIAL.indexOf(c) === -1 ? c : '\\\\' + c;
}

// SQL LIKE pattern to RegExp. A backslash escapes the next character,
// % matches any run of characters, _ matches exactly one character.
function likeMatch(value, pattern) {
  let src = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\\\' && i + 1 < pattern.length) {
      src += escapeRegExpChar(pattern[++i]);
    } else if (c === '%') {
      src += '.*';
    } else if (c === '_') {
      src += '.';
    } else {
      src += escapeRegExpChar(c);
    }
  }
  return new RegExp(src + '$', 'i').test(value);
}

// Tiny mock of the SQL engine, supporting exactly the query shapes
// this challenge produces: a plain name LIKE search, and the
// boolean-oracle injection with a subquery on the users table.
function mockQuery(sql) {
  const stmt = sql.split('--')[0]; // -- comments out the rest of the line
  const oracle = stmt.match(
    /OR\\s*\\(\\s*SELECT\\s+secret\\s+FROM\\s+users\\s+WHERE\\s+username\\s*=\\s*'admin'\\s*\\)\\s*LIKE\\s*'([^']*)'/i
  );
  if (oracle) {
    const secret = users.find(u => u.username === 'admin').secret;
    // name LIKE '<term>' OR <oracle>: every row matches when the guess is right
    return likeMatch(secret, oracle[1]) ? products.slice() : [];
  }
  const m = stmt.match(/name\\s+LIKE\\s*'([^']*)'/i);
  const pattern = m ? m[1] : '%';
  return products.filter(p => likeMatch(p.name, pattern));
}

function vulnFn(q) {
  // VULNERABLE: q is interpolated straight into the SQL string and
  // LIKE wildcards are never escaped.
  const sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'";
  return mockQuery(sql).length; // the page only reveals this count
}`,
  fixedCode: `'use strict';
// Reference fix for the LIKE injection. In production this is:
//
//   const pattern = '%' + String(q).replace(/[\\\\%_]/g, '\\\\$&') + '%';
//   db.prepare("SELECT id, name, price FROM products WHERE name LIKE ? ESCAPE '\\\\'").all(pattern);
//
// The ? placeholder keeps q out of the SQL text entirely (no quote
// breakout possible), and the backslash escaping turns user-supplied
// % and _ into literal characters (no wildcard dump possible).
const products = [
  { id: 1, name: 'Red Hoodie', price: 39 },
  { id: 2, name: 'Blue Jeans', price: 59 },
  { id: 3, name: 'Green T-Shirt', price: 19 },
];
const users = [
  { username: 'admin', secret: 'Purple-Harbor-9921' },
];

const REGEX_SPECIAL = '.*+?^$\\{}()|[]\\\\';
function escapeRegExpChar(c) {
  return REGEX_SPECIAL.indexOf(c) === -1 ? c : '\\\\' + c;
}

// SQL LIKE pattern to RegExp. A backslash escapes the next character,
// % matches any run of characters, _ matches exactly one character.
function likeMatch(value, pattern) {
  let src = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\\\' && i + 1 < pattern.length) {
      src += escapeRegExpChar(pattern[++i]);
    } else if (c === '%') {
      src += '.*';
    } else if (c === '_') {
      src += '.';
    } else {
      src += escapeRegExpChar(c);
    }
  }
  return new RegExp(src + '$', 'i').test(value);
}

function vulnFn(q) {
  // FIXED: q never touches the SQL string. It is escaped for LIKE
  // wildcards, wrapped in %...%, and passed as a bound parameter
  // (mocked here by filtering in JS), so quotes, % and _ are inert.
  const safe = String(q).replace(/[\\\\%_]/g, '\\\\$&');
  const pattern = '%' + safe + '%'; // bound as a parameter with ESCAPE '\\\\'
  return products.filter(p => likeMatch(p.name, pattern)).length;
}`,
  testExploit: `// True means THE EXPLOIT SUCCEEDED. Two vectors are checked:
// 1. the boolean-oracle quote breakout still leaks the admin secret;
// 2. an unescaped LIKE wildcard (% or _) still matches rows it should not,
//    so a bind-only fix without wildcard escaping is NOT accepted.
vulnFn("' OR (SELECT secret FROM users WHERE username='admin') LIKE 'P%' -- ") === products.length ||
vulnFn('%') === products.length ||
vulnFn('_') === products.length`,
  testLegit: `vulnFn('hoodie') === 1`,
  exploitDescription: 'The search term is interpolated into a LIKE pattern with no escaping. A quote breakout plus an OR subquery against the users table turns the match count into a boolean oracle: the injection returns every product only when the guess about the admin secret is right, so the secret can be extracted character by character. An unescaped % on its own also dumps the whole catalog.',
  fixHint: 'Never build SQL by concatenating user input. Bind the search term as a parameter (prepared statement with a ? placeholder) and escape the LIKE wildcards % and _ (plus the escape character itself) before adding the surrounding % wildcards, using an explicit ESCAPE clause.',
};
