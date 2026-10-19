'use strict';
// M11 fix block: GROUP BY Injection (sqli/groupby-having).
// The stats page interpolated the `by` query parameter straight into the
// GROUP BY expression, and the grouping key was echoed back as the row label.
// An attacker could pass a scalar subquery such as
// (SELECT secret FROM users WHERE username='admin') and read the admin
// secret from the grouped output.
// Standard fix: the GROUP BY target is an identifier, and identifiers cannot
// be parameterized, so validate the value against a strict allowlist of
// known columns and reject everything else.
module.exports = {
  module: 'sqli',
  vulnId: 'groupby-having',
  title: 'GROUP BY Injection: allowlist the grouping column',
  language: 'javascript',
  vulnerableCode: `// Self-contained mock of the vulnerable stats query.
// The \`by\` value is interpolated into the SQL exactly like the real
// challenge did: SELECT <by> AS grp, ... GROUP BY <by>
const sales = [
  { region: 'north', product: 'laptop', amount: 1200 },
  { region: 'north', product: 'mouse', amount: 25 },
  { region: 'south', product: 'laptop', amount: 1100 },
  { region: 'south', product: 'mouse', amount: 30 }
];
const users = [
  { username: 'admin', secret: 'ADMIN_SECRET_9f3k2' },
  { username: 'guest', secret: 'guest-secret' }
];

function groupSales(by) {
  const groups = {};
  for (const row of sales) {
    const key = row[by];
    if (key === undefined) throw new Error('SQL error: no such column: ' + by);
    if (!groups[key]) groups[key] = { n: 0, total: 0 };
    groups[key].n += 1;
    groups[key].total += row.amount;
  }
  return Object.keys(groups).map(function (k) {
    return { grp: k, n: groups[k].n, total: groups[k].total };
  });
}

// Naive stand-in for better-sqlite3 executing the built SQL string:
// a plain column groups the sales; anything else is evaluated like a raw
// SQL expression, so an injected scalar subquery runs and its result comes
// back as the group label.
function vulnFn(by) {
  const sql = 'SELECT ' + by + ' AS grp, COUNT(*) AS n, SUM(amount) AS total FROM sqli_sales GROUP BY ' + by;
  if (by === 'region' || by === 'product') return groupSales(by);
  const m = by.match(/\\(\\s*SELECT\\s+(\\w+)\\s+FROM\\s+(\\w+)\\s+WHERE\\s+(\\w+)\\s*=\\s*'([^']*)'\\s*\\)/i);
  if (m) {
    const table = m[2].toLowerCase() === 'users' ? users : sales;
    const row = table.find(function (r) { return String(r[m[3]]) === m[4]; });
    if (row) {
      return [{ grp: String(row[m[1]]), n: sales.length, total: sales.reduce(function (a, r) { return a + r.amount; }, 0) }];
    }
  }
  throw new Error('SQL error: ' + sql);
}`,
  fixedCode: `// Reference solution: the GROUP BY expression is an identifier, so it
// cannot be parameterized. Instead it is validated against a strict
// allowlist of real columns; anything else is rejected before any SQL runs.
const sales = [
  { region: 'north', product: 'laptop', amount: 1200 },
  { region: 'north', product: 'mouse', amount: 25 },
  { region: 'south', product: 'laptop', amount: 1100 },
  { region: 'south', product: 'mouse', amount: 30 }
];
const users = [
  { username: 'admin', secret: 'ADMIN_SECRET_9f3k2' },
  { username: 'guest', secret: 'guest-secret' }
];

const ALLOWED_GROUP_COLUMNS = ['region', 'product'];

function vulnFn(by) {
  if (!ALLOWED_GROUP_COLUMNS.includes(by)) {
    throw new Error('Invalid group-by column: ' + String(by));
  }
  const groups = {};
  for (const row of sales) {
    const key = row[by];
    if (!groups[key]) groups[key] = { n: 0, total: 0 };
    groups[key].n += 1;
    groups[key].total += row.amount;
  }
  return Object.keys(groups).map(function (k) {
    return { grp: k, n: groups[k].n, total: groups[k].total };
  });
}`,
  testExploit: `(function () { try { return vulnFn("(SELECT secret FROM users WHERE username='admin')").some(function (r) { return String(r.grp).indexOf('ADMIN_SECRET_9f3k2') !== -1; }); } catch (e) { return false; } })()`,
  testLegit: `(function () { var rows = vulnFn('region'); return rows.length === 2 && rows.some(function (r) { return r.grp === 'north' && r.n === 2 && r.total === 1225; }) && rows.some(function (r) { return r.grp === 'south' && r.n === 2 && r.total === 1130; }); })()`,
  exploitDescription: 'The stats page put the "by" parameter directly into the GROUP BY expression and printed the grouping key. Passing a scalar subquery like (SELECT secret FROM users WHERE username=\'admin\') made the database return the admin secret as the group label.',
  fixHint: 'The grouping target is a column name (an identifier), and identifiers cannot be bound as parameters. Check the value against a strict allowlist of real columns (region, product) and reject anything else before building the query.',
};
