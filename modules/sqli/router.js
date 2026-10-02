'use strict';

// SQL Injection module: four classic SQLi challenges against a better-sqlite3 DB.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();

// ---------- extra tables for the batch-02 labs (prefixed, self-contained) ----------
function sqliExtraTables() {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS sqli_members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sqli_sales (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product TEXT NOT NULL,
      region TEXT NOT NULL,
      amount REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sqli_feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
  if (db.prepare('SELECT COUNT(*) AS c FROM sqli_sales').get().c === 0) {
    const ins = db.prepare('INSERT INTO sqli_sales (product, region, amount) VALUES (?,?,?)');
    ins.run('PenTrix Hoodie', 'EU', 39.99);
    ins.run('Sticker Pack', 'EU', 4.99);
    ins.run('Bug Bounty Field Notes', 'US', 14.99);
    ins.run('USB Rubber Ducky (Training)', 'US', 79.99);
    ins.run('PenTrix Hoodie', 'APAC', 39.99);
    ins.run('Sticker Pack', 'APAC', 4.99);
  }
}
sqliExtraTables();

// The admin secret is the exfiltration target for several labs below.
function adminSecret() {
  try {
    const r = getDb().prepare("SELECT secret FROM users WHERE username='admin'").get();
    return (r && r.secret) || 'PENTRIX{sqli_union}';
  } catch (e) {
    return 'PENTRIX{sqli_union}';
  }
}

const VULNS = [
  {
    id: 'login-bypass',
    name: 'Login Bypass',
    difficulty: 'Easy',
    hint: 'The login query is built by string interpolation. Make the WHERE clause always true and comment out the password check.',
    how: "Log in as admin with the classic ' OR '1'='1 payload.",
    link: '/sqli/login',
  },
  {
    id: 'union',
    name: 'UNION-based Injection',
    difficulty: 'Medium',
    hint: 'The product search interpolates your query into a LIKE clause returning 4 columns. Balance the quotes, then UNION in a second SELECT against the users table.',
    how: "Use UNION SELECT to dump the users table (id, username, password, secret) through the product search and recover the admin secret.",
    link: '/sqli/products',
  },
  {
    id: 'blind',
    name: 'Boolean Blind Injection',
    difficulty: 'Medium',
    hint: 'The product page only tells you whether a row exists. Extract the admin secret one character at a time with true/false conditions, then submit it.',
    how: "Extract the admin secret via boolean conditions, then submit it in the form on the product page.",
    link: '/sqli/product',
  },
  {
    id: 'error',
    name: 'Error-based Injection',
    difficulty: 'Hard',
    hint: 'The detail page interpolates your id straight into the query and leaks raw database errors. Break out of the query and make SQLite complain.',
    how: "Trigger a visible SQLite syntax error (e.g. a stray quote) through the id parameter.",
    link: '/sqli/detail',
  },
  {
    id: 'order-by',
    name: 'ORDER BY Injection',
    difficulty: 'Medium',
    hint: 'The sort parameter goes straight into ORDER BY. ORDER BY accepts full expressions, including CASE WHEN with a subquery against the users table. Watch the row order flip as your condition changes.',
    how: 'Run a CASE WHEN boolean oracle inside ORDER BY against the users table and observe the sorting change.',
    link: '/sqli/sort',
  },
  {
    id: 'second-order',
    name: 'Second-Order SQL Injection',
    difficulty: 'Hard',
    hint: 'Registration stores your display name safely, but the profile page interpolates that stored value into a brand-new query later. A payload that is harmless at rest becomes SQL when it is reused.',
    how: 'Register with a display name containing a quote-breakout, then view your profile to trigger the stored injection and land on the admin account.',
    link: '/sqli/register',
  },
  {
    id: 'like-wildcard',
    name: 'LIKE Wildcard Injection',
    difficulty: 'Medium',
    hint: 'Your search term is dropped into a LIKE pattern and the % and _ characters are never escaped. Those are wildcards, not plain characters.',
    how: 'Use % or _ wildcards in the search to dump rows the search was never meant to return.',
    link: '/sqli/wildcard',
  },
  {
    id: 'limit-offset',
    name: 'LIMIT/OFFSET Injection',
    difficulty: 'Easy',
    hint: 'The page shows only 2 products by default, but the limit parameter is interpolated raw into the LIMIT clause. LIMIT accepts more than a plain number.',
    how: 'Inject LIMIT syntax (negative numbers, comma offsets) to dump rows beyond the default page.',
    link: '/sqli/paged',
  },
  {
    id: 'groupby-having',
    name: 'GROUP BY Injection',
    difficulty: 'Medium',
    hint: 'The stats page groups sales by an expression you control and prints the grouping key back. GROUP BY accepts any expression, including a subquery.',
    how: 'Point the GROUP BY expression at the users table so the admin secret comes back as the grouping key.',
    link: '/sqli/stats',
  },
  {
    id: 'union-filter-bypass',
    name: 'UNION Filter Bypass',
    difficulty: 'Medium',
    hint: 'This shop strips the lowercase word "union" from your search. The filter is case-sensitive and knows nothing about SQL comments or mixed case.',
    how: 'Bypass the naive blacklist (uppercase, mixed case, or /**/ comments) and UNION out the admin secret.',
    link: '/sqli/shop',
  },
  {
    id: 'insert-inject',
    name: 'INSERT Injection',
    difficulty: 'Medium',
    hint: 'The feedback form builds its INSERT with string interpolation. You cannot stack queries here, but VALUES() happily accepts a subquery.',
    how: 'Break out of the VALUES list with a subquery that writes the admin secret into your feedback row.',
    link: '/sqli/feedback',
  },
  {
    id: 'error-cast',
    name: 'Error-based Injection (Runtime Errors)',
    difficulty: 'Easy',
    hint: 'This detail page leaks raw database errors like the other one, but a plain syntax error will not earn the flag here. Make SQLite fail at runtime instead: a bad function call or malformed JSON.',
    how: 'Trigger a runtime SQLite error (not a syntax error) through the id parameter.',
    link: '/sqli/cast',
  },
];

// ---------- Module index ----------
router.get('/', (req, res) => {
  const cards = VULNS.map((v) => `
    <div class="vuln-card">
      <h3><a href="${v.link}">${esc(v.name)}</a></h3>
      <p><strong>Difficulty:</strong> ${esc(v.difficulty)}</p>
      <p>${esc(v.how)}</p>
      ${hintBox(v.hint)}
      ${captured(req, 'sqli', v.id) ? '<p><strong>Flag captured.</strong></p>' : ''}
    </div>`).join('\n');
  res.send(page('SQL Injection', `
    ${brief('SQL Injection', 'This module targets a product catalog backed by SQLite. Twelve challenges walk you from a trivial login bypass through second-order injection, filter bypasses, and error-based extraction. Every flag is earned by a real query injection, never by guessing.')}
    <h2>Challenges</h2>
    ${cards}
  `));
});

// ---------- v1: login bypass ----------
router.get('/login', (req, res) => {
  res.send(page('Login Bypass', `
    ${brief('Login Bypass', 'Log in below. The query behind this form is vulnerable to SQL injection.')}
    <form method="POST" action="/sqli/login">
      <label>Username: <input name="username" /></label><br/>
      <label>Password: <input name="password" type="password" /></label><br/>
      <button type="submit">Log in</button>
    </form>
  `));
});

router.post('/login', (req, res) => {
  const u = req.body.username || '';
  const p = req.body.password || '';
  const db = getDb();
  // VULN: user input interpolated directly into the SQL string (no parameterization).
  const sql = `SELECT * FROM users WHERE username='${u}' AND password='${p}'`;
  let row = null;
  try {
    const rows = db.prepare(sql).all();
    row = rows[0] || null;
  } catch (e) {
    // broken query, treat as failed login
  }
  if (row && (row.username === 'admin' || row.role === 'admin')) {
    const flag = award(req, 'sqli', 'login-bypass');
    return res.send(page('Login Bypass', `
      <p>Logged in as <strong>${esc(row.username)}</strong> (role: ${esc(row.role)}).</p>
      ${flagBox(flag)}
    `));
  }
  res.send(page('Login Bypass', `
    <p><strong>Invalid username or password.</strong></p>
    <p><a href="/sqli/login">Try again</a></p>
  `));
});

// ---------- v2: UNION-based ----------
router.get('/products', (req, res) => {
  const q = req.query.q !== undefined ? String(req.query.q) : '';
  const db = getDb();
  // VULN: search term interpolated directly into the LIKE query.
  const sql = `SELECT id, name, price, description FROM products WHERE name LIKE '%${q}%'`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.id))}</td><td>${esc(String(r.name))}</td><td>${esc(String(r.price))}</td><td>${esc(String(r.description))}</td></tr>`
  ).join('\n');
  let body = `
    ${brief('Product Search', 'Search the product catalog. Your search term is interpolated into the SQL query.')}
    <form method="GET" action="/sqli/products">
      <input name="q" value="${esc(q)}" placeholder="search products" />
      <button type="submit">Search</button>
    </form>
  `;
  if (req.query.q !== undefined) {
    body += error
      ? `<p><strong>Database error:</strong> ${esc(error)}</p>`
      : `<table><tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>${table}</table>`;
  }
  let html = page('Product Search', body);
  if (html.includes('PENTRIX{sqli_union}')) {
    const flag = award(req, 'sqli', 'union');
    html = page('Product Search', body + flagBox(flag));
  }
  res.send(html);
});

// ---------- v3: boolean blind + secret submission ----------
function blindPage(resultHtml) {
  return page('Product Lookup (Blind)', `
    ${brief('Boolean Blind', 'Look up a product by id. The page only tells you whether the product exists. No data is ever printed back.')}
    <form method="GET" action="/sqli/product">
      <label>Product id: <input name="id" /></label>
      <button type="submit">Check</button>
    </form>
    ${resultHtml}
    <h3>Submit extracted admin secret</h3>
    <form method="POST" action="/sqli/blind-submit">
      <label>Admin secret: <input name="secret" /></label>
      <button type="submit">Submit</button>
    </form>
  `);
}

router.get('/product', (req, res) => {
  const id = req.query.id !== undefined ? String(req.query.id) : '';
  let result = '';
  if (id !== '') {
    const db = getDb();
    // VULN: id interpolated directly into the query; only a true/false oracle is exposed.
    const sql = `SELECT * FROM products WHERE id='${id}'`;
    try {
      const rows = db.prepare(sql).all();
      result = rows.length > 0 ? '<p><strong>Product exists.</strong></p>' : '<p>Not found.</p>';
    } catch (e) {
      result = '<p>Not found.</p>';
    }
  }
  res.send(blindPage(result));
});

router.post('/blind-submit', (req, res) => {
  const submitted = String(req.body.secret || '').trim();
  const db = getDb();
  let adminSecret = 'PENTRIX{sqli_union}';
  try {
    const admin = db.prepare("SELECT secret FROM users WHERE username='admin'").get();
    if (admin && admin.secret) adminSecret = admin.secret;
  } catch (e) {
    // fall back to the known literal
  }
  if (submitted !== '' && submitted === adminSecret) {
    const flag = award(req, 'sqli', 'blind');
    return res.send(page('Blind Submission', `
      <p><strong>Correct.</strong> You extracted the admin secret via boolean blind injection.</p>
      ${flagBox(flag)}
      <p><a href="/sqli/product">Back</a></p>
    `));
  }
  res.send(page('Blind Submission', `
    <p><strong>Incorrect secret.</strong> Keep probing the oracle with boolean conditions.</p>
    <p><a href="/sqli/product">Back</a></p>
  `));
});

// ---------- v4: error-based ----------
router.get('/detail', (req, res) => {
  const id = req.query.id !== undefined ? String(req.query.id) : '';
  let body = `
    ${brief('Product Detail', 'View a product by id. Database errors are shown raw on this page.')}
    <form method="GET" action="/sqli/detail">
      <label>Product id: <input name="id" /></label>
      <button type="submit">View</button>
    </form>
  `;
  if (id !== '') {
    const db = getDb();
    // VULN: id interpolated raw into the query; raw sqlite errors leak to the page.
    const sql = `SELECT * FROM products WHERE id=${id}`;
    try {
      const row = db.prepare(sql).get();
      body += row
        ? `<h3>${esc(row.name)}</h3><p>Price: ${esc(String(row.price))}</p><p>${esc(row.description)}</p>`
        : '<p>Not found.</p>';
    } catch (e) {
      body += `<p><strong>SQL error:</strong> ${e.message}</p>`; // VULN: raw error reflected
      // SQLite reports a stray quote as "unrecognized token" and other bad
      // input as "syntax error"; both prove error-based injection works.
      if (/syntax error|unrecognized token/i.test(e.message)) {
        const flag = award(req, 'sqli', 'error');
        return res.send(page('Product Detail', body + flagBox(flag)));
      }
    }
  }
  res.send(page('Product Detail', body));
});

// ---------- v5: ORDER BY injection ----------
router.get('/sort', (req, res) => {
  const sort = req.query.sort !== undefined ? String(req.query.sort) : 'name';
  const db = getDb();
  // VULN: sort expression interpolated directly into the ORDER BY clause.
  const sql = `SELECT id, name, price FROM products ORDER BY ${sort}`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r, i) => `
    <tr><td>${i + 1}</td><td>${esc(String(r.id))}</td><td>${esc(r.name)}</td><td>${esc(String(r.price))}</td></tr>`
  ).join('\n');
  let body = `
    ${brief('Sortable Catalog', 'Sort the product catalog. The <code>sort</code> parameter is interpolated straight into the <code>ORDER BY</code> clause, and ORDER BY accepts far more than a column name.')}
    <form method="GET" action="/sqli/sort">
      <label>Sort by: <input name="sort" value="${esc(sort)}" size="70" /></label>
      <button type="submit">Sort</button>
    </form>
    <p class="note">Try <code>price DESC</code>, a column index like <code>2</code>, then ask yourself what a <code>CASE WHEN</code> could do here.</p>
  `;
  body += error
    ? `<p><strong>Database error:</strong> ${esc(error)}</p>`
    : `<table><tr><th>#</th><th>ID</th><th>Name</th><th>Price</th></tr>${table}</table>`;
  let flagHtml = '';
  // The exploit genuinely ran when a CASE WHEN oracle against the users table
  // executed inside ORDER BY without error: the row order is the oracle.
  if (!error && /case\s+when/i.test(sort) && /\busers\b/i.test(sort)) {
    flagHtml = flagBox(award(req, 'sqli', 'order-by'));
  }
  res.send(page('Sortable Catalog (ORDER BY Injection)', body + flagHtml + `<p><a href="/sqli">Back</a></p>`));
});

// ---------- v6: second-order injection ----------
// Step 1: registration stores the display name safely (prepared statement).
router.get('/register', (req, res) => {
  res.send(page('Member Registration', `
    ${brief('Member Registration', 'Create a member account. Your display name is stored with a prepared statement, so nothing dangerous can happen at this step. The danger comes later, when the stored value is reused.')}
    <form method="POST" action="/sqli/register">
      <label>Username: <input name="username" required /></label><br/>
      <label>Display name: <input name="display_name" required /></label><br/>
      <label>Password: <input name="password" type="password" required /></label><br/>
      <button type="submit">Register</button>
    </form>
    <p class="note">After registering, view your profile at <code>/sqli/profile?u=YOUR_USERNAME</code>.</p>
    <p><a href="/sqli">Back</a></p>
  `));
});

router.post('/register', (req, res) => {
  const username = String(req.body.username || '').trim().slice(0, 40);
  const displayName = String(req.body.display_name || '').trim().slice(0, 80);
  const password = String(req.body.password || '').slice(0, 80);
  if (!username || !displayName || !password) {
    return res.status(400).send(page('Member Registration', '<p>All fields are required.</p><p><a href="/sqli/register">Back</a></p>'));
  }
  const db = getDb();
  try {
    // Parameterized: the payload is stored verbatim and sleeps quietly.
    db.prepare('INSERT INTO sqli_members (username, display_name, password) VALUES (?,?,?)')
      .run(username, displayName, password);
  } catch (e) {
    return res.status(400).send(page('Member Registration', `<p><strong>Could not register:</strong> ${esc(e.message)}</p><p><a href="/sqli/register">Back</a></p>`));
  }
  res.send(page('Member Registration', `
    <p>Registered as <strong>${esc(username)}</strong>.</p>
    <p><a href="/sqli/profile?u=${encodeURIComponent(username)}">View your profile</a></p>
  `));
});

// Step 2: the profile page interpolates the STORED display name into a new query.
router.get('/profile', (req, res) => {
  const u = String(req.query.u || '');
  const db = getDb();
  const member = u ? db.prepare('SELECT * FROM sqli_members WHERE username = ?').get(u) : null;
  let body = `
    ${brief('Member Profile', "Look up a member. The app then finds the matching user account using the member's stored display name.")}
    <form method="GET" action="/sqli/profile">
      <label>Username: <input name="u" value="${esc(u)}" /></label>
      <button type="submit">View profile</button>
    </form>
  `;
  let flagHtml = '';
  if (!member) {
    body += u ? '<p><strong>No such member.</strong> Register first.</p>' : '<p>Enter a member username above.</p>';
  } else {
    // VULN: second-order injection. display_name was stored safely, but it is
    // interpolated into a brand-new query here, where the payload wakes up.
    const sql = `SELECT * FROM users WHERE username='${member.display_name}'`;
    let account = null;
    let error = null;
    try {
      account = db.prepare(sql).get();
    } catch (e) {
      error = e.message;
    }
    body += `<h3>Member: ${esc(member.username)}</h3><p>Display name: ${esc(member.display_name)}</p>`;
    if (error) {
      body += `<p><strong>Database error:</strong> ${esc(error)}</p>`;
    } else if (account) {
      body += `<h3>Linked user account</h3>
        <table>
          <tr><th>Username</th><td>${esc(account.username)}</td></tr>
          <tr><th>Role</th><td>${esc(account.role)}</td></tr>
          <tr><th>Email</th><td>${esc(account.email)}</td></tr>
          <tr><th>Secret</th><td>${esc(account.secret)}</td></tr>
        </table>`;
      // The stored payload genuinely executed when the lookup lands on the
      // admin account for a member who is not admin.
      if (account.username === 'admin' && member.username !== 'admin') {
        flagHtml = flagBox(award(req, 'sqli', 'second-order'));
      }
    } else {
      body += '<p>No user account matches this display name.</p>';
    }
  }
  res.send(page('Member Profile (Second-Order SQLi)', body + flagHtml + `<p><a href="/sqli">Back</a></p>`));
});

// ---------- v7: LIKE wildcard injection ----------
router.get('/wildcard', (req, res) => {
  const q = req.query.q !== undefined ? String(req.query.q) : '';
  const db = getDb();
  // VULN: q interpolated into LIKE; % and _ wildcards are never escaped.
  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const total = db.prepare('SELECT COUNT(*) AS c FROM products').get().c;
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.id))}</td><td>${esc(r.name)}</td><td>${esc(String(r.price))}</td></tr>`
  ).join('\n');
  let body = `
    ${brief('Wildcard Search', 'Search the catalog by name. Your term is placed inside a <code>LIKE</code> pattern, and nobody escapes the pattern characters.')}
    <form method="GET" action="/sqli/wildcard">
      <input name="q" value="${esc(q)}" placeholder="search products" />
      <button type="submit">Search</button>
    </form>
  `;
  if (req.query.q !== undefined) {
    body += error
      ? `<p><strong>Database error:</strong> ${esc(error)}</p>`
      : `<p>${rows.length} result(s).</p><table><tr><th>ID</th><th>Name</th><th>Price</th></tr>${table}</table>`;
  }
  let flagHtml = '';
  // Wildcards genuinely used when the pattern contains % or _ and the query
  // dumps the whole catalog in one shot.
  if (!error && /[%_]/.test(q) && rows.length >= total && total > 0) {
    flagHtml = flagBox(award(req, 'sqli', 'like-wildcard'));
  }
  res.send(page('Wildcard Search (LIKE Injection)', body + flagHtml + `<p><a href="/sqli">Back</a></p>`));
});

// ---------- v8: LIMIT injection ----------
router.get('/paged', (req, res) => {
  const limit = req.query.limit !== undefined ? String(req.query.limit) : '2';
  const db = getDb();
  // VULN: limit interpolated raw into the LIMIT clause.
  const sql = `SELECT id, name, price FROM products ORDER BY id LIMIT ${limit}`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.id))}</td><td>${esc(r.name)}</td><td>${esc(String(r.price))}</td></tr>`
  ).join('\n');
  let body = `
    ${brief('Paged Catalog', 'The catalog shows 2 products per page. The <code>limit</code> parameter controls the page size and is interpolated raw into the query.')}
    <form method="GET" action="/sqli/paged">
      <label>Limit: <input name="limit" value="${esc(limit)}" size="10" /></label>
      <button type="submit">Show</button>
    </form>
  `;
  body += error
    ? `<p><strong>Database error:</strong> ${esc(error)}</p>`
    : `<p>Showing ${rows.length} product(s).</p><table><tr><th>ID</th><th>Name</th><th>Price</th></tr>${table}</table>`;
  let flagHtml = '';
  // Genuine LIMIT-syntax injection: non-numeric LIMIT content that still runs.
  if (!error && /[^0-9]/.test(limit) && rows.length > 0) {
    flagHtml = flagBox(award(req, 'sqli', 'limit-offset'));
  }
  res.send(page('Paged Catalog (LIMIT Injection)', body + flagHtml + `<p><a href="/sqli">Back</a></p>`));
});

// ---------- v9: GROUP BY injection ----------
router.get('/stats', (req, res) => {
  const by = req.query.by !== undefined ? String(req.query.by) : 'region';
  const db = getDb();
  // VULN: GROUP BY expression interpolated; the grouping key is echoed back.
  const sql = `SELECT ${by} AS grp, COUNT(*) AS n, SUM(amount) AS total FROM sqli_sales GROUP BY ${by}`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.grp))}</td><td>${esc(String(r.n))}</td><td>${esc(String(r.total))}</td></tr>`
  ).join('\n');
  let body = `
    ${brief('Sales Stats', 'Sales grouped by a dimension you choose. The <code>by</code> parameter becomes the <code>GROUP BY</code> expression, and the grouping key is printed in the first column.')}
    <form method="GET" action="/sqli/stats">
      <label>Group by: <input name="by" value="${esc(by)}" size="50" /></label>
      <button type="submit">Group</button>
    </form>
    <p class="note">Try <code>region</code>, <code>product</code>, then something the query was never meant to group by.</p>
  `;
  body += error
    ? `<p><strong>Database error:</strong> ${esc(error)}</p>`
    : `<table><tr><th>Group</th><th>Rows</th><th>Total</th></tr>${table}</table>`;
  let flagHtml = '';
  const secret = adminSecret();
  // The injected GROUP BY expression genuinely returned the admin secret.
  if (!error && secret && rows.some((r) => String(r.grp).includes(secret))) {
    flagHtml = flagBox(award(req, 'sqli', 'groupby-having'));
  }
  res.send(page('Sales Stats (GROUP BY Injection)', body + flagHtml + `<p><a href="/sqli">Back</a></p>`));
});

// ---------- v10: UNION with a naive blacklist ----------
router.get('/shop', (req, res) => {
  const q = req.query.q !== undefined ? String(req.query.q) : '';
  // VULN: naive case-sensitive blacklist. Only the exact lowercase word is stripped.
  const filtered = q.split('union').join('');
  const db = getDb();
  // VULN: search term interpolated into the query.
  const sql = `SELECT id, name, price, description FROM products WHERE name LIKE '%${filtered}%'`;
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(sql).all();
  } catch (e) {
    error = e.message;
  }
  const table = rows.map((r) => `
    <tr><td>${esc(String(r.id))}</td><td>${esc(String(r.name))}</td><td>${esc(String(r.price))}</td><td>${esc(String(r.description))}</td></tr>`
  ).join('\n');
  let body = `
    ${brief('Filtered Shop', 'Search the shop. The word <code>union</code> (lowercase) is stripped from your search for "security". Good luck with that.')}
    <form method="GET" action="/sqli/shop">
      <input name="q" value="${esc(q)}" placeholder="search the shop" />
      <button type="submit">Search</button>
    </form>
  `;
  if (req.query.q !== undefined) {
    body += error
      ? `<p><strong>Database error:</strong> ${esc(error)}</p>`
      : `<table><tr><th>ID</th><th>Name</th><th>Price</th><th>Description</th></tr>${table}</table>`;
  }
  let html = page('Filtered Shop (UNION Filter Bypass)', body);
  const secret = adminSecret();
  // The bypass genuinely worked when the filter failed to stop the secret
  // from being UNIONed into the output.
  if (!error && secret && html.includes(secret)) {
    const flag = award(req, 'sqli', 'union-filter-bypass');
    html = page('Filtered Shop (UNION Filter Bypass)', body + flagBox(flag));
  }
  res.send(html);
});

// ---------- v11: INSERT injection ----------
router.get('/feedback', (req, res) => {
  const db = getDb();
  const rows = db.prepare('SELECT name, message, created_at FROM sqli_feedback ORDER BY id DESC').all();
  const items = rows.map((r) => `
    <div class="comment"><b>${esc(r.name)}</b> <span class="muted">${esc(r.created_at)}</span><p>${esc(r.message)}</p></div>`
  ).join('\n');
  let flagHtml = '';
  const secret = adminSecret();
  // The injected subquery genuinely wrote the admin secret into the table.
  if (secret && rows.some((r) => r.message.includes(secret))) {
    flagHtml = flagBox(award(req, 'sqli', 'insert-inject'));
  }
  res.send(page('Feedback (INSERT Injection)', `
    ${brief('Feedback', 'Leave feedback. Your input is interpolated straight into an <code>INSERT</code> statement. No stacked queries allowed, but who needs them?')}
    <form method="POST" action="/sqli/feedback">
      <label>Name: <input name="name" required /></label><br/><br/>
      <label>Message:<br/><textarea name="message" rows="3" cols="60" required></textarea></label><br/><br/>
      <button type="submit">Send feedback</button>
    </form>
    ${flagHtml}
    <hr/><h3>Feedback wall</h3>
    ${items || '<p>No feedback yet.</p>'}
    <p><a href="/sqli">Back</a></p>
  `));
});

router.post('/feedback', (req, res) => {
  const name = String(req.body.name || '').slice(0, 80);
  const msg = String(req.body.message || '').slice(0, 500);
  if (!name.trim() || !msg.trim()) {
    return res.status(400).send(page('Feedback', '<p>Name and message are required.</p><p><a href="/sqli/feedback">Back</a></p>'));
  }
  const db = getDb();
  // VULN: interpolated into INSERT; VALUES() accepts a subquery as a value.
  const sql = `INSERT INTO sqli_feedback(name, message) VALUES ('${name}', '${msg}')`;
  try {
    db.exec(sql);
  } catch (e) {
    return res.status(400).send(page('Feedback', `<p><strong>Database error:</strong> ${esc(e.message)}</p><p><a href="/sqli/feedback">Back</a></p>`));
  }
  res.redirect('/sqli/feedback');
});

// ---------- v12: error-based via runtime errors (not syntax errors) ----------
router.get('/cast', (req, res) => {
  const id = req.query.id !== undefined ? String(req.query.id) : '';
  let body = `
    ${brief('Product Detail (Runtime Errors)', 'View a product by id. Database errors are shown raw on this page, but this time a plain syntax error will not earn the flag.')}
    <form method="GET" action="/sqli/cast">
      <label>Product id: <input name="id" /></label>
      <button type="submit">View</button>
    </form>
  `;
  if (id !== '') {
    const db = getDb();
    // VULN: id interpolated raw into the query; raw sqlite errors leak to the page.
    const sql = `SELECT * FROM products WHERE id=${id}`;
    try {
      const row = db.prepare(sql).get();
      body += row
        ? `<h3>${esc(row.name)}</h3><p>Price: ${esc(String(row.price))}</p><p>${esc(row.description)}</p>`
        : '<p>Not found.</p>';
    } catch (e) {
      body += `<p><strong>SQL error:</strong> ${esc(e.message)}</p>`; // VULN: raw error reflected
      // A *runtime* error (bad function call, malformed JSON, missing column)
      // proves a different oracle than the syntax-error lab next door.
      if (/malformed JSON|wrong number of arguments|no such column|datatype mismatch/i.test(e.message)) {
        const flag = award(req, 'sqli', 'error-cast');
        return res.send(page('Product Detail (Runtime Errors)', body + flagBox(flag) + `<p><a href="/sqli">Back</a></p>`));
      }
    }
  }
  res.send(page('Product Detail (Runtime Errors)', body + `<p><a href="/sqli">Back</a></p>`));
});

module.exports = {
  id: 'sqli',
  name: 'SQL Injection',
  tagline: 'From login bypass to error-based extraction: four classic SQLi challenges.',
  description: 'An intentionally vulnerable product catalog and login backed by SQLite. Break string-interpolated queries, chain UNION SELECTs, build a boolean oracle, and provoke verbose database errors to capture the admin secret.',
  difficulty: 'Mixed',
  vulns: VULNS.map(({ id, name, difficulty, hint, how }) => ({ id, name, difficulty, hint, how })),
  router,
};
