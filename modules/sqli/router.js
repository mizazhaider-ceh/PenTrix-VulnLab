'use strict';

// SQL Injection module: four classic SQLi challenges against a better-sqlite3 DB.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();

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
    ${brief('SQL Injection', 'This module targets a product catalog backed by SQLite. Four challenges walk you from a trivial login bypass up to error-based extraction. Every flag is earned by a real query injection, never by guessing.')}
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

module.exports = {
  id: 'sqli',
  name: 'SQL Injection',
  tagline: 'From login bypass to error-based extraction: four classic SQLi challenges.',
  description: 'An intentionally vulnerable product catalog and login backed by SQLite. Break string-interpolated queries, chain UNION SELECTs, build a boolean oracle, and provoke verbose database errors to capture the admin secret.',
  difficulty: 'Mixed',
  vulns: VULNS.map(({ id, name, difficulty, hint, how }) => ({ id, name, difficulty, hint, how })),
  router,
};
