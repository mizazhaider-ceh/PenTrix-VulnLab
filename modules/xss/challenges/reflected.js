'use strict';
// Reflected XSS: the search term is echoed into the results page unencoded.
const express = require('express');
const { page, esc, emptyState, claimBox } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');

const router = express.Router();

const CATALOG = [
  { sku: 'BG-1042', name: 'Ceramic pour-over set', price: '$39.00' },
  { sku: 'BG-1107', name: 'Walnut desk lamp', price: '$64.00' },
  { sku: 'BG-1210', name: 'Linen throw blanket', price: '$52.00' },
  { sku: 'BG-1318', name: 'Stoneware mug (set of 4)', price: '$28.00' },
  { sku: 'BG-1425', name: 'Brass bookends', price: '$34.00' },
  { sku: 'BG-1533', name: 'Wool desk mat', price: '$45.00' },
];

router.get('/search', (req, res) => {
  const q = String(req.query.q || '');
  const needle = q.toLowerCase();
  const hits = q ? CATALOG.filter((p) => p.name.toLowerCase().includes(needle) || p.sku.toLowerCase().includes(needle)) : [];
  const table = `<div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">Matching products</caption>
      <thead><tr><th scope="col">SKU</th><th scope="col">Product</th><th scope="col">Price</th></tr></thead>
      <tbody>${hits.map((p) => `<tr><td>${esc(p.sku)}</td><td>${esc(p.name)}</td><td>${esc(p.price)}</td></tr>`).join('')}</tbody>
    </table></div>`;
  // VULN: user input interpolated into HTML with no output encoding.
  const result = q
    ? `<h3>Results for: ${q}</h3>${hits.length ? table : `<p>No products matched "${q}". Try another search.</p>`}`
    : emptyState('Search the catalog', '<p>Look up a product by name or SKU, for example a lamp or a mug.</p>');
  res.send(page('Search · Brightside Goods', `
    <h2>Brightside Goods</h2>
    ${xssNonceTag(req, 'reflected')}
    ${siteFrame('Brightside Goods', ['Shop', 'Search', 'Cart'], `
      <form method="GET" action="/xss/search">
        <div class="clay-field">
          <label for="q">Search products</label>
          <input class="clay-input" type="text" id="q" name="q" value="${esc(q)}" placeholder="Search by name or SKU" autocomplete="off">
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Search</button>
      </form>
      ${result}`)}
    ${claimBox({ vulnId: 'reflected', payload: esc(`<script>${beacon('reflected')}</script>`), statusUrl: '/xss/claim-status?v=reflected' })}
    ${backLinks('reflected')}
  `));
});

module.exports = {
  vuln: {
    id: 'reflected',
    name: 'Reflected XSS',
    difficulty: 'Easy',
    hint: 'The search term is echoed straight back into the results page. What happens if the "search term" is HTML?',
    hints: [
      "The search box echoes your query back into the results page. What happens if your 'search term' is not text?",
      'The query is interpolated into HTML with no output encoding. A <script> tag in your search becomes a real script in the page.',
      'Wrap a fetch() call to /xss/collect in a script tag and submit it as the search query. The call needs three query parameters: c (the cookie), v (this challenge id) and n (the page token, window.__px).',
    ],
    tools: 'B',
    how: 'Put a script payload in the search box so it executes when the results page renders.',
    link: '/xss/search',
    start: 'curl -s "http://localhost:3000/xss/search?q=pentrix" | grep -n pentrix',
  },
  router,
};
