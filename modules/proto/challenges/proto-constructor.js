'use strict';
// Blacklist Bypass via constructor: the merge endpoint drops any key that
// contains the literal string "__proto__", but constructor.prototype reaches
// the same Object.prototype. Smuggle constructor[prototype][role]=admin
// through, then open the admin check.
const express = require('express');
const { award } = require('../../../lib/flags');
const { briefPanel, esc, fixPanel, flagBox, hintLadder, page, payloadBlock } = require('../../../lib/page');

const router = express.Router();

// ---------------------------------------------------------------------------
// Naive recursive merge (copied verbatim from modules/proto/router.js).
// The deliberate flaw: it walks every key, including constructor and
// prototype, straight into the prototype chain. No key sanitization.
function merge(target, source, blocked) {
  for (const k of Object.keys(source)) {
    if (blocked && blocked(k)) continue;
    const v = source[k];
    if (v !== null && typeof v === 'object') {
      const t = target[k];
      if ((typeof t === 'object' && t !== null) || typeof t === 'function') {
        merge(t, v, blocked);
      } else {
        target[k] = {};
        merge(target[k], v, blocked);
      }
    } else {
      target[k] = v;
    }
  }
  return target;
}

// Hand-rolled nested query parser (copied verbatim from modules/proto/router.js).
// a[b][c]=v becomes {a:{b:{c:v}}}. Dangerous segments are created as REAL
// own properties via defineProperty, exactly like a careless parser would.
function parseNested(raw) {
  const out = {};
  if (!raw) return out;
  for (const pair of raw.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const k = decodeURIComponent((eq === -1 ? pair : pair.slice(0, eq)).replace(/\+/g, ' '));
    const v = eq === -1 ? '' : decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
    const path = [];
    const re = /([^\[\]]+)|\[(.*?)\]/g;
    let m;
    while ((m = re.exec(k)) !== null) path.push(m[1] !== undefined ? m[1] : m[2]);
    if (!path.length) continue;
    let cur = out;
    for (let i = 0; i < path.length - 1; i++) {
      const seg = path[i];
      if (!Object.prototype.hasOwnProperty.call(cur, seg) || typeof cur[seg] !== 'object' || cur[seg] === null) {
        const nxt = {};
        if (seg === '__proto__' || seg === 'constructor' || seg === 'prototype') {
          Object.defineProperty(cur, seg, { value: nxt, enumerable: true, writable: true, configurable: true });
        } else {
          cur[seg] = nxt;
        }
      }
      cur = cur[seg];
    }
    const last = path[path.length - 1];
    if (last === '__proto__' || last === 'constructor' || last === 'prototype') {
      Object.defineProperty(cur, last, { value: v, enumerable: true, writable: true, configurable: true });
    } else {
      cur[last] = v;
    }
  }
  return out;
}

function rawQuery(req) {
  const u = req.originalUrl || '';
  const q = u.indexOf('?');
  return q === -1 ? '' : u.slice(q + 1);
}

// The application's global config object that every merge writes into.
const config = { app: 'pentrix-vulnlab' };

const vuln = {
  id: 'proto-constructor',
  name: 'Blacklist Bypass via constructor',
  difficulty: 'Medium',
  hint: 'Keys containing the literal string __proto__ are dropped. But the prototype chain has more than one entrance.',
  hints: ["The filter blocks __proto__. In Repeater, look for the other entrance to the prototype chain: every object reaches its constructor, and the constructor reaches its prototype.", "Intercept the merge request in Burp Proxy and send it to Repeater. In the query string, spell the path through constructor and prototype to reach the property the admin check tests. The blacklist never sees __proto__.", "In Repeater, add the constructor[prototype] segments to the query string, setting the role property the admin check reads, then open the admin check in the browser and watch the fresh object inherit it."],
  tools: 'BZ, B, C',
  how: 'In Repeater, send a query string that reaches Object.prototype through constructor/prototype instead of the blacklisted __proto__ key, then open the admin check so the fresh object inherits role=admin.',
  link: '/proto#proto-constructor',
  start: 'Open the merge console in your browser with Burp Proxy on, submit a harmless query string, intercept the GET /proto/constructor request in Proxy, then push it to Repeater and experiment with the key names.',
};

// GET /proto/constructor -> config merge console with a __proto__ blacklist.
router.get('/constructor', (req, res) => {
  const data = parseNested(rawQuery(req));
  // VULN: the blacklist only drops the literal string "__proto__", but the
  // prototype chain has another entrance: constructor.prototype.
  merge(config, data, (k) => k.includes('__proto__'));
  res.send(page('Blacklist Bypass', `
    ${briefPanel('Config merge console', `
      <p>This console folds your query string into the application's global
      config. After a lesson from the earlier console, any key containing the
      literal string <code>__proto__</code> is now dropped before merging.
      Everything else is still deep-merged.</p>
      <p>Blocked so far: <code>__proto__</code>. Allowed: everything else, including
      <code>constructor</code> and <code>prototype</code>.</p>
    `, 'Settings')}
    <div class="clay-card">
      <h3>Merge a query string</h3>
      <form onsubmit="location='/proto/constructor?'+document.getElementById('qs').value; return false;">
        <input id="qs" class="clay-input" size="55" placeholder="constructor[prototype][role]=admin" />
        <button type="submit" class="clay-btn clay-btn-primary">Merge</button>
      </form>
      <p><b>Try it:</b>
        <a href="/proto/constructor?constructor[prototype][role]=admin"><code>?constructor[prototype][role]=admin</code></a>
      </p>
      <p>Keys merged this request: <code>${esc(Object.keys(data).join(', ') || '(none)')}</code></p>
    </div>
    <div class="clay-card">
      <h3>Step 2: the admin check</h3>
      <p>The check creates a brand-new <code>{}</code> and tests
      <code>user.role === 'admin'</code>. If you found a path to
      <code>Object.prototype</code> that never uses the literal string
      <code>__proto__</code>, the fresh object inherits it.</p>
      <p><a class="clay-btn clay-btn-primary" href="/proto/constructor/admin">Open admin check</a></p>
    </div>
    ${hintLadder(vuln)}
  `));
});

// GET /proto/constructor/admin -> authorization check on a fresh object.
router.get('/constructor/admin', (req, res) => {
  const user = {}; // fresh object: no role is assigned anywhere in this handler
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-constructor');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>You reached <code>Object.prototype</code> through
      <code>constructor.prototype</code>, dodging the <code>__proto__</code>
      blacklist. A fresh <code>{}</code> now reads <code>role = 'admin'</code>.</p>
      ${flagBox(flag)}
      ${fixPanel('proto', 'proto-constructor')}
      <p><a class="clay-btn clay-btn-secondary" href="/proto">Back to the module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    <div class="clay-card">
      <h2>Access denied</h2>
      <p>A fresh <code>{}</code> has <code>role = ${esc(String(user.role))}</code>.
      Find a path to <code>Object.prototype</code> that never uses the literal
      string <code>__proto__</code>, then reload this page.</p>
      <p><a class="clay-btn clay-btn-secondary" href="/proto/constructor">Back to the merge console</a></p>
    </div>
  `));
});

module.exports = { vuln, router };
