'use strict';
// Module-scoped helpers shared by the proto challenges. No routes, no vuln.
// Moved verbatim from modules/proto/router.js during the challenge split.

// ---------------------------------------------------------------------------
// Naive recursive merge. The deliberate flaw: it walks every key, including
// __proto__, constructor and prototype, straight into the prototype chain.
// VULN: no key sanitization; merging attacker-controlled objects pollutes prototypes.
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

// Hand-rolled nested query parser: a[b][c]=v becomes {a:{b:{c:v}}}.
// Dangerous segments (__proto__/constructor/prototype) are created as REAL
// own properties via defineProperty, exactly like a careless parser would.
// VULN: the parser preserves attacker-chosen magic keys instead of dropping them.
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

module.exports = { merge, parseNested, rawQuery, config };
