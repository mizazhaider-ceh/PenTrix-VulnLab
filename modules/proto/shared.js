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
        // Sub-objects inherit the target's prototype, so a nested magic key
        // climbs to the same (per-session) prototype an unnested one would.
        target[k] = Object.create(Object.getPrototypeOf(target));
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

// ---------------------------------------------------------------------------
// Per-session pollution scope (P1-1).
//
// The lesson these challenges teach is unchanged: a naive recursive merge
// walks __proto__ (or constructor.prototype) into the shared prototype, and
// a fresh object then inherits the attacker's values. What changed is WHICH
// prototype is shared: one per student session instead of the process-wide
// Object.prototype. With the old process-global config, a single student's
// pollution handed every later visitor the admin flags for free and could
// corrupt unrelated pages; now the pollution persists for the polluting
// student (identical solo experience) and is invisible to everyone else.
//
// The wiring reproduces the real semantics exactly:
//   state.config's prototype IS state.proto, so merging
//     {"__proto__": {...}} recurses into state.proto and plants keys on it.
//   state.proto.constructor is a function whose .prototype is state.proto,
//     so constructor[prototype][...] lands on state.proto as well.
//   Admin checks build their "fresh object" with Object.create(state.proto),
//     so it inherits whatever the merge planted, just like a real {} would
//     inherit a polluted Object.prototype.
const { createSessionState } = require('../../lib/session-state');

function freshProtoState() {
  const proto = {};
  function SessionCtor() {}
  SessionCtor.prototype = proto;
  Object.defineProperty(proto, 'constructor', {
    value: SessionCtor, writable: true, configurable: true, enumerable: false,
  });
  const config = Object.create(proto);
  config.app = 'pentrix-vulnlab';
  return { proto, config };
}

const protoStates = createSessionState(freshProtoState);

function protoStateFor(req) {
  return protoStates.get(req);
}

// A brand-new object for an admin check: inherits this session's polluted
// prototype stand-in, exactly as a real {} inherits Object.prototype.
function freshUser(req) {
  return Object.create(protoStateFor(req).proto);
}

module.exports = { merge, parseNested, rawQuery, protoStateFor, freshUser, freshProtoState };
