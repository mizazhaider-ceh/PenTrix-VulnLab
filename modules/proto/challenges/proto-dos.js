'use strict';
// Polluting toString: the dashboard merges your query string into a widget
// object whose prototype is a fresh per-request scope, then renders it with
// string coercion. Pollute __proto__[toString] with a non-function value and
// the render crashes (DoS). The crash page awards the flag.
const express = require('express');
const { award } = require('../../../lib/flags');
const { briefPanel, esc, fixPanel, flagBox, hintLadder, page } = require('../../../lib/page');

const router = express.Router();

// ---------------------------------------------------------------------------
// Naive recursive merge (copied verbatim from modules/proto/router.js).
// The deliberate flaw: it walks every key, including __proto__, straight
// into the prototype chain. No key sanitization.
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

const vuln = {
  id: 'proto-dos',
  name: 'Polluting toString',
  difficulty: 'Easy',
  hint: 'The widget page stringifies an object whose prototype you control. What if toString stopped being a function?',
  hints: ["Polluting toString breaks the widget. What happens when toString isn't a function?", "The render crashes. It's a DoS via prototype pollution.", "Pollute __proto__[toString] and load the widget. Crash = flag."],
  tools: 'B',
  how: 'Pollute toString on the widget scope so the render crashes; the crash page awards the flag.',
  link: '/proto#proto-dos',
  start: 'curl -s "http://localhost:3000/proto/dos?__proto__[toString]=boom" | grep -o "The widget broke"',
};

// GET /proto/dos -> dashboard widget whose render merges the query string.
router.get('/dos', (req, res) => {
  const data = parseNested(rawQuery(req));
  const scope = {};               // fresh prototype scope for THIS request only
  const widget = Object.create(scope);
  widget.name = 'dashboard-widget';
  // VULN: __proto__ from the query merges into the widget's prototype scope.
  // The scope is per-request, so the breakage stays contained to this demo.
  merge(widget, data);
  let shown;
  try {
    shown = `${widget}`; // string coercion calls toString() from the prototype
  } catch (e) {
    const flag = award(req, 'proto', 'proto-dos');
    return res.send(page('Widget crashed', `
      <div class="clay-card">
        <h2>The widget broke</h2>
        <p>The dashboard tried to render the widget and crashed:</p>
        <div class="clay-well"><code>${esc(e.message)}</code></div>
        <p>You polluted <code>toString</code> on the widget's prototype scope, so
        string coercion exploded. Denial of service demonstrated.</p>
        ${flagBox(flag)}
        ${fixPanel('proto', 'proto-dos')}
        <p><a class="clay-btn clay-btn-secondary" href="/proto/dos">Reload a fresh widget</a></p>
      </div>
    `));
  }
  res.send(page('Widget status', `
    ${briefPanel('Dashboard widget', `
      <p>This page merges your query string into a widget object, then renders it
      with string coercion (<code>\`\${widget}\`</code>). The widget's prototype
      is a fresh object created per request, so your pollution cannot escape this page.</p>
    `, 'Dashboard')}
    <div class="clay-card">
      <h3>Merge a query string</h3>
      <form onsubmit="location='/proto/dos?'+document.getElementById('qs').value; return false;">
        <input id="qs" class="clay-input" size="55" placeholder="__proto__[toString]=boom" />
        <button type="submit" class="clay-btn clay-btn-primary">Merge</button>
      </form>
      <p><b>Try it:</b>
        <a href="/proto/dos?__proto__[toString]=boom"><code>?__proto__[toString]=boom</code></a>
      </p>
      <p>Widget renders as: <code>${esc(shown)}</code></p>
      <p class="note">What happens if <code>toString</code> stops being a function?</p>
    </div>
    ${hintLadder(vuln)}
  `));
});

module.exports = { vuln, router };
