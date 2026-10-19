'use strict';
// Client-Side Pollution: GET /proto/client serves a theme picker whose nested
// query parser and naive recursive merge run in the BROWSER. A
// __proto__[theme] parameter pollutes Object.prototype in the visitor's
// browser; the page reads the theme from a fresh {}, renders it, and reports
// the value to GET /proto/client/claim, which awards the flag.
// This challenge needs no module-level helpers: no merge(), no config, no
// body parsing. Everything happens in the served HTML and its script.
const express = require('express');
const { appShell, esc, fixPanel, flagBox, page } = require('../../../lib/page');
const { award } = require('../../../lib/flags');

const router = express.Router();

const vuln = {
  id: 'proto-client',
  name: 'Client-Side Pollution',
  difficulty: 'Easy',
  hint: 'All the merging happens in your browser, not on the server. Open the demo link and watch the theme box change color.',
  hints: ["The client-side code reads ?__proto__[theme] and merges it. Client-side pollution.", "The browser's Object.prototype gets polluted. The page renders the polluted value.", "Open ?__proto__[theme]=pwned and see it reflected."],
  tools: "B",
  how: 'Load the page with a __proto__[theme] parameter so it renders the polluted value; the page reports it for the flag.',
  link: '/proto#proto-client',
  start: 'curl -s "http://localhost:3000/proto/client" | grep -o "themeOut"\n# The merge runs in JavaScript in your browser, so open this in a real\n# browser: http://localhost:3000/proto/client?__proto__[theme]=dark',
};

// GET /proto/client -> the theme picker. Parses the browser's query string
// into nested objects and merges them with a naive recursive merge, all in
// client-side JavaScript, then reads the theme from a fresh object.
// VULN: the parser preserves the magic __proto__ key and the merge walks it
// straight into Object.prototype, in the victim's browser.
router.get('/client', (req, res) => {
  res.send(page('Theme picker · Palette', `
    ${appShell('Palette', `
      <h2>Theme picker</h2>
      <p>Palette remembers your theme from the URL, so you can share a themed
      link with a friend. This page parses <b>your browser's</b> query string
      into nested objects and merges them into an options object with a naive
      recursive merge, all in JavaScript. It then reads the theme from a
      <i>fresh</i> object. If the merge polluted
      <code>Object.prototype</code> in your browser, the fresh object inherits
      your theme.</p>
      <form onsubmit="location='/proto/client?'+document.getElementById('qs').value; return false;">
        <div class="clay-field">
          <label for="qs">Query string to merge</label>
          <input class="clay-input" id="qs" type="text" size="55" placeholder="__proto__[theme]=dark" autocomplete="off">
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Apply</button>
      </form>
      <p><b>Try it:</b>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto/client?__proto__[theme]=dark"><code>?__proto__[theme]=dark</code></a>
        (any CSS color works, e.g. <code>tomato</code>, <code>#00ffcc</code>)
      </p>
      <div class="card" id="themeBox" style="border:2px solid #888; padding:1.5em; margin:1em 0;">
        <b>Active theme (read from a fresh <code>{}</code>):</b>
        <span id="themeOut">(default: light)</span>
      </div>
      <script>
        // VULN: hand-rolled nested query parser + naive recursive merge running
        // in the browser. __proto__ in the query string pollutes Object.prototype
        // HERE, in the victim's browser, and the page renders the polluted value.
        function setPath(obj, path, value) {
          var cur = obj;
          for (var i = 0; i < path.length - 1; i++) {
            var seg = path[i];
            if (!Object.prototype.hasOwnProperty.call(cur, seg)) {
              var nxt = {};
              if (seg === '__proto__') {
                Object.defineProperty(cur, seg, { value: nxt, enumerable: true, writable: true, configurable: true });
              } else {
                cur[seg] = nxt;
              }
            }
            cur = cur[seg];
          }
          cur[path[path.length - 1]] = value;
        }
        function merge(t, s) {
          for (const k of Object.keys(s)) {
            const v = s[k];
            if (v && typeof v === 'object') {
              if (!t[k] || typeof t[k] !== 'object') t[k] = {};
              merge(t[k], v);
            } else {
              t[k] = v;
            }
          }
        }
        function parseQuery(qs) {
          const out = {};
          qs.replace(/^\\?/, '').split('&').forEach(function (pair) {
            if (!pair) return;
            const kv = pair.split('=');
            const key = decodeURIComponent(kv[0]);
            const val = kv.length > 1 ? decodeURIComponent(kv[1]) : '';
            const path = [];
            const re = /([^\\[\\]]+)|\\[(.*?)\\]/g;
            let m;
            while ((m = re.exec(key)) !== null) path.push(m[1] !== undefined ? m[1] : m[2]);
            if (path.length) setPath(out, path, val);
          });
          return out;
        }
        const opts = {};
        merge(opts, parseQuery(location.search));
        const fresh = {};
        const theme = fresh.theme; // undefined unless Object.prototype was polluted
        if (theme !== undefined) {
          document.getElementById('themeOut').textContent = theme;
          document.getElementById('themeBox').style.background = theme;
          // The page itself reports the demonstrated pollution to claim the flag.
          location.href = '/proto/client/claim?theme=' + encodeURIComponent(theme);
        }
      </script>
    `, { crumb: 'Theme picker', nav: ['Home', 'Themes', 'Share'] })}
  `));
});

// GET /proto/client/claim -> the page redirects here after demonstrating the
// pollution in the browser. The claim only counts when a real polluted value
// arrives from the page.
router.get('/client/claim', (req, res) => {
  const theme = (req.query.theme || '').toString().slice(0, 40);
  if (theme && theme !== 'light') {
    const flag = award(req, 'proto', 'proto-client');
    return res.send(page('Theme claimed · Palette', `
      ${appShell('Palette', `
        <h2>Pollution demonstrated</h2>
        <p>The page rendered theme <code>${esc(theme)}</code> read from a fresh
        <code>{}</code> in the browser: client-side <code>Object.prototype</code>
        pollution confirmed.</p>
        ${flagBox(flag)}
        ${fixPanel('proto', 'proto-client')}
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/proto">Back to the module</a></p>
      `, { crumb: 'Theme claimed', nav: ['Home', 'Themes', 'Share'] })}
    `));
  }
  res.status(400).send(page('No pollution · Palette', `
    ${appShell('Palette', `
      <h2>No flag</h2>
      <p>This endpoint only awards a flag when the client page reports a genuinely
      polluted theme value. Load <code>/proto/client?__proto__[theme]=dark</code>
      in a browser so the page can demonstrate the pollution.</p>
    `, { crumb: 'No pollution', nav: ['Home', 'Themes', 'Share'] })}
  `));
});

module.exports = { vuln, router };
