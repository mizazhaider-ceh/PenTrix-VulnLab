// PenTrix VulnLab module: Prototype Pollution (proto)
// A naive recursive merge() is used to fold attacker input (query strings,
// JSON bodies) into config objects. Every challenge abuses a different way
// to smuggle __proto__ / constructor / prototype past the merge.
const express = require('express');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
// Router-scoped form parsing only (app-level middleware is out of scope).
router.use(express.urlencoded({ extended: false }));
router.use(express.json());
// text/plain bodies are needed for the unicode lab: the app-level json parser
// would already have decoded \uXXXX escapes, destroying the raw evidence.
router.use(express.text({ type: 'text/plain' }));

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

const BRIEF_HTML = `
<p><b>What is prototype pollution?</b> Every JavaScript object inherits from
<code>Object.prototype</code>. A recursive <i>merge</i> that copies attacker
keys without filtering lets an attacker write to <code>__proto__</code>,
<code>constructor.prototype</code>, and friends, silently changing the
behaviour of <b>every object</b> in the process.</p>
<p><b>The pattern in this module:</b> each challenge merges your input into an
object with the naive <code>merge()</code> above. Your job is to smuggle a
magic key through, pollute <code>Object.prototype</code>, and then make a
"fresh" <code>{}</code> fail (or pass) a check it should never pass.</p>
<p>Each challenge page links its own admin check. Pollute first, then open the check.</p>`;

// ---------------------------------------------------------------- index page
router.get('/', (req, res) => {
  const vulns = module.exports.vulns;
  const rows = vulns.map((v) => {
    const done = captured(req, 'proto', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="${v.path}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');
  res.send(page('Prototype Pollution', `
    ${brief('Module briefing', BRIEF_HTML)}
    <h2>Challenges</h2>
    ${rows}
    <p class="note">Tip: pollution is process-wide once it lands. If a check
    passes "for free", restart the lab server for a clean slate.</p>
  `));
});

// ------------------------------------------------- v1: query-string pollution
router.get('/query', (req, res) => {
  const data = parseNested(rawQuery(req));
  // VULN: every query parameter is deep-merged into the global config object.
  merge(config, data);
  res.send(page('Query-String Pollution', `
    <h2>Merge query parameters into the app config</h2>
    <p>This endpoint runs your raw query string through a nested parser
    (<code>a[b]=c</code> becomes nested objects) and deep-merges the result
    into the application's global config. The merge trusts every key.</p>
    <p><b>Try it:</b>
      <a href="/proto/query?__proto__[role]=admin"><code>?__proto__[role]=admin</code></a>
    </p>
    <form onsubmit="location='/proto/query?'+document.getElementById('qs').value; return false;">
      <input id="qs" size="55" placeholder="__proto__[role]=admin" />
      <button type="submit">Merge</button>
    </form>
    <p>Keys merged this request: <code>${esc(Object.keys(data).join(', ') || '(none)')}</code></p>
    <hr />
    <p>Step 2: open the admin check. It creates a brand-new <code>{}</code> and
    tests <code>user.role === 'admin'</code>.</p>
    <p><a class="btn" href="/proto/query/admin">Open admin check</a></p>
  `));
});

router.get('/query/admin', (req, res) => {
  const user = {}; // fresh object: no role is assigned anywhere in this handler
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-query');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>A fresh <code>{}</code> just passed the <code>role === 'admin'</code>
      check. <code>Object.prototype.role</code> is polluted.</p>
      ${flagBox(flag)}
      <p><a href="/proto">Back to the module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    <h2>Access denied</h2>
    <p>A fresh <code>{}</code> has <code>role = ${esc(String(user.role))}</code>.
    Pollute <code>Object.prototype.role</code> via the merge endpoint, then reload this page.</p>
    <p><a href="/proto/query">Back to the merge endpoint</a></p>
  `));
});

// ------------------------------------------------------ v2: JSON body pollution
router.get('/json', (req, res) => {
  res.send(page('JSON Body Pollution', `
    <h2>Merge a JSON body into the app config</h2>
    <p>This endpoint accepts <code>Content-Type: application/json</code> and
    deep-merges the parsed body into the global config with the same naive
    merge. Remember: <code>JSON.parse</code> happily creates an own property
    literally named <code>__proto__</code>.</p>
    <textarea id="jb" rows="6" cols="60">{"__proto__": {"role": "admin"}}</textarea><br /><br />
    <button onclick="fetch('/proto/json/merge', {method:'POST', headers:{'Content-Type':'application/json'}, body: document.getElementById('jb').value}).then(r => r.text()).then(t => document.getElementById('out').innerHTML = t);">Merge JSON</button>
    <div id="out"></div>
    <hr />
    <p>Or with curl:</p>
    <pre><code>curl -X POST http://localhost:3000/proto/json/merge \\
  -H 'Content-Type: application/json' \\
  -d '{"__proto__": {"role": "admin"}}'</code></pre>
    <p>Step 2: <a class="btn" href="/proto/json/admin">Open admin check</a></p>
  `));
});

router.post('/json/merge', (req, res) => {
  const data = req.body;
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return res.status(400).send('<p>Send a JSON object.</p>');
  }
  // VULN: parsed JSON body is deep-merged with no key filtering.
  merge(config, data);
  res.send(`<p>Merged keys: <code>${esc(Object.keys(data).join(', '))}</code>.
  Now <a href="/proto/json/admin">open the admin check</a>.</p>`);
});

router.get('/json/admin', (req, res) => {
  const user = {};
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-json');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>A fresh <code>{}</code> just passed the <code>role === 'admin'</code>
      check. The JSON body polluted <code>Object.prototype</code>.</p>
      ${flagBox(flag)}
      <p><a href="/proto">Back to the module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    <h2>Access denied</h2>
    <p>A fresh <code>{}</code> has <code>role = ${esc(String(user.role))}</code>.
    POST a polluting JSON body first, then reload.</p>
    <p><a href="/proto/json">Back to the merge endpoint</a></p>
  `));
});

// ------------------------------------ v3: blacklist bypass via constructor
router.get('/constructor', (req, res) => {
  const data = parseNested(rawQuery(req));
  // VULN: the blacklist only drops the literal string "__proto__", but the
  // prototype chain has another entrance: constructor.prototype.
  merge(config, data, (k) => k.includes('__proto__'));
  res.send(page('Blacklist Bypass', `
    <h2>Merge with a blacklist</h2>
    <p>This endpoint learned from the previous one: any key containing the
    literal string <code>__proto__</code> is dropped before merging. Everything
    else is still deep-merged.</p>
    <p>Blocked so far: <code>__proto__</code>. Allowed: everything else, including
    <code>constructor</code> and <code>prototype</code>.</p>
    <p><b>Try it:</b>
      <a href="/proto/constructor?constructor[prototype][role]=admin"><code>?constructor[prototype][role]=admin</code></a>
    </p>
    <form onsubmit="location='/proto/constructor?'+document.getElementById('qs').value; return false;">
      <input id="qs" size="55" placeholder="constructor[prototype][role]=admin" />
      <button type="submit">Merge</button>
    </form>
    <p>Keys merged this request: <code>${esc(Object.keys(data).join(', ') || '(none)')}</code></p>
    <hr />
    <p>Step 2: <a class="btn" href="/proto/constructor/admin">Open admin check</a></p>
  `));
});

router.get('/constructor/admin', (req, res) => {
  const user = {};
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-constructor');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>You reached <code>Object.prototype</code> through
      <code>constructor.prototype</code>, dodging the <code>__proto__</code>
      blacklist. A fresh <code>{}</code> now reads <code>role = 'admin'</code>.</p>
      ${flagBox(flag)}
      <p><a href="/proto">Back to the module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    <h2>Access denied</h2>
    <p>A fresh <code>{}</code> has <code>role = ${esc(String(user.role))}</code>.
    Find a path to <code>Object.prototype</code> that never uses the literal
    string <code>__proto__</code>, then reload.</p>
    <p><a href="/proto/constructor">Back to the merge endpoint</a></p>
  `));
});

// ------------------------------------------------------------ v4: toString DoS
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
      <h2>The widget broke</h2>
      <p>The dashboard tried to render the widget and crashed:</p>
      <p><code>${esc(e.message)}</code></p>
      <p>You polluted <code>toString</code> on the widget's prototype scope, so
      string coercion exploded. Denial of service demonstrated.</p>
      ${flagBox(flag)}
      <p><a href="/proto/dos">Reload a fresh widget</a></p>
    `));
  }
  res.send(page('Widget status', `
    <h2>Dashboard widget</h2>
    <p>This page merges your query string into a widget object, then renders it
    with string coercion (<code>\`\${widget}\`</code>). The widget's prototype
    is a fresh object created per request, so your pollution cannot escape this page.</p>
    <p><b>Try it:</b>
      <a href="/proto/dos?__proto__[toString]=boom"><code>?__proto__[toString]=boom</code></a>
    </p>
    <form onsubmit="location='/proto/dos?'+document.getElementById('qs').value; return false;">
      <input id="qs" size="55" placeholder="__proto__[toString]=boom" />
      <button type="submit">Merge</button>
    </form>
    <p>Widget renders as: <code>${esc(shown)}</code></p>
    <p class="note">What happens if <code>toString</code> stops being a function?</p>
  `));
});

// ------------------------------------------------- v5: client-side pollution
router.get('/client', (req, res) => {
  res.send(page('Client-Side Pollution', `
    <h2>Theme picker (client-side merge)</h2>
    <p>This page parses <b>your browser's</b> query string into nested objects
    and merges them into an options object with a naive recursive merge, all
    in JavaScript. It then reads the theme from a <i>fresh</i> object. If the
    merge polluted <code>Object.prototype</code> in your browser, the fresh
    object inherits your theme.</p>
    <p><b>Try it:</b>
      <a href="/proto/client?__proto__[theme]=dark"><code>?__proto__[theme]=dark</code></a>
      (any CSS color works, e.g. <code>tomato</code>, <code>#00ffcc</code>)
    </p>
    <div id="themeBox" style="border:2px solid #888; padding:1.5em; margin:1em 0;">
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
  `));
});

router.get('/client/claim', (req, res) => {
  const theme = (req.query.theme || '').toString().slice(0, 40);
  // The claim only counts when a real polluted value arrives from the page.
  if (theme && theme !== 'light') {
    const flag = award(req, 'proto', 'proto-client');
    return res.send(page('Theme claimed', `
      <h2>Pollution demonstrated</h2>
      <p>The page rendered theme <code>${esc(theme)}</code> read from a fresh
      <code>{}</code> in the browser: client-side <code>Object.prototype</code>
      pollution confirmed.</p>
      ${flagBox(flag)}
      <p><a href="/proto">Back to the module</a></p>
    `));
  }
  res.status(400).send(page('No pollution', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when the client page reports a genuinely
    polluted theme value. Load <code>/proto/client?__proto__[theme]=dark</code>
    in a browser so the page can demonstrate the pollution.</p>
  `));
});

// ------------------------------------------- v6: unicode escape blacklist bypass
router.get('/unicode', (req, res) => {
  res.send(page('Unicode Escape Bypass', `
    <h2>Merge with a raw-text blacklist</h2>
    <p>This endpoint is stricter: it scans the <b>raw request text</b> and
    rejects it with 400 if it contains the literal string
    <code>__proto__</code> anywhere. Only then does it
    <code>JSON.parse</code> the body and merge it.</p>
    <p>The catch: JSON string escapes like <code>\\u005f</code> are decoded by
    <code>JSON.parse</code> <i>after</i> the blacklist scan. The raw text never
    contains <code>__proto__</code>, but the parsed object does.</p>
    <p>Send the body as <code>text/plain</code> so the server sees your exact bytes.</p>
    <textarea id="jb" rows="6" cols="70">{"\\u005f\\u005fproto\\u005f\\u005f": {"role": "admin"}}</textarea><br /><br />
    <button onclick="fetch('/proto/unicode/merge', {method:'POST', headers:{'Content-Type':'text/plain'}, body: document.getElementById('jb').value}).then(r => r.text()).then(t => document.getElementById('out').innerHTML = t);">Merge JSON</button>
    <div id="out"></div>
    <hr />
    <p>Or with curl:</p>
    <pre><code>curl -X POST http://localhost:3000/proto/unicode/merge \\
  -H 'Content-Type: text/plain' \\
  -d '{"\\u005f\\u005fproto\\u005f\\u005f": {"role": "admin"}}'</code></pre>
    <p>Step 2: <a class="btn" href="/proto/unicode/admin">Open admin check</a></p>
  `));
});

router.post('/unicode/merge', (req, res) => {
  const raw = req.body;
  if (typeof raw !== 'string') {
    return res.status(400).send('<p>Send the JSON document as text/plain.</p>');
  }
  // VULN: the blacklist inspects the raw text, but JSON.parse decodes \uXXXX
  // escapes afterwards, so the forbidden key materializes post-scan.
  if (raw.includes('__proto__')) {
    return res.status(400).send('<p><b>Blocked:</b> raw request text contains "__proto__".</p><p><a href="/proto/unicode">Back</a></p>');
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    return res.status(400).send(`<p>Invalid JSON: <code>${esc(e.message)}</code></p>`);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return res.status(400).send('<p>Send a JSON object.</p>');
  }
  merge(config, data);
  res.send(`<p>Blacklist passed. Merged keys: <code>${esc(Object.keys(data).join(', '))}</code>.
  Now <a href="/proto/unicode/admin">open the admin check</a>.</p>`);
});

router.get('/unicode/admin', (req, res) => {
  const user = {};
  // VULN: the authorization check reads user.role, which prototype pollution can inject.
  if (user.role === 'admin') {
    const flag = award(req, 'proto', 'proto-unicode-bypass');
    return res.send(page('Admin panel', `
      <h2>Welcome, admin</h2>
      <p>Your <code>\\u005f</code> escapes slipped past the raw-text blacklist
      and <code>JSON.parse</code> rebuilt the forbidden key. A fresh
      <code>{}</code> now reads <code>role = 'admin'</code>.</p>
      ${flagBox(flag)}
      <p><a href="/proto">Back to the module</a></p>
    `));
  }
  res.send(page('Admin panel', `
    <h2>Access denied</h2>
    <p>A fresh <code>{}</code> has <code>role = ${esc(String(user.role))}</code>.
    Smuggle <code>__proto__</code> past the raw-text blacklist, then reload.</p>
    <p><a href="/proto/unicode">Back to the merge endpoint</a></p>
  `));
});

module.exports = {
  id: 'proto',
  name: 'Prototype Pollution',
  tagline: 'Smuggle magic keys through a naive recursive merge and turn Object.prototype into a privilege escalation.',
  description: 'A hand-rolled deep merge folds attacker input into config objects without filtering keys. Pollute Object.prototype through query strings, JSON bodies, constructor.prototype, unicode escapes, and even in the victim browser, then watch fresh objects inherit your values.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'proto-query',
      name: 'Query-String Pollution',
      difficulty: 'Medium',
      hint: 'The merge endpoint folds every query parameter into the app config. What happens when a parameter is named __proto__[role]?',
      how: 'Pollute Object.prototype.role via the query string, then open the admin check.',
      path: '/proto/query',
    },
    {
      id: 'proto-json',
      name: 'JSON Body Pollution',
      difficulty: 'Medium',
      hint: 'The merge endpoint accepts a JSON body. JSON.parse happily creates an own property literally named __proto__.',
      how: 'POST {"__proto__":{"role":"admin"}} to the merge endpoint, then open the admin check.',
      path: '/proto/json',
    },
    {
      id: 'proto-constructor',
      name: 'Blacklist Bypass via constructor',
      difficulty: 'Medium',
      hint: 'Keys containing the literal string __proto__ are dropped. But the prototype chain has more than one entrance.',
      how: 'Reach Object.prototype through constructor/prototype instead, then open the admin check.',
      path: '/proto/constructor',
    },
    {
      id: 'proto-dos',
      name: 'Polluting toString',
      difficulty: 'Easy',
      hint: 'The widget page stringifies an object whose prototype you control. What if toString stopped being a function?',
      how: 'Pollute toString on the widget scope so the render crashes; the crash page awards the flag.',
      path: '/proto/dos',
    },
    {
      id: 'proto-client',
      name: 'Client-Side Pollution',
      difficulty: 'Easy',
      hint: 'All the merging happens in your browser, not on the server. Open the demo link and watch the theme box change color.',
      how: 'Load the page with a __proto__[theme] parameter so it renders the polluted value; the page reports it for the flag.',
      path: '/proto/client',
    },
    {
      id: 'proto-unicode-bypass',
      name: 'Unicode Escape Bypass',
      difficulty: 'Hard',
      hint: 'The blacklist scans the raw JSON text for __proto__. JSON string escapes are decoded after that scan.',
      how: 'Smuggle the key past the blacklist with \\u005f escapes, then open the admin check.',
      path: '/proto/unicode',
    },
  ],
  router,
};
