// PenTrix VulnLab module: Client-Side Template Injection (csti)
// The server stores templates; the browser evaluates them with a deliberately
// naive {{ expression }} interpolator built on Function. Five labs: basic
// evaluation, a blacklist bypass via an alternative delimiter, reaching
// Function through the exposed constructor, CSTI inside an HTML attribute,
// and a stored template evaluated on every view. Local lab use only.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

const VULN_IDS = ['basic', 'filter-bypass', 'constructor', 'attr', 'stored'];

const db = getDb();
db.exec('CREATE TABLE IF NOT EXISTS csti_profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)');
if (db.prepare('SELECT COUNT(*) AS c FROM csti_profiles').get().c === 0) {
  db.prepare('INSERT INTO csti_profiles (name) VALUES (?)').run('alice');
}

// The naive client-side template engine, served to every lab page.
// It is intentionally the vulnerability: expressions become live JavaScript.
const RENDER_JS = `
var CSTI_CTX = { constructor: Object }; // VULN: exposing constructor hands out Function
function cstiRender(tpl) {
  function ev(m, expr) {
    try {
      // VULN: {{ expression }} is compiled and executed with Function.
      return Function('ctx', 'with(ctx){ return (' + expr + '); }')(CSTI_CTX);
    } catch (err) { return '[ERR]'; }
  }
  var s = String(tpl).replace(/\\{\\{([\\s\\S]*?)\\}\\}/g, ev);
  // VULN: a second delimiter syntax, [[ expression ]], is evaluated too.
  s = s.replace(/\\[\\[([\\s\\S]*?)\\]\\]/g, ev);
  return s;
}`;

// ---------------------------------------------------------------------------
// Flag capture beacon. The victim page's own JavaScript fires it once the
// template actually evaluated (labs 1, 2, 4, 5 auto-beacon when the rendered
// output contains the attacker's expected result; lab 3's payload beacons
// manually after achieving code execution).
// ---------------------------------------------------------------------------
router.get('/beacon', (req, res) => {
  const v = String(req.query.v || '');
  const d = String(req.query.d || '');
  let ok = false;
  if (VULN_IDS.includes(v)) {
    ok = (v === 'constructor') ? d.length > 0 : d === '49';
  }
  if (ok) {
    const flag = award(req, 'csti', v);
    return res.send(page('Template executed', `
      <h2>Template executed</h2>
      <p>The client-side template engine evaluated attacker input for vuln
      <b>${esc(v)}</b>.</p>
      ${flagBox(flag)}
      <p><a href="/csti">Back to the CSTI module</a></p>
    `));
  }
  res.status(400).send(page('Beacon', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when the template engine really evaluated
    your expression (<code>v</code> = basic, filter-bypass, constructor, attr, or stored,
    with the expected result data). Work through the lab page in your browser.</p>
    <p><a href="/csti">Back to the CSTI module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// Lab 1: basic {{7*7}} evaluation
// ---------------------------------------------------------------------------
const DEFAULT_BASIC = "Hello {{'gues'+'t'}}!";

router.get('/basic', (req, res) => {
  const tpl = req.session.csti_basic || DEFAULT_BASIC;
  res.send(page('Basic CSTI', `
    <h2>Greeting card (basic)</h2>
    <p>Your greeting is stored on the server and rendered by the browser's template engine.</p>
    <form method="POST" action="/csti/basic">
      <textarea name="tpl" rows="3" cols="60">${esc(tpl)}</textarea><br /><br />
      <button type="submit">Save greeting</button>
    </form>
    <hr />
    <h3>Preview</h3>
    <div id="out" style="border:1px dashed #888; padding:1em; min-height:2em;"></div>
    <script>
      ${RENDER_JS}
      var TPL = ${JSON.stringify(tpl)};
      var html = cstiRender(TPL);
      // VULN: rendered template output is injected as HTML.
      document.getElementById('out').innerHTML = html;
      if (html.indexOf('49') !== -1) {
        fetch('/csti/beacon?v=basic&d=' + encodeURIComponent('49'));
      }
    </script>
    <p class="note">Goal: make the preview show <b>49</b>. The engine evaluates
    <code>{{ expression }}</code> as JavaScript.</p>
  `));
});

router.post('/basic', (req, res) => {
  req.session.csti_basic = String(req.body.tpl || '').slice(0, 2000) || DEFAULT_BASIC;
  res.redirect('/csti/basic');
});

// ---------------------------------------------------------------------------
// Lab 2: {{ }} blocked server-side, [[ ]] still evaluates
// ---------------------------------------------------------------------------
const DEFAULT_FB = "[[ 'hel' + 'lo' ]]";

router.get('/filter-bypass', (req, res) => {
  const tpl = req.session.csti_fb || DEFAULT_FB;
  res.send(page('Filtered CSTI', `
    <h2>Greeting card (filtered)</h2>
    <p class="note">Server-side filter: templates containing <code>{{</code> or
    <code>}}</code> are rejected. Surely that stops template injection...</p>
    <form method="POST" action="/csti/filter-bypass">
      <textarea name="tpl" rows="3" cols="60">${esc(tpl)}</textarea><br /><br />
      <button type="submit">Save greeting</button>
    </form>
    <hr />
    <h3>Preview</h3>
    <div id="out" style="border:1px dashed #888; padding:1em; min-height:2em;"></div>
    <script>
      ${RENDER_JS}
      var TPL = ${JSON.stringify(tpl)};
      var html = cstiRender(TPL);
      document.getElementById('out').innerHTML = html;
      if (html.indexOf('49') !== -1) {
        fetch('/csti/beacon?v=filter-bypass&d=' + encodeURIComponent('49'));
      }
    </script>
    <p class="note">Goal: make the preview show <b>49</b> without using
    <code>{{</code> or <code>}}</code>. The client engine knows more than one syntax.</p>
  `));
});

router.post('/filter-bypass', (req, res) => {
  const tpl = String(req.body.tpl || '').slice(0, 2000);
  // VULN: naive blacklist. It blocks {{ }} at the door, but the client-side
  // engine also evaluates the [[ ]] delimiter, which the filter never heard of.
  if (tpl.includes('{{') || tpl.includes('}}')) {
    return res.status(400).send(page('Blocked', `
      <h2>Blocked by the filter</h2>
      <p>Templates containing <code>{{</code> or <code>}}</code> are not allowed.</p>
      <p><a href="/csti/filter-bypass">Back</a></p>
    `));
  }
  req.session.csti_fb = tpl || DEFAULT_FB;
  res.redirect('/csti/filter-bypass');
});

// ---------------------------------------------------------------------------
// Lab 3: constructor.constructor reaches Function for code execution
// ---------------------------------------------------------------------------
const DEFAULT_CTOR = '2 + 2 = {{2+2}}';

router.get('/constructor', (req, res) => {
  const tpl = req.session.csti_ctor || DEFAULT_CTOR;
  res.send(page('Constructor breakout', `
    <h2>Math card (constructor breakout)</h2>
    <p>Same template engine, but this time the goal is real code execution, not just math.</p>
    <form method="POST" action="/csti/constructor">
      <textarea name="tpl" rows="3" cols="60">${esc(tpl)}</textarea><br /><br />
      <button type="submit">Save template</button>
    </form>
    <hr />
    <h3>Preview</h3>
    <div id="out" style="border:1px dashed #888; padding:1em; min-height:2em;"></div>
    <script>
      ${RENDER_JS}
      var TPL = ${JSON.stringify(tpl)};
      document.getElementById('out').innerHTML = cstiRender(TPL);
    </script>
    <p class="note">Goal: execute JavaScript through the template. The engine exposes
    <code>constructor</code> (which is <code>Object</code>) to every expression, and
    <code>Object.constructor</code> is <code>Function</code>. From there you can compile
    and run any string as code, then beacon the flag yourself.</p>
  `));
});

router.post('/constructor', (req, res) => {
  req.session.csti_ctor = String(req.body.tpl || '').slice(0, 2000) || DEFAULT_CTOR;
  res.redirect('/csti/constructor');
});

// ---------------------------------------------------------------------------
// Lab 4: CSTI inside an HTML attribute context
// ---------------------------------------------------------------------------
const DEFAULT_ATTR = '{{1+1}}';

function escAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

router.get('/attr', (req, res) => {
  const tpl = req.session.csti_attr || DEFAULT_ATTR;
  res.send(page('Attribute CSTI', `
    <h2>Profile badge (attribute context)</h2>
    <p>Your badge text is placed inside an HTML attribute, entity-encoded by the server.
    Surely encoding <code>&quot;</code> stops injection...</p>
    <form method="POST" action="/csti/attr">
      <textarea name="tpl" rows="3" cols="60">${esc(tpl)}</textarea><br /><br />
      <button type="submit">Save badge text</button>
    </form>
    <hr />
    <h3>Badge</h3>
    <input id="badge" type="text" size="60" value="${escAttr(tpl)}" readonly />
    <p id="msg"></p>
    <script>
      ${RENDER_JS}
      // VULN: getAttribute() decodes the entities back, and then the raw
      // template is evaluated client-side. Server-side encoding cannot stop
      // client-side evaluation.
      var raw = document.getElementById('badge').getAttribute('value');
      var html = cstiRender(raw);
      document.getElementById('badge').value = html;
      document.getElementById('msg').textContent = 'Evaluated inside the value attribute: ' + html;
      if (html.indexOf('49') !== -1) {
        fetch('/csti/beacon?v=attr&d=' + encodeURIComponent('49'));
      }
    </script>
    <p class="note">Goal: make the badge show <b>49</b>. View source: your payload sits
    entity-encoded in the attribute, yet it still evaluates. Double quotes in payloads are
    fine; the browser decodes them back before the engine runs.</p>
  `));
});

router.post('/attr', (req, res) => {
  req.session.csti_attr = String(req.body.tpl || '').slice(0, 2000) || DEFAULT_ATTR;
  res.redirect('/csti/attr');
});

// ---------------------------------------------------------------------------
// Lab 5: stored profile name evaluated as a template on every view
// ---------------------------------------------------------------------------
router.get('/stored', (req, res) => {
  const names = db.prepare('SELECT name FROM csti_profiles ORDER BY id').all().map((r) => r.name);
  res.send(page('Stored CSTI', `
    <h2>Member profiles (stored)</h2>
    <p>Set your display name. It is stored on the server and every visitor's browser
    evaluates it as a template when the list renders.</p>
    <form method="POST" action="/csti/stored/profile">
      <input type="text" name="name" placeholder="display name" maxlength="200" required size="40" />
      <button type="submit">Save profile</button>
    </form>
    <hr />
    <h3>Members</h3>
    <div id="profiles"></div>
    <script>
      ${RENDER_JS}
      var NAMES = ${JSON.stringify(names)};
      var box = document.getElementById('profiles');
      var hit = false;
      NAMES.forEach(function (n) {
        // VULN: every stored display name is evaluated as a template on view.
        var html = cstiRender(n);
        var div = document.createElement('div');
        div.className = 'comment';
        div.innerHTML = '<b>Member:</b> ' + html;
        box.appendChild(div);
        if (html.indexOf('49') !== -1) hit = true;
      });
      if (hit) {
        fetch('/csti/beacon?v=stored&d=' + encodeURIComponent('49'));
      }
    </script>
    <p class="note">Goal: store a display name that renders as <b>49</b> for everyone
    who views this page.</p>
  `));
});

router.post('/stored/profile', (req, res) => {
  const name = String(req.body.name || '').slice(0, 200).trim();
  if (!name) {
    return res.status(400).send(page('Profiles', '<p>A display name is required.</p><p><a href="/csti/stored">Back</a></p>'));
  }
  db.prepare('INSERT INTO csti_profiles (name) VALUES (?)').run(name);
  res.redirect('/csti/stored');
});

// ---------------------------------------------------------------------------
// Module index
// ---------------------------------------------------------------------------
const PATHS = {
  'basic': 'basic',
  'filter-bypass': 'filter-bypass',
  'constructor': 'constructor',
  'attr': 'attr',
  'stored': 'stored',
};

router.get('/', (req, res) => {
  const rows = module.exports.vulns.map((v) => {
    const done = captured(req, 'csti', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/csti/${PATHS[v.id]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
      </div>`;
  }).join('\n');

  res.send(page('Client-Side Template Injection', `
    ${brief('Module briefing', `
      <p><b>CSTI in 30 seconds:</b> some apps let the <i>browser</i> evaluate templates with a
      JavaScript engine instead of rendering them on the server. If that engine runs user input
      through <code>Function</code> (or <code>eval</code>), every <code>{{ expression }}</code>
      is live JavaScript in the victim's browser.</p>
      <p><b>The engine in this module</b> (view source on any lab page) replaces
      <code>{{ ... }}</code> and <code>[[ ... ]]</code> by compiling the inside with
      <code>Function</code> and exposing <code>constructor</code> (which is <code>Object</code>)
      to every expression. The server only <i>stores</i> your template; the browser does the
      evaluating. Each lab page beacons <code>/csti/beacon</code> once your expression really
      evaluates.</p>`)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

module.exports = {
  id: 'csti',
  name: 'Client-Side Template Injection',
  tagline: 'Your template engine runs whatever the user types.',
  description: 'A deliberately naive client-side {{ expression }} interpolator built on Function. Five labs: basic evaluation, a blacklist bypass through an alternative delimiter, breaking out to code execution via constructor.constructor, CSTI inside an HTML attribute, and a stored template evaluated on every view.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'basic',
      name: 'Basic Template Evaluation',
      difficulty: 'Easy',
      hint: 'The preview renders {{ expression }} as live JavaScript. What expression evaluates to 49?',
      how: 'Save a greeting containing {{7*7}} and watch the preview render 49.',
    },
    {
      id: 'filter-bypass',
      name: 'Filter Bypass via Alternative Delimiter',
      difficulty: 'Medium',
      hint: 'The server rejects {{ and }}. But the client engine understands a second delimiter syntax, which the filter never heard of.',
      how: 'Use the [[ expression ]] syntax to evaluate 7*7 without touching {{ }}.',
    },
    {
      id: 'constructor',
      name: 'Constructor Breakout to Code Execution',
      difficulty: 'Medium',
      hint: 'Expressions can see constructor (which is Object), and Object.constructor is Function. Compile a string that beacons the flag.',
      how: 'Submit {{constructor.constructor("fetch(...)")()}} with a fetch to /csti/beacon?v=constructor.',
    },
    {
      id: 'attr',
      name: 'CSTI Inside an HTML Attribute',
      difficulty: 'Medium',
      hint: 'The server entity-encodes your text into the value attribute, but the browser decodes it with getAttribute before the engine evaluates it. Encoding does not stop client-side evaluation.',
      how: 'Save {{7*7}} as the badge text; the attribute decodes and the engine renders 49.',
    },
    {
      id: 'stored',
      name: 'Stored Template in Profile Name',
      difficulty: 'Easy',
      hint: 'Display names are stored and every view evaluates them as templates. Your payload persists and fires for every visitor.',
      how: 'Save {{7*7}} as your display name and reload the member list.',
    },
  ],
  router,
};
