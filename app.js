const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

const { getDb } = require('./lib/db');
const { page, esc } = require('./lib/page');
const { captured } = require('./lib/flags');

const app = express();
const PORT = process.env.PORT || 3000;

// /upload takes raw file bytes (express.raw in its router); the global form
// parser must not eat them first. curl's --data-binary defaults to
// application/x-www-form-urlencoded, which urlencoded() would consume,
// leaving the upload router with an empty body.
const urlencodedParser = express.urlencoded({ extended: true });
app.use((req, res, next) => {
  if (req.path === '/upload' || req.path.startsWith('/upload/')) return next();
  urlencodedParser(req, res, next);
});
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: 'pentrix-vulnlab-insecure-dev-secret',
  resave: false,
  saveUninitialized: true,
  // VULN (deliberate): cookies readable by JS so XSS cookie-stealing demos work.
  cookie: { httpOnly: false },
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

getDb(); // init + seed

// ---- auto-mount modules: modules/<id>/router.js ----
const modulesDir = path.join(__dirname, 'modules');
const registry = [];
if (fs.existsSync(modulesDir)) {
  for (const dir of fs.readdirSync(modulesDir)) {
    const modPath = path.join(modulesDir, dir, 'router.js');
    if (!fs.existsSync(modPath)) continue;
    try {
      const mod = require(modPath);
      if (!mod.id || !mod.router || !Array.isArray(mod.vulns)) {
        console.warn(`[warn] skipping ${dir}: bad module shape`);
        continue;
      }
      app.use('/' + mod.id, mod.router);
      registry.push(mod);
      console.log(`[ok] mounted /${mod.id} (${mod.vulns.length} vulns)`);
    } catch (e) {
      console.error(`[err] failed to load ${dir}:`, e.message);
    }
  }
}
app.locals.registry = registry;

// ---- home ----
app.get('/', (req, res) => {
  const cards = registry.map((m) => {
    const done = m.vulns.filter((v) => captured(req, m.id, v.id)).length;
    return `<a class="modcard" href="/${m.id}">
      <h3>${esc(m.name)}</h3>
      <p>${esc(m.tagline)}</p>
      <div class="meta"><span class="pill">${esc(m.difficulty)}</span><span class="dim">${done}/${m.vulns.length} flags</span></div>
    </a>`;
  }).join('');
  res.send(page('Home', `
    <section class="hero">
      <h1>🧪 PenTrix VulnLab</h1>
      <p>An intentionally vulnerable web application for learning web security, built by The PenTrix.
      <b>Run locally only.</b> Pick a module, exploit it, capture the flags.</p>
      <p><a class="btn" href="/scoreboard">View scoreboard</a> <a class="btn ghost" href="/about">How to use</a></p>
    </section>
    <section class="grid">${cards || '<p>No modules found. Something went wrong with the build.</p>'}</section>`));
});

// ---- scoreboard ----
app.get('/scoreboard', (req, res) => {
  let total = 0, got = 0;
  const sections = registry.map((m) => {
    const rows = m.vulns.map((v) => {
      total++;
      const hit = captured(req, m.id, v.id);
      if (hit) got++;
      return `<tr><td>${hit ? '✅' : '⬜'}</td><td><b>${esc(v.name)}</b></td><td>${esc(v.difficulty)}</td><td class="dim">${hit ? 'captured' : 'not captured'}</td></tr>`;
    }).join('');
    return `<h3 class="modhead"><a href="/${m.id}">${esc(m.name)}</a></h3>
      <table class="tbl"><tr><th></th><th>Vulnerability</th><th>Difficulty</th><th>Status</th></tr>${rows}</table>`;
  }).join('');
  const pct = total ? Math.round((got / total) * 100) : 0;
  res.send(page('Scoreboard', `<h2>🏆 Scoreboard</h2>
    <p class="dim">${got} / ${total} flags captured</p>
    <div class="progress"><div class="bar" style="width:${pct}%"></div></div>${sections}`));
});

// ---- about / rules ----
app.get('/about', (req, res) => {
  res.send(page('About', `
    <h2>⚠️ Read this first</h2>
    <div class="warn"><p><b>This application is intentionally vulnerable.</b>
    Never deploy it to a public server or expose it to the internet.
    Run it only on your own machine or an isolated lab network.</p></div>
    <h3>How to use</h3>
    <ol>
      <li>Pick a module on the home page.</li>
      <li>Read the briefing: each module tells you what to attack.</li>
      <li>Exploit the vulnerability the way a real attacker would.</li>
      <li>Capture the flag (<code>PENTRIX{...}</code>); progress is tracked on the scoreboard.</li>
      <li>Stuck? Open the hint. Still stuck? Check <code>SOLUTIONS.md</code>.</li>
    </ol>
    <h3>Rules of the lab</h3>
    <ul>
      <li>Attack <b>only</b> this application.</li>
      <li>Flags prove exploitation. Share write-ups, not just flags.</li>
      <li>Every vulnerability is marked in the source with <code>// VULN:</code> comments so you can study the code after solving.</li>
    </ul>`));
});

app.listen(PORT, () => console.log(`[ok] PenTrix VulnLab listening on http://localhost:${PORT}`));
