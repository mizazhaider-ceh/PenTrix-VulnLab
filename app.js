const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

const { getDb, ensureFlags, DB_PATH } = require('./lib/db');
const { page, esc, difficultyPill, progressBar, emptyState, payloadBlock, errorPage,
  fixEditorPage, fixResultHtml, fixBadgePill } = require('./lib/page');
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
// Session secret: set SESSION_SECRET in the environment for any graded or
// shared use. The fallback below is committed and insecure by design (it only
// needs to be unique per browser for a local training lab); never rely on it
// where session integrity matters.
const SESSION_SECRET = process.env.SESSION_SECRET || 'pentrix-vulnlab-insecure-dev-secret';
if (!process.env.SESSION_SECRET) {
  console.warn('[warn] SESSION_SECRET not set, using insecure dev fallback (fine for local labs only)');
}
const { SqliteStore } = require('./lib/session-store');
app.use(session({
  store: new SqliteStore(path.join(path.dirname(DB_PATH), 'sessions.db')),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  // VULN (deliberate): cookies readable by JS so XSS cookie-stealing demos work.
  cookie: { httpOnly: false },
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

getDb(); // init + seed

// ---- auto-mount modules: modules/<id>/index.js (falls back to router.js
// during the challenge-split migration; the fallback is removed once every
// module has an index.js) ----
const modulesDir = path.join(__dirname, 'modules');
// Route prefixes owned by the app shell; modules may not claim them.
const RESERVED_IDS = new Set(['scoreboard', 'about', 'uploads', 'scenarios']);
const seenIds = new Set();
const registry = [];
if (fs.existsSync(modulesDir)) {
  for (const dir of fs.readdirSync(modulesDir)) {
    const indexPath = path.join(modulesDir, dir, 'index.js');
    const legacyPath = path.join(modulesDir, dir, 'router.js');
    const modPath = fs.existsSync(indexPath) ? indexPath : legacyPath;
    if (!fs.existsSync(modPath)) continue;
    let mod;
    try {
      mod = require(modPath);
    } catch (e) {
      console.error(`[err] failed to load ${dir}:`, e.message);
      continue;
    }
    if (!mod.id || !mod.router || !Array.isArray(mod.vulns)) {
      console.warn(`[warn] skipping ${dir}: bad module shape`);
      continue;
    }
    // Fail fast (abort boot) on contract violations that would silently
    // shadow routes or collide with app shell routes.
    if (!/^[a-z0-9]+$/.test(mod.id)) {
      throw new Error(`module "${dir}" has invalid id "${mod.id}": use lowercase alphanumeric only`);
    }
    if (RESERVED_IDS.has(mod.id)) {
      throw new Error(`module "${dir}" claims reserved id "${mod.id}" (reserved: ${[...RESERVED_IDS].join(', ')})`);
    }
    if (seenIds.has(mod.id)) {
      throw new Error(`duplicate module id "${mod.id}" (already mounted from another directory)`);
    }
    seenIds.add(mod.id);
    app.use('/' + mod.id, mod.router);
    registry.push(mod);
    console.log(`[ok] mounted /${mod.id} (${mod.vulns.length} vulns)`);
  }
}
app.locals.registry = registry;

// ---- M12 kill-chain scenarios (defs live in scenarios/; the framework mounts
// below, after the fixmode block, so the wiring order is explicit) ----
const scenariosMod = require('./scenarios/index');

// Seed per-deployment random flags for every registered challenge.
// Flags live only in the SQLite file (gitignored); the source never
// contains a real flag, so reading GitHub reveals nothing.
ensureFlags(registry.flatMap((m) => m.vulns.map((v) => ({ modId: m.id, vulnId: v.id })))
  .concat(scenariosMod.scenarios.map((s) => ({ modId: 'scenario', vulnId: s.id }))));

// ---- shell helpers (M4) ----
const DIFFICULTIES = ['Beginner', 'Easy', 'Intermediate', 'Medium', 'Mixed', 'Hard'];
// Difficulties actually present in the registry, in pedagogical order, so the
// filter never offers a dead-end option.
const presentDiffs = DIFFICULTIES.filter((d) => registry.some((m) => m.difficulty === d));

function moduleProgress(req, m) {
  const done = m.vulns.filter((v) => captured(req, m.id, v.id)).length;
  return { done, total: m.vulns.length };
}

function totals(req) {
  let got = 0, total = 0;
  for (const m of registry) {
    total += m.vulns.length;
    got += moduleProgress(req, m).done;
  }
  return { got, total };
}

function scoreChipHtml(req) {
  const { got, total } = totals(req);
  return `<span class="score-chip" title="Flags captured"><span aria-hidden="true">🚩</span> ${got}/${total}</span>`;
}

// M12: scoreboard section for the kill-chain scenarios. It reuses the
// sb-module card styling (the extra sb-scenarios marker stays for future
// CSS), and rows mirror the module row markup but without data-key, so the
// sb-module test parsing in tests/helpers.js is untouched.
function scenariosSectionHtml(req) {
  const list = scenariosMod.scenarios;
  const done = list.filter((s) => captured(req, 'scenario', s.id)).length;
  const rows = list.map((s) => {
    const hit = captured(req, 'scenario', s.id);
    const st = hit
      ? '<span class="status status-captured"><span class="dot" aria-hidden="true"></span>Captured</span>'
      : '<span class="status status-missing"><span class="dot" aria-hidden="true"></span>Not captured</span>';
    return `<tr><td>${st}</td><td><a href="/scenarios/${esc(s.id)}"><b>${esc(s.name)}</b></a></td><td>${difficultyPill(s.difficulty)}</td></tr>`;
  }).join('');
  return `<section class="sb-module sb-scenarios" aria-label="Kill-chain scenarios">
    <div class="sb-head"><span class="orb" aria-hidden="true">🔗</span>
      <h3><a href="/scenarios">Kill-chain scenarios</a></h3>
      <span class="sb-count">${done}/${list.length}</span></div>
    ${progressBar(done, list.length, 'Kill-chain scenarios progress')}
    <div class="tbl-scroll"><table class="tbl">
      <caption class="sr-only">Kill-chain scenarios: completion status</caption>
      <thead><tr><th scope="col">Status</th><th scope="col">Scenario</th><th scope="col">Difficulty</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </section>`;
}

// Gentlest entry point: first Beginner module, else first Easy, else first.
function startHereModule() {
  return registry.find((m) => m.difficulty === 'Beginner')
    || registry.find((m) => m.difficulty === 'Easy')
    || registry[0];
}

// ---- home ----
app.get('/', (req, res) => {
  const q = String(req.query.q || '').trim();
  const qLower = q.toLowerCase();
  const diff = presentDiffs.includes(String(req.query.difficulty)) ? String(req.query.difficulty) : 'All';
  const filtering = q !== '' || diff !== 'All';

  const cards = registry.map((m, i) => {
    if (diff !== 'All' && m.difficulty !== diff) return '';
    if (qLower && !(m.name + ' ' + m.tagline + ' ' + m.id).toLowerCase().includes(qLower)) return '';
    const { done, total } = moduleProgress(req, m);
    const start = startHereModule();
    const featured = !filtering && start && m.id === start.id;
    const num = String(i + 1).padStart(2, '0');
    return `<a class="clay-card reveal${featured ? ' featured' : ''}" href="/${m.id}"
      data-search="${esc((m.name + ' ' + m.tagline + ' ' + m.id).toLowerCase())}" data-key="${esc(m.difficulty.toLowerCase())}">
      ${featured ? '<span class="badge-new">Start here</span>' : ''}
      <div class="card-top"><span class="orb" aria-hidden="true">${num}</span>${difficultyPill(m.difficulty)}</div>
      <h3>${esc(m.name)}</h3>
      <p class="tagline">${esc(m.tagline)}</p>
      <div class="card-foot">${progressBar(done, total, m.name + ' progress')}</div>
    </a>`;
  }).join('');

  const { got, total } = totals(req);
  const start = startHereModule();
  const starter = got === 0 && start ? `
    <section class="starter" aria-label="Where to start">
      <div class="orb-row"><span class="orb" aria-hidden="true">🧭</span><h2>New to the lab? Start here.</h2></div>
      <p>No flags captured yet. <b>${esc(start.name)}</b> is the gentlest entry point: ${esc(start.tagline)}</p>
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/${start.id}">Begin with ${esc(start.name)}</a></p>
    </section>` : '';

  const diffOptions = ['All', ...presentDiffs].map((d) =>
    `<option value="${esc(d)}"${d === diff ? ' selected' : ''}>${esc(d === 'All' ? 'All difficulties' : d)}</option>`
  ).join('');

  res.send(page('Home', `
    <section class="hero reveal">
      <h1>PenTrix VulnLab</h1>
      <p class="lead">An intentionally vulnerable web application for learning web security, built by The PenTrix.
      <b>Run locally only.</b> Pick a module, exploit it, capture the flags.</p>
      <div class="cta-row">
        <a class="clay-btn clay-btn-primary" href="/scoreboard">View scoreboard</a>
        <a class="clay-btn clay-btn-secondary" href="/about">How to use</a>
      </div>
      <div class="stats" aria-label="Lab statistics">
        <div class="stat"><b>${registry.length}</b><span>modules</span></div>
        <div class="stat"><b>${total}</b><span>challenges</span></div>
        <div class="stat"><b>${got}</b><span>flags captured</span></div>
      </div>
    </section>
    ${starter}
    <form class="filterbar" id="home-filter" method="get" action="/" role="search" aria-label="Filter modules">
      <div class="clay-field">
        <label for="hq">Search modules</label>
        <input class="clay-input" type="search" id="hq" name="q" value="${esc(q)}" placeholder="e.g. injection, xss, crypto" autocomplete="off">
      </div>
      <div class="clay-field">
        <label for="hdiff">Difficulty</label>
        <select class="clay-select" id="hdiff" name="difficulty">${diffOptions}</select>
      </div>
      <div class="actions">
        <button class="clay-btn clay-btn-primary clay-btn-sm" type="submit">Filter</button>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/">Reset</a>
      </div>
    </form>
    <p class="dim" data-home-empty hidden>No modules match your filter. Try clearing the search.</p>
    <section class="grid" aria-label="Modules">${cards || emptyState('No modules found', '<p>Something went wrong with the build: no modules loaded.</p>', '')}</section>`,
    'home', { scoreChip: scoreChipHtml(req) }));
});

// ---- scoreboard ----
app.get('/scoreboard', (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const status = String(req.query.status || 'all').toLowerCase();
  const statusOk = ['all', 'captured', 'missing'].includes(status) ? status : 'all';

  let total = 0, got = 0;
  const sections = registry.map((m, i) => {
    const num = String(i + 1).padStart(2, '0');
    const rows = m.vulns.map((v) => {
      total++;
      const hit = captured(req, m.id, v.id);
      if (hit) got++;
      if (statusOk === 'captured' && !hit) return '';
      if (statusOk === 'missing' && hit) return '';
      if (q && !(v.name + ' ' + m.name).toLowerCase().includes(q)) return '';
      const st = hit
        ? '<span class="status status-captured"><span class="dot" aria-hidden="true"></span>Captured</span>'
        : '<span class="status status-missing"><span class="dot" aria-hidden="true"></span>Not captured</span>';
      return `<tr data-search="${esc((v.name + ' ' + m.name).toLowerCase())}" data-key="${hit ? 'captured' : 'missing'}">
        <td>${st}</td><td><b>${esc(v.name)}</b></td><td>${difficultyPill(v.difficulty)}</td></tr>`;
    }).join('');
    if (!rows) return '';
    const { done, total: modTotal } = moduleProgress(req, m);
    const capId = `sb-cap-${m.id}`;
    return `<section class="sb-module" aria-labelledby="${capId}">
      <div class="sb-head"><span class="orb" aria-hidden="true">${num}</span>
        <h3 id="${capId}"><a href="/${m.id}">${esc(m.name)}</a></h3>
        <span class="sb-count">${done}/${modTotal}</span></div>
      ${progressBar(done, modTotal, m.name + ' progress')}
      <div class="tbl-scroll"><table class="tbl">
        <caption class="sr-only">${esc(m.name)}: challenge status</caption>
        <thead><tr><th scope="col">Status</th><th scope="col">Challenge</th><th scope="col">Difficulty</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </section>`;
  }).join('');

  const pct = total ? Math.round((got / total) * 100) : 0;
  const start = startHereModule();
  const starterPanel = got === 0 && start ? `
    <section class="starter" aria-label="Getting started">
      <div class="orb-row"><span class="orb" aria-hidden="true">🏁</span><h2>No flags captured yet</h2></div>
      <p>Every expert starts with one flag. <b>${esc(start.name)}</b> is the gentlest entry point: ${esc(start.tagline)}</p>
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/${start.id}">Start with ${esc(start.name)}</a></p>
    </section>` : '';

  const statusOptions = [['all', 'All'], ['captured', 'Captured'], ['missing', 'Not captured']].map(([v, l]) =>
    `<option value="${v}"${v === statusOk ? ' selected' : ''}>${l}</option>`
  ).join('');

  res.send(page('Scoreboard', `
    <h1>Scoreboard</h1>
    <section class="card" aria-label="Overall progress">
      <div class="progress-meta" style="font-size:1rem">
        <div class="clay-progress" role="progressbar" aria-valuenow="${got}" aria-valuemin="0" aria-valuemax="${total}" aria-label="Total flags captured" style="height:18px"><div class="fill" style="width:${pct}%"></div></div>
        <span><b>${got} / ${total}</b> flags · ${pct}% ${fixBadgePill(fixBadgeCountSafe(req))}</span>
      </div>
    </section>
    ${starterPanel}
    <form class="filterbar" id="sb-filter" method="get" action="/scoreboard" role="search" aria-label="Filter challenges">
      <div class="clay-field">
        <label for="sq">Search challenges</label>
        <input class="clay-input" type="search" id="sq" name="q" value="${esc(String(req.query.q || ''))}" placeholder="e.g. login bypass" autocomplete="off">
      </div>
      <div class="clay-field">
        <label for="sstatus">Status</label>
        <select class="clay-select" id="sstatus" name="status">${statusOptions}</select>
      </div>
      <div class="actions">
        <button class="clay-btn clay-btn-primary clay-btn-sm" type="submit">Filter</button>
        <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/scoreboard">Reset</a>
      </div>
    </form>
    <p class="dim" data-sb-empty hidden>No challenges match your filter. Try clearing the search.</p>
    ${sections || emptyState('Nothing matches', '<p>No challenges match the current filter.</p>', '<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/scoreboard">Clear filter</a></p>')}
    ${scenariosSectionHtml(req)}`,
    'scoreboard', { scoreChip: scoreChipHtml(req) }));
});

// ---- about / rules ----
app.get('/about', (req, res) => {
  res.send(page('About', `
    <h1>About this lab</h1>
    <div class="warn" role="note" aria-label="Safety warning">
      <p class="warn-title"><span class="dot" aria-hidden="true"></span>Read this first: run locally only</p>
      <p><b>This application is intentionally vulnerable.</b>
      Never deploy it to a public server or expose it to the internet.
      Run it only on your own machine or an isolated lab network.</p>
    </div>
    <section class="block">
      <h2>How to use</h2>
      <ol>
        <li>Pick a module on the home page. New here? The <b>Start here</b> card is the gentlest entry point.</li>
        <li>Read the briefing: each module tells you what to attack.</li>
        <li>Exploit the vulnerability the way a real attacker would.</li>
        <li>Capture the flag; progress is tracked on the scoreboard.</li>
        <li>Stuck? Open the hint. Still stuck? Check <code>SOLUTIONS.md</code>.</li>
      </ol>
      ${payloadBlock('Flag format', 'PENTRIX{<32 hex characters>}')}
    </section>
    <section class="block">
      <h2>Rules of the lab</h2>
      <ul>
        <li>Attack <b>only</b> this application.</li>
        <li>Flags prove exploitation. Share write-ups, not just flags.</li>
        <li>Every vulnerability is marked in the source with <code>// VULN:</code> comments so you can study the code after solving.</li>
      </ul>
    </section>`,
    'about', { scoreChip: scoreChipHtml(req) }));
});

// ---- M11 break-then-fix mode (additive: guarded requires, no change to boot when files are absent) ----
let fixmode = null;
let fixbadges = null;
try { fixmode = require('./lib/fixmode'); } catch (e) { console.warn('[warn] fix mode unavailable: lib/fixmode.js could not load'); }
try { fixbadges = require('./lib/fixbadges'); } catch (e) { console.warn('[warn] fix badges unavailable: lib/fixbadges.js could not load'); }

// ---- M12 kill-chain scenarios wiring (mounted after the fixmode block) ----
app.use('/scenarios', scenariosMod.router);
scenariosMod.setScenariosRegistry(registry);

// Resolve a /fix URL to a registered module + challenge, or null.
function findFixChallenge(module, vulnId) {
  const m = registry.find((mm) => mm.id === module);
  if (!m) return null;
  const v = m.vulns.find((vv) => vv.id === vulnId);
  if (!v) return null;
  return { m, v };
}

function fixNotFound(req, res) {
  res.status(404).send(page('Not found',
    errorPage(404, 'No such challenge',
      '<p>Fix mode could not find that module or challenge. Check the address bar for typos.</p>'),
    null, { scoreChip: scoreChipHtml(req) }));
}

// How many fix badges the current user earned (safe to call on every request).
function fixBadgeCountSafe(req) {
  try {
    return fixbadges && typeof fixbadges.fixBadgeCount === 'function' ? fixbadges.fixBadgeCount(req) : 0;
  } catch (e) {
    return 0;
  }
}

function fixBlockFor(module, vulnId) {
  try {
    return fixmode && typeof fixmode.getFixBlock === 'function' ? fixmode.getFixBlock(module, vulnId) : null;
  } catch (e) {
    return null;
  }
}

// ---- fix editor ----
app.get('/fix/:module/:vuln', (req, res) => {
  const module = String(req.params.module || '');
  const vuln = String(req.params.vuln || '');
  if (!findFixChallenge(module, vuln)) return fixNotFound(req, res);
  const block = fixBlockFor(module, vuln);
  if (block) return res.send(fixEditorPage(block));
  res.send(page('Fix mode · coming soon',
    `<h1>Fix mode</h1>
    <div class="clay-card"><div class="card-top"><span class="orb" aria-hidden="true">🛠</span></div>
      <h2>Fix mode is coming soon for this challenge</h2>
      <p class="tagline">Break it first, then come back to fix it. The repair editor is not ready for this one yet.</p>
      <div class="card-foot"><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/${esc(module)}">Back to the module</a></div>
    </div>`,
    'fix', { scoreChip: scoreChipHtml(req) }));
});

// ---- fix test ----
app.post('/fix/:module/:vuln/test', (req, res) => {
  const module = String(req.params.module || '');
  const vuln = String(req.params.vuln || '');
  if (!findFixChallenge(module, vuln)) return fixNotFound(req, res);
  let code = '';
  try {
    if (req.body && typeof req.body.code === 'string') code = req.body.code;
  } catch (e) { code = ''; }
  let result;
  try {
    result = fixmode && typeof fixmode.testFix === 'function'
      ? fixmode.testFix(module, vuln, code)
      : { ok: false, error: 'Fix mode is not available right now. Try again later.' };
  } catch (err) {
    console.error('[err] fix test crashed:', err && err.message ? err.message : err);
    result = { ok: false, error: 'The fix check hit an unexpected error. Simplify your code and try again.' };
  }
  if (result && result.ok && fixbadges && typeof fixbadges.awardFixBadge === 'function') {
    try { fixbadges.awardFixBadge(req, module, vuln); }
    catch (err) { console.error('[err] fix badge award failed:', err && err.message ? err.message : err); }
  }
  const block = fixBlockFor(module, vuln);
  const title = (block && block.title) ? String(block.title) : vuln;
  const vulnerableCode = (block && typeof block.vulnerableCode === 'string') ? block.vulnerableCode : '';
  res.send(page('Fix result · ' + title,
    `<div class="clay-card fix-editor">
      <p class="eyebrow"><span class="orb" aria-hidden="true">🛠</span>Fix mode</p>
      <h1>${esc(title)}</h1>
      ${fixResultHtml(result)}
      <h2>Your fix</h2>
      <form method="post" action="/fix/${esc(module)}/${esc(vuln)}/test" id="fix-form">
        <label class="fix-label" for="fix-code">Adjust the code below, then press "Test my fix".</label>
        <textarea id="fix-code" name="code" class="fix-code" style="font-family:var(--font-mono)" spellcheck="false" rows="20">${esc(code)}</textarea>
        <div class="fix-actions"><button type="submit" class="clay-btn clay-btn-primary">Test my fix</button></div>
      </form>
      ${vulnerableCode ? `<h2>The vulnerable code</h2>${payloadBlock('Vulnerable code (read only)', vulnerableCode)}` : ''}
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/fix/${esc(module)}/${esc(vuln)}">Start over</a>
      <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/scoreboard">Scoreboard</a></p>
    </div>`,
    'fix', { scoreChip: scoreChipHtml(req) }));
});

// ---- 404 and 500, rendered inside the page template ----
app.use((req, res) => {
  res.status(404).send(page('Not found',
    errorPage(404, 'Lost in the lab?',
      '<p>That page does not exist. It may have been a mistyped URL, or a module that never shipped.</p><p class="dim">Tip: the lab runs locally, so check the address bar for typos first.</p>'),
    null, { scoreChip: scoreChipHtml(req) }));
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[err]', err && err.stack ? err.stack : err);
  res.status(500).send(page('Error',
    errorPage(500, 'Something broke',
      '<p>The lab hit an unexpected error. Your progress is safe; try going back and continuing.</p><p class="dim">If this keeps happening, restart the lab and check the terminal for the error log.</p>'),
    null, { scoreChip: scoreChipHtml(req) }));
});

// Exported so the test suite can boot the app on an ephemeral port.
if (require.main === module) {
  app.listen(PORT, () => console.log(`[ok] PenTrix VulnLab listening on http://localhost:${PORT}`));
}
module.exports = app;
