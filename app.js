// Process guards first: no require below may throw or reject before the
// guards are installed, and the async-handler patch must land before any
// router is created (app verb methods are copied onto the app at creation).
require('./lib/process-guards').installProcessGuards();
require('./lib/async-handler').patchExpress();

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { getDb, ensureFlags, DB_PATH } = require('./lib/db');
const { page, esc, difficultyPill, progressBar, emptyState, payloadBlock, errorPage,
  fixEditorPage, fixResultHtml, fixBadgePill, trackOf, trackIndex } = require('./lib/page');
const { captured } = require('./lib/flags');
const rctx = require('./lib/request-context');

const app = express();
const PORT = process.env.PORT || 3000;

// Boot gate (P5-1): until the listen() callback below marks the lab ready,
// every request gets a static 503 page. Nothing mid-boot (body parsers,
// session store, module routes) ever runs for a request in that window,
// so a stack trace can never leak during a restart.
const { createBootGate } = require('./lib/boot-gate');
const bootGate = createBootGate();
app.use(bootGate.middleware);

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
// Session secret (P1-9): SESSION_SECRET in the environment wins. Otherwise a
// random secret is generated once and persisted next to the lab database
// (gitignored, mode 0600), so restarts keep existing sessions valid while no
// deployment ever runs on the old committed fallback value. The literal
// fallback below survives only for read-only filesystems where the secret
// file cannot be written; it is fine for a one-off local lab and nothing else.

function resolveSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const secretPath = path.join(path.dirname(DB_PATH), '.session-secret');
  try {
    const existing = fs.readFileSync(secretPath, 'utf8').trim();
    if (existing.length >= 32) return existing;
  } catch (e) { /* first boot: generate below */ }
  const generated = crypto.randomBytes(32).toString('hex');
  try {
    fs.mkdirSync(path.dirname(secretPath), { recursive: true });
    fs.writeFileSync(secretPath, generated + '\n', { mode: 0o600 });
    console.log('[ok] generated a persistent session secret for this install');
    return generated;
  } catch (e) {
    console.warn('[warn] could not persist a session secret; using insecure dev fallback (fine for local labs only)');
    return 'pentrix-vulnlab-insecure-dev-secret';
  }
}

const SESSION_SECRET = resolveSessionSecret();

// This process boot's identity (P1-3). A session stores the boot id it
// started on; when the id no longer matches, the student sees the restart
// notice once (see the request-context middleware after the session setup).
const BOOT_ID = crypto.randomBytes(8).toString('hex');
const { SqliteStore } = require('./lib/session-store');
const sessionStore = new SqliteStore(path.join(path.dirname(DB_PATH), 'sessions.db'));
// lib/flags re-reads the merged stored flags through this reference when a
// request's session snapshot may be stale (parallel bursts, P1-6).
rctx.setSessionStore(sessionStore);
app.use(session({
  store: sessionStore,
  secret: SESSION_SECRET,
  resave: false,
  // saveUninitialized off (P1-9): anonymous browsing no longer writes a
  // session row per visitor; a session is only stored once a handler puts
  // something in it (a flag, a login, per-session challenge state).
  saveUninitialized: false,
  // VULN (deliberate): cookies readable by JS so XSS cookie-stealing demos work.
  cookie: { httpOnly: false },
}));

// ---- request context + restart-volatility notice (P1-3, P4-3) ----
// Wraps every request in the request context lib/flags and lib/page.js
// share (award tracking for the "Next challenge" button), and watches for
// sessions that outlived a lab restart: an established session keeps the
// boot id it started with, and a mismatch flags this request so the
// <!--px-boot-notice--> placeholder in page() is filled on the way out.
// Only established sessions (something stored besides the cookie jar) are
// stamped, so the marker never defeats saveUninitialized: false (P1-9).
app.use((req, res, next) => {
  rctx.run(req, () => {
    try {
      const s = req.session;
      const established = s && Object.keys(s).some((k) => k !== 'cookie');
      if (established) {
        if (!s.bootId) {
          s.bootId = BOOT_ID;
        } else if (s.bootId !== BOOT_ID) {
          s.bootId = BOOT_ID;
          req.__pxBootChanged = true;
        }
      }
    } catch (e) { /* the notice is best-effort and never blocks a request */ }
    next();
  });
});
app.use((req, res, next) => {
  const origSend = res.send;
  res.send = function (body) {
    if (typeof body === 'string' && body.includes('<!--px-boot-notice-->')) {
      body = body.split('<!--px-boot-notice-->').join(req.__pxBootChanged ? bootNoticeHtml() : '');
    }
    return origSend.call(this, body);
  };
  next();
});

// The restart banner (clay .warn card, matching /about's warning). The
// dismiss button only hides it in the browser (public/app.js); the server
// shows it once per restart because the boot id is updated on sight.
function bootNoticeHtml() {
  return `<div class="wrap"><div class="warn" role="status" data-boot-notice>
    <p class="warn-title"><span class="dot" aria-hidden="true"></span>The lab restarted</p>
    <p>The lab restarted since your session began, so progress from the previous boot may be gone: the scoreboard can fall back to 0 and per-boot secrets were rotated. <b>Record each flag as you earn it</b> (every flag box has a Copy button), so a restart never costs you your work.</p>
    <p><button type="button" class="clay-btn clay-btn-secondary clay-btn-sm" data-boot-dismiss>Dismiss</button></p>
  </div></div>`;
}
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ---- shared chrome guarantee (P4-8) ----
// Every page built with page() in lib/page.js renders the full shell:
// topbar, nav, footer. The score chip and the nav highlight are the two
// pieces a caller can accidentally drop (shell routes pass them, module
// routers do not). Fill them in here, on the way out, so challenge
// sub-pages carry the same chrome as the home page: any page template
// that still contains the <!--px-chrome--> placeholder gets the live
// chip for this session, and the nav link matching this path gets
// aria-current when no caller set one. Non-HTML responses are untouched.
const NAV_SECTIONS = ['scoreboard', 'scenarios', 'paths', 'about'];
app.use((req, res, next) => {
  const origSend = res.send;
  res.send = function (body) {
    if (typeof body === 'string' && body.includes('<!--px-chrome-->')) {
      body = body.split('<!--px-chrome-->').join(scoreChipHtml(req));
      if (!body.includes('aria-current="page"')) {
        const seg = String(req.path || '').split('/').filter(Boolean)[0] || '';
        const href = seg === '' ? '/' : (NAV_SECTIONS.includes(seg) ? '/' + seg : '');
        if (href) {
          body = body.replace(`<a href="${href}">`, `<a href="${href}" aria-current="page">`);
        }
      }
    }
    return origSend.call(this, body);
  };
  next();
});

getDb(); // init + seed

// ---- auto-mount modules: modules/<id>/index.js (falls back to router.js
// during the challenge-split migration; the fallback is removed once every
// module has an index.js) ----
const modulesDir = path.join(__dirname, 'modules');
// Route prefixes owned by the app shell; modules may not claim them.
const RESERVED_IDS = new Set(['scoreboard', 'about', 'uploads', 'scenarios', 'paths']);
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
// Ordered challenge catalog for the capture banner's "Next challenge"
// button (P4-3): lib/page.js resolves the successor of the challenge this
// request just awarded from this list.
rctx.setCatalog(registry.map((m) => ({
  id: m.id,
  vulns: (m.vulns || []).map((v) => ({ id: v.id, link: v.link })),
})));

// ---- M13 career paths (defs live in paths/; the framework mounts below,
// after the fixmode block, so the wiring order is explicit) ----
const scenariosMod = require('./scenarios/index');
const pathsMod = require('./paths/index');

// Seed per-deployment random flags for every registered challenge.
// Flags live only in the SQLite file (gitignored); the source never
// contains a real flag, so reading GitHub reveals nothing.
ensureFlags(registry.flatMap((m) => m.vulns.map((v) => ({ modId: m.id, vulnId: v.id })))
  .concat(scenariosMod.scenarios.map((s) => ({ modId: 'scenario', vulnId: s.id }))));

// ---- shell helpers (M4) ----
// One difficulty taxonomy (P4-7): modules and paths use
// Beginner / Intermediate / Advanced; challenges use Easy / Medium / Hard.
// The module filter offers the module scale, including Advanced.
const DIFFICULTIES = ['Beginner', 'Easy', 'Intermediate', 'Medium', 'Mixed', 'Hard', 'Advanced'];
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
  // Defensive: error pages (404/413/500) call this too, and an error raised
  // before session middleware ran leaves req.session undefined, which makes
  // captured() throw. An error page must never throw while rendering, or
  // Express falls back to its default handler and serves a stack trace.
  try {
    const { got, total } = totals(req);
    return `<span class="score-chip" title="Flags captured"><span aria-hidden="true">🚩</span> ${got}/${total}</span>`;
  } catch (e) {
    return '';
  }
}

// M12: scoreboard section for the kill-chain scenarios. It reuses the
// sb-module card styling (the extra sb-scenarios marker stays for future
// CSS). Rows carry data-search/data-key like module rows so the filter form
// and the client-side filter treat scenarios the same way (the scenario
// name stays link-wrapped, so the sb-module test parsing in
// tests/helpers.js, which expects <td><b>, does not pick these rows up).
function scenariosSectionHtml(req, statusOk, q) {
  const list = scenariosMod.scenarios;
  const done = list.filter((s) => captured(req, 'scenario', s.id)).length;
  const rows = list.map((s) => {
    const hit = captured(req, 'scenario', s.id);
    if (statusOk === 'captured' && !hit) return '';
    if (statusOk === 'missing' && hit) return '';
    if (q && !(s.name + ' kill-chain scenarios').toLowerCase().includes(q)) return '';
    const st = hit
      ? '<span class="status status-captured"><span class="dot" aria-hidden="true"></span>Captured</span>'
      : '<span class="status status-missing"><span class="dot" aria-hidden="true"></span>Not captured</span>';
    return `<tr data-search="${esc((s.name + ' kill-chain scenarios').toLowerCase())}" data-key="${hit ? 'captured' : 'missing'}"><td>${st}</td><td><a href="/scenarios/${esc(s.id)}"><b>${esc(s.name)}</b></a></td><td>${difficultyPill(s.difficulty)}</td></tr>`;
  }).join('');
  if (!rows && (statusOk !== 'all' || q)) return '';
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

// Canonical entry module (P4-6): misconfig. It is the module whose learning
// track literally says "Start here", and it is the agreed first step across
// the home page, the track banner, and the Zero to Web Pentester path.
const ENTRY_MODULE_ID = 'misconfig';
function startHereModule() {
  return registry.find((m) => m.id === ENTRY_MODULE_ID)
    || registry.find((m) => m.difficulty === 'Beginner')
    || registry.find((m) => m.difficulty === 'Easy')
    || registry[0];
}

// Recommended module order for the home grid: track order first (the
// curriculum's learning sequence), then module tier, then name. The orb
// number on each card is this recommended order, so the grid reads as a
// numbered learning path.
const TIER_ORDER = { beginner: 0, intermediate: 1, advanced: 2 };
function recommendedModuleOrder() {
  return registry.slice().sort((a, b) =>
    // The canonical entry module always comes first.
    (a.id === ENTRY_MODULE_ID ? -1 : b.id === ENTRY_MODULE_ID ? 1 : 0)
    || trackIndex(a.id) - trackIndex(b.id)
    || (TIER_ORDER[String(a.difficulty || '').toLowerCase()] ?? 1)
       - (TIER_ORDER[String(b.difficulty || '').toLowerCase()] ?? 1)
    || a.name.localeCompare(b.name));
}

// ---- home ----
app.get('/', (req, res) => {
  const q = String(req.query.q || '').trim();
  const qLower = q.toLowerCase();
  const diff = presentDiffs.includes(String(req.query.difficulty)) ? String(req.query.difficulty) : 'All';
  const filtering = q !== '' || diff !== 'All';
  const ordered = recommendedModuleOrder();

  const cards = ordered.map((m, i) => {
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
      <p class="track-line dim">${esc(trackOf(m.id))} · recommended #${num}</p>
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
    </section>
    <section class="starter" aria-label="Set up Burp first">
      <div class="orb-row"><span class="orb" aria-hidden="true">🛠</span><h2>Set up Burp first</h2></div>
      <p>Every challenge in this lab is solved through <b>Burp Suite</b>, the standard intercepting proxy: Proxy to see traffic, Repeater to tamper, Intruder for brute force. The free Community Edition is enough for all ${total} challenges. Install Burp, point your browser at the proxy, and install the CA certificate once, then come back and start capturing flags.</p>
      <p><a class="clay-btn clay-btn-primary clay-btn-sm" href="/setup-guide">Open the Tool Setup Guide</a></p>
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
      // Rows link back to their challenge (P4-3). The name cell keeps its
      // <td><b> shape (tests/helpers.js parses it); the link lives in its
      // own trailing cell and deep-links to the challenge anchor.
      const href = v.link || `/${m.id}#${v.id}`;
      return `<tr data-search="${esc((v.name + ' ' + m.name).toLowerCase())}" data-key="${hit ? 'captured' : 'missing'}">
        <td>${st}</td><td><b>${esc(v.name)}</b></td><td>${difficultyPill(v.difficulty)}</td><td><a class="clay-btn clay-btn-secondary clay-btn-sm" href="${esc(href)}">Open</a></td></tr>`;
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
        <thead><tr><th scope="col">Status</th><th scope="col">Challenge</th><th scope="col">Difficulty</th><th scope="col">Open</th></tr></thead>
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

  // The scenarios section follows the same filter as the module sections;
  // the "Nothing matches" state only renders when BOTH are empty, so it
  // never claims no results while scenario rows are on screen (P4-3).
  const scenarioHtml = scenariosSectionHtml(req, statusOk, q);
  const anyRows = Boolean(sections) || Boolean(scenarioHtml);

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
    ${anyRows ? sections : emptyState('Nothing matches', '<p>No challenges match the current filter.</p>', '<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/scoreboard">Clear filter</a></p>')}
    ${scenarioHtml}
    <section class="card" aria-label="About your progress">
      <div class="card-top"><span class="orb" aria-hidden="true">💾</span><b>Progress resets on restart</b></div>
      <p class="dim">Your scoreboard lives in your session: if the lab restarts or your session is lost, captures go back to 0. <b>Record each flag as you earn it</b>, and export your progress for your records before you close the lab.</p>
      <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/scoreboard/export.csv" download>Export scoreboard (CSV)</a></p>
    </section>`,
    'scoreboard', { scoreChip: scoreChipHtml(req) }));
});

// ---- scoreboard CSV export (P1-4: classroom minimum) ----
// The student's own scoreboard as a gradebook-ready CSV: one row per
// challenge plus the kill-chain scenarios. Instructors collect one file
// per student because the lab has no accounts (see docs/CLASSROOM.md).
app.get('/scoreboard/export.csv', (req, res) => {
  const cell = (v) => {
    const s = String(v == null ? '' : v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const rows = [['module_id', 'module_name', 'challenge_id', 'challenge_name', 'difficulty', 'status']];
  for (const m of registry) {
    for (const v of m.vulns || []) {
      rows.push([m.id, m.name, v.id, v.name, v.difficulty, captured(req, m.id, v.id) ? 'captured' : 'not captured']);
    }
  }
  for (const s of scenariosMod.scenarios) {
    rows.push(['scenario', 'Kill-chain scenarios', s.id, s.name, s.difficulty,
      captured(req, 'scenario', s.id) ? 'captured' : 'not captured']);
  }
  res
    .type('text/csv')
    .set('Content-Disposition', 'attachment; filename="pentrix-scoreboard.csv"')
    .send(rows.map((r) => r.map(cell).join(',')).join('\n') + '\n');
});

// ---- tool setup guide: render docs/TOOL_SETUP_GUIDE.md as HTML ----
// Minimal markdown renderer: fenced code blocks, headings (with GitHub-style
// anchor ids so the guide's own TOC links keep working), tables, lists,
// paragraphs, inline code, bold, and links. HTML is escaped first.
function mdSlug(text) {
  return text.toLowerCase().replace(/[^a-z0-9 -]/g, '').trim().replace(/\s+/g, '-').replace(/-+/g, '-');
}
function mdInline(text) {
  let out = text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return out;
}
function renderGuideMarkdown(md) {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  const out = [];
  let code = null;      // null or array of code lines
  let para = [];
  let list = null;      // null, 'ul', or 'ol'
  let table = null;     // null or array of row arrays
  function flushPara() {
    if (para.length) { out.push('<p>' + mdInline(para.join(' ')) + '</p>'); para = []; }
  }
  function flushList() {
    if (!list) return;
    out.push(list.open + list.items.join('\n') + (list.kind === 'ul' ? '\n</ul>' : '\n</ol>'));
    list = null;
  }
  function flushTable() {
    if (!table) return;
    const rows = table.filter((r) => !r.every((c) => /^:?-+:?$/.test(c)));
    const head = rows[0].map((c) => '<th>' + mdInline(c) + '</th>').join('');
    const body = rows.slice(1).map((r) => '<tr>' + r.map((c) => '<td>' + mdInline(c) + '</td>').join('') + '</tr>').join('\n');
    out.push('<div class="tbl-scroll"><table class="tbl">\n<thead><tr>' + head + '</tr></thead>\n<tbody>\n' + body + '\n</tbody></table></div>');
    table = null;
  }
  const openUl = (items) => ({ kind: 'ul', open: '<ul>', items });
  for (const raw of lines) {
    const line = raw;
    if (line.trim().startsWith('```')) {
      if (code === null) { flushPara(); flushList(); flushTable(); code = []; }
      else {
        out.push('<pre><code>' + code.join('\n')
          .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</code></pre>');
        code = null;
      }
      continue;
    }
    if (code !== null) { code.push(line); continue; }
    const trimmed = line.trim();
    const hm = trimmed.match(/^(#{1,4})\s+(.*)$/);
    if (hm) {
      flushPara(); flushList(); flushTable();
      const lvl = Math.min(hm[1].length + 1, 4);
      const text = hm[2].replace(/\s*#+$/, '').trim();
      out.push(`<h${lvl} id="${mdSlug(text)}">${mdInline(text)}</h${lvl}>`);
      continue;
    }
    if (/^-{3,}\s*$/.test(trimmed)) { // horizontal rule
      flushPara(); flushList(); flushTable();
      out.push('<hr />');
      continue;
    }
    if (/^\|.*\|$/.test(trimmed)) {
      flushPara(); flushList();
      const cells = trimmed.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      table = table || [];
      table.push(cells);
      continue;
    }
    if (table && trimmed !== '') { flushTable(); }
    if (/^\s*[-*]\s+/.test(line)) {
      flushPara(); flushTable();
      if (!list || list.kind !== 'ul') { flushList(); list = openUl([]); }
      list.items.push('<li>' + mdInline(trimmed.replace(/^\s*[-*]\s+/, '')) + '</li>');
      continue;
    }
    const om = trimmed.match(/^\s*(\d+)\.\s+(.*)$/);
    if (om) {
      flushPara(); flushTable();
      if (!list || list.kind !== 'ol') { flushList(); list = { kind: 'ol', open: '<ol>', items: [] }; }
      list.items.push('<li>' + mdInline(om[2]) + '</li>');
      continue;
    }
    if (trimmed === '') { flushPara(); flushList(); flushTable(); continue; }
    if (trimmed.startsWith('>')) { // blockquote line
      flushPara(); flushList(); flushTable();
      out.push('<blockquote><p>' + mdInline(trimmed.replace(/^>\s?/, '')) + '</p></blockquote>');
      continue;
    }
    flushList(); flushTable();
    para.push(trimmed);
  }
  flushPara(); flushList(); flushTable();
  return out.join('\n');
}

app.get('/setup-guide', (req, res) => {
  let md;
  try {
    md = fs.readFileSync(path.join(__dirname, 'docs', 'TOOL_SETUP_GUIDE.md'), 'utf8');
  } catch (e) {
    return res.status(500).send(page('Tool Setup Guide',
      '<h1>Tool Setup Guide</h1><p>The setup guide file could not be read. It lives at <code>docs/TOOL_SETUP_GUIDE.md</code> in the lab source.</p>',
      null, { scoreChip: scoreChipHtml(req) }));
  }
  res.send(page('Tool Setup Guide', renderGuideMarkdown(md),
    'setup-guide', { scoreChip: scoreChipHtml(req) }));
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
      <h2>Set up Burp first</h2>
      <div class="clay-card">
        <div class="card-top"><span class="orb" aria-hidden="true">🛠</span><b>Tool Setup Guide</b><span class="dim">do this once, before your first flag</span></div>
        <p>Every challenge in this lab is solved through <b>Burp Suite</b>, the standard intercepting proxy: Proxy to see traffic, Repeater to tamper, Intruder for brute force. The free Community Edition is enough for all 201 challenges. The guide walks you through installing Burp, pointing your browser at the proxy, installing the CA certificate, and the workflow you will repeat on every challenge (plus a race-condition technique and a Grep-Match walkthrough the hint ladders rely on).</p>
        <p><a class="clay-btn clay-btn-primary" href="/setup-guide">Open the Tool Setup Guide</a></p>
      </div>
    </section>
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

// ---- M13 career paths wiring (mounted after the scenarios block) ----
app.use('/paths', pathsMod.router);
pathsMod.setPathsRegistry(registry);

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
// Fix checks run in worker threads (lib/fixmode.js), so this handler is
// async; the lib returns { ok, error } for student-code problems and never
// rejects for them, but the try/catch (plus the async-handler wrapper)
// keeps any unexpected runner failure on the friendly error path.
app.post('/fix/:module/:vuln/test', async (req, res) => {
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
      ? await fixmode.testFix(module, vuln, code)
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
  // P5-4: an oversized body is a client error, not a lab crash. body-parser
  // marks these with type 'entity.too.large' (status 413); answer with a
  // clean 413 page instead of falling through to the 500 branch.
  if (err && (err.type === 'entity.too.large' || err.status === 413 || err.statusCode === 413)) {
    if (res.headersSent) return next(err);
    try {
      return res.status(413).send(page('Request too large',
        errorPage(413, 'That request was too large',
          '<p>The lab refused the request because its body was bigger than the limit. Trim what you sent and try again.</p>'),
        null, { scoreChip: scoreChipHtml(req) }));
    } catch (e) {
      // The 413 page itself must render no matter what; never fall through
      // to Express's default error handler, which serves a stack trace.
      return res.status(413).type('text').send('Request too large.');
    }
  }
  // Honor other 4xx statuses carried by middleware errors (e.g. malformed
  // JSON bodies, status 400) instead of collapsing them to a 500.
  if (err && Number.isInteger(err.status) && err.status >= 400 && err.status < 500) {
    if (res.headersSent) return next(err);
    try {
      return res.status(err.status).send(page('Bad request',
        errorPage(err.status, 'Bad request',
          '<p>The lab could not understand that request. Check the format and try again.</p>'),
        null, { scoreChip: scoreChipHtml(req) }));
    } catch (e) {
      return res.status(err.status).type('text').send('Bad request.');
    }
  }
  console.error('[err]', err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  try {
    res.status(500).send(page('Error',
      errorPage(500, 'Something broke',
        '<p>The lab hit an unexpected error. Your progress is safe; try going back and continuing.</p><p class="dim">If this keeps happening, restart the lab and check the terminal for the error log.</p>'),
      null, { scoreChip: scoreChipHtml(req) }));
  } catch (e) {
    res.status(500).type('text').send('Something broke. Your progress is safe; try going back and continuing.');
  }
});

// Exported so the test suite can boot the app on an ephemeral port.
if (require.main === module) {
  app.listen(PORT, () => {
    bootGate.markReady();
    console.log(`[ok] PenTrix VulnLab listening on http://localhost:${PORT}`);
  });
}
module.exports = app;
