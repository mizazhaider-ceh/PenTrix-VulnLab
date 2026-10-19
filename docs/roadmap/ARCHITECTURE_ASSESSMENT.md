# ARCHITECTURE_ASSESSMENT: PenTrix VulnLab (Phase One)

Date: 2026-10-19. Author: Technical Auditor (subagent).
Method: read app.js, lib/*, Dockerfile, docker-compose.yml, MODULE_CONTRACT.md,
sample module routers, and package.json line by line; verified claims against a
live local instance at http://localhost:3000 with curl; ran small node probes
against the repo. No Docker daemon on this VM, so the Dockerfile and
docker-compose.yml were reviewed statically (limits documented in each section).
No code was modified. Only the local instance was tested.

Labels: OBSERVED = seen in code or live output. HYPOTHESIS = plausible, not yet
verified (collected at the end for later phases).

## 0. Correction to Phase Zero

Phase Zero reported 244 vulns by hint-count. The live scoreboard reports
**235** flags, and summing `vulns.length` across all 29 loaded modules in node
gives **235**. The 244 figure was an overcount: several routers contain extra
`hint:` strings in page templates or comments that the grep counted. 235 is the
authoritative number and it matches the README's "235 intentionally vulnerable
challenges". The README is not stale on this point.

## 1. Request flow (OBSERVED)

```
browser
  -> Express 4.19.2 (app.js, single process, node app.js)
  -> middleware chain, in order:
       1. conditional express.urlencoded (SKIPPED for /upload* paths, so the
          upload module's express.raw() sees raw bytes)
       2. express.json() (default 100kb limit)
       3. cookie-parser
       4. express-session (MemoryStore)
       5. express.static(public/) at /
       6. express.static(uploads/) at /uploads
  -> 29 module routers, auto-mounted at /<id> in readdir (alphabetical) order
  -> better-sqlite3, synchronous queries against data/vulnlab.db (singleton)
  -> HTML rendered from template strings (lib/page.js), no view engine
```

Notes:
- There is no API layer, no service layer, no ORM. Routers call SQLite directly
  and render HTML directly. For a 15k-line training app this is simple and
  readable; the cost is duplicated HTML patterns across 29 routers.
- better-sqlite3 is fully synchronous, so every query blocks the single Node
  event loop for its duration. Normal lab queries are milliseconds. A student's
  SQLi payload is arbitrary SQL, so a deliberately heavy query (cartesian join,
  recursive CTE) blocks the whole process for everyone on it. This is only a
  problem for shared deployments; per-student containers remove it (section 7).
- `app.listen(PORT)` with no host argument binds all interfaces (0.0.0.0 / ::).
  Combined with compose `3000:3000`, the default deployment listens on every
  host interface (section 6).
- OBSERVED response headers: `X-Powered-By: Express` is sent. 404s return the
  default Express HTML error page. No request logging middleware exists.

## 2. Express/SQLite architecture findings (OBSERVED)

1. **Singleton DB, lazy seed.** `lib/db.js` exports `getDb()` (singleton) and
   `DB_PATH` (env `DB_PATH` or `data/vulnlab.db`). First call does
   `mkdir -p`, creates 5 core tables with `IF NOT EXISTS`, and seeds users,
   products, orders, comments only when the tables are empty. Deleting the DB
   file and rebooting reseeds cleanly. Modules add their own prefixed tables
   (observed prefixes: `sqli_`, `xss_`, `jwt_`, `idor_`, `http_`, `redirect_`),
   following the contract rule.
2. **21 async route handlers exist across the modules, and app.js has no
   error-handling middleware.** Express 4 does not catch rejected promises from
   async handlers. A rejection becomes an unhandled rejection, and Node's
   default behavior terminates the process. Consequence: one malformed request
   to the wrong module can kill the server and wipe every in-memory session.
   (The absence of error middleware is OBSERVED; which exact requests trigger
   a crash is HYPOTHESIS H4 until a fault-injection sweep is run.)
3. **The `/upload` body-parser exemption hardcodes a module id in app.js.**
   The global urlencoded parser is skipped for `/upload*` so the upload
   module's `express.raw({ type: '*/*', limit: '2mb' })` receives raw bytes.
   This is app-level code with knowledge of one specific module. It works, it
   is commented, but it is coupling: renaming the upload module's id would
   silently break uploads. Recommendation: accept and document, do not churn
   the module contract to fix it (section 8).
4. **Module load-time side effects are unconstrained.** The hostheader module
   starts an internal HTTP agent at require time:
   `internalAgent.listen(13919, '127.0.0.1', ...)` (modules/hostheader/router.js,
   lines 241-259). This is by design for the Host-header SSRF lab, but the
   loader places no limits on what a module may do at load: open ports, start
   timers, touch the filesystem outside its directory. OBSERVED consequence: a
   second app process on the same host fails to bind 13919 (`EADDRINUSE` seen
   in a probe) while the module still loads. Per-student containers (separate
   net namespaces) avoid the collision (HYPOTHESIS H7).
5. **Static file serving.** `public/` serves `style.css`; `uploads/` is served
   at `/uploads`. OBSERVED: the seeded `uploads/shell.php.jpg`
   (`<?php echo 1; ?>`) is retrievable over HTTP, served as `image/jpeg`, so
   it is not executed by the browser, but the on-disk webshell is the lab's
   whole point. Student uploads land in the same directory and are immediately
   retrievable, which is exactly the upload-vuln attack chain.
6. **Process-spawning labs.** The cmdi module uses
   `child_process.exec('ping -c 1 ' + host, { timeout: 8000 })`. Real command
   injection, real shell per request, no rate limiting. `iputils-ping` is
   installed in the image specifically for this lab. The 8s exec timeout bounds
   a single request, but nothing bounds concurrent requests.

## 3. Module loader contract (OBSERVED)

How auto-mounting works in app.js:

1. `fs.readdirSync('modules')` lists directories (alphabetical order).
2. Each `modules/<dir>/router.js` is `require`d inside try/catch. Synchronous
   require errors are logged and the module is skipped; the app still boots.
3. Shape check: `mod.id`, `mod.router`, and `Array.isArray(mod.vulns)` must be
   truthy, otherwise `[warn] skipping <dir>: bad module shape`.
4. `app.use('/' + mod.id, mod.router)` mounts the router; the module is pushed
   to `registry`, also exposed as `app.locals.registry`.
5. Home (`/`) and scoreboard (`/scoreboard`) render purely from the registry.
   `/about` is static. These three routes are registered AFTER the module loop.

Compatibility surface (what the shell actually consumes):

- Loader requires: `id` (string, used as URL prefix), `router`
  (express.Router), `vulns` (array).
- Home page uses: `name`, `tagline`, `difficulty`, `vulns.length`, and per-vuln
  `captured(req, m.id, v.id)`.
- Scoreboard uses: `name`, per-vuln `id`, `name`, `difficulty`, `captured(...)`.
- Module index convention (used by each module's own `GET /<id>`, not by the
  shell): `brief()`, per-vuln `hint`, `how`, `link`, `hintBox()`.
- A probe requiring all 29 routers confirmed every module exports the full
  7-field shape (`id, name, tagline, description, difficulty, vulns, router`).

Loader gaps (OBSERVED, all minor, none breaking today):

- No validation of `id` format. An id with slashes, uppercase, or spaces would
  mount at an odd path. A duplicate id would mount twice and double-count
  flags. An id of `scoreboard`, `about`, or `uploads` would shadow the shell
  routes or the static uploads mount, because module routes register first.
- Mount order is filesystem order (alphabetical). Nothing depends on it today,
  but two modules could theoretically claim overlapping sub-paths; first
  mounted wins silently.
- `require` caches modules; there is no hot reload. Fine for the use case.

## 4. Session, flag, and scoreboard system (OBSERVED)

- `express-session` 1.18 with default **MemoryStore**. Config in app.js:
  `secret: 'pentrix-vulnlab-insecure-dev-secret'` (hardcoded, committed),
  `resave: false`, `saveUninitialized: true`,
  `cookie: { httpOnly: false }` with an inline comment marking it a deliberate
  VULN so XSS cookie-stealing labs work.
- Effective cookie attributes: `httpOnly=false` (deliberate), no `Secure` flag,
  no `SameSite` attribute (the library default in this version leaves it
  unset), `Path=/`, session lifetime (browser-session cookie, `maxAge: null`).
  (Set-Cookie values were redacted by this environment's tooling, so the exact
  wire format is confirmed from the express-session source defaults plus the
  app.js override, not from a captured header.)
- `saveUninitialized: true` creates a session and sends a cookie to every
  visitor, including bots and scanners. Each one occupies MemoryStore until
  the process ends. `award()` marks the session modified, so switching to
  `saveUninitialized: false` would not break flag persistence (section 8).
- `lib/flags.js` (18 lines): `flagFor(modId, vulnId)` builds
  `PENTRIX{<modId>_<vulnId>}`; `award(req, modId, vulnId)` sets
  `req.session.flags['<modId>:<vulnId>'] = true` and returns the flag string;
  `captured(req, modId, vulnId)` reads it back. Modules are expected to call
  `award()` only after the exploit genuinely succeeds (contract rule 2) and to
  render the result with `flagBox()`.
- Scoreboard and home-page counters derive entirely from the session. There is
  no server-side record of who captured what, no timestamps, no export.
- Consequences, all OBSERVED mechanisms:
  1. Progress dies with the process (restart, crash, redeploy). For a local
     self-study lab this is tolerable; for classroom or graded use it is not.
  2. The session secret is public (it is in the repo). Anyone holding it can
     forge a session cookie with arbitrary `flags` set, i.e. self-award the
     whole scoreboard without exploiting anything. For solo study this only
     cheats yourself; for any shared or graded deployment it breaks the
     scoreboard's integrity. Fix path: `SESSION_SECRET` env var (section 8).
  3. MemoryStore grows with traffic and is never pruned except by expiry
     (sessions here have no maxAge, so effectively never). A scanner hitting
     the app inflates memory. Low severity locally.

## 5. Dockerfile, line by line (OBSERVED, static review, no daemon on this VM)

```dockerfile
FROM node:20-slim
```
Node 20 matches the better-sqlite3@11 prebuild matrix. OBSERVED: v11 has no
Node 24 prebuild and crashes on Node 24 (Phase Zero), so the image must stay on
Node 20 until better-sqlite3 is bumped and re-verified (HYPOTHESIS H5 covers
whether the prebuild actually downloads on node:20-slim).

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ iputils-ping \
  && rm -rf /var/lib/apt/lists/*
```
- `python3 make g++` are needed only if better-sqlite3 falls back to a
  node-gyp source build. They remain in the final image (no multi-stage
  build, no purge). In a deliberately RCE-vulnerable app, shipping compilers
  widens what an exploited student process can do (compile payloads, build
  tools). `rm -rf /var/lib/apt/lists/*` is good hygiene and is present.
- `iputils-ping` is a genuine runtime dependency of the cmdi lab
  (`ping -c 1`). It must stay in the final image.

```dockerfile
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
```
Good layer caching. `package.json` has no `devDependencies`, so `--omit=dev`
is currently a no-op (harmless).

```dockerfile
COPY . .
RUN mkdir -p uploads data && chmod 777 uploads data
```
- `.dockerignore` (OBSERVED) excludes `node_modules`, `data`, `uploads`,
  `.git`. So the committed `data/vulnlab.db` is NOT baked into the image;
  `/app/data` starts empty and `getDb()` seeds it on first boot. Resetting the
  lab is deleting the volume contents. This is actually the sane behavior; the
  oddity is only that the DB is committed to git while both `.gitignore` and
  `.dockerignore` exclude `data/` (section 8, item 8).
- `chmod 777` on `uploads` and `data` is broader than needed. With the compose
  volume, the host's `./data` permissions win for `data/`. For `uploads/` the
  777 persists. Once a non-root USER is added, prefer `chown` to that user
  instead of world-writable.

```dockerfile
EXPOSE 3000
CMD ["node", "app.js"]
```
`EXPOSE` is documentation only. Exec-form CMD is correct (proper signal
handling, no shell wrapper).

Missing from the Dockerfile (OBSERVED): no `USER` (the app runs as **root** in
the container, so every RCE lab yields a root shell in the container); no
`HEALTHCHECK`; no removal of build tools.

## 6. docker-compose.yml, line by line (OBSERVED, static review)

```yaml
services:
  vulnlab:
    build: .
```
Builds the local Dockerfile. No image tag, no pull policy. Fine for local use.

```yaml
    ports:
      - "3000:3000"
```
Short syntax binds **all host interfaces**, not just localhost. On a laptop
this is usually fine; on any shared or lab network it exposes a deliberately
RCE-vulnerable app to the LAN. This is the single most consequential line in
the file. Minimal fix: `"127.0.0.1:3000:3000"` (section 8).

```yaml
    volumes:
      - ./data:/app/data
```
Persists the SQLite DB on the host across container recreates. Consequences:
host `./data` permissions apply inside the container; deleting the host dir
resets the lab; pointing two containers at one host dir (or one DB file via
`DB_PATH`) risks SQLite locking problems across containers (HYPOTHESIS H8:
do not share one sqlite file between containers).
`uploads/` is NOT volume-mounted, so student-uploaded webshells vanish on
container recreate while the DB persists. That inconsistency is OBSERVED;
whether it is intended hygiene or an oversight is undecided, document it
either way.

```yaml
    environment:
      - PORT=3000
```
Matches EXPOSE; app defaults to 3000 anyway. `DB_PATH` is read by lib/db.js but
not set here.

Missing from compose (OBSERVED): no `restart:` policy (a crash from section
2.2 stays down), no `healthcheck:`, no `mem_limit`/`cpus:` (a ReDoS or fork-ish
payload can consume the host), no `networks:` (default bridge is fine), no
`cap_drop`/`security_opt`, no `read_only` root filesystem.

## 7. Lab isolation risks for a deliberately vulnerable app

Threat model: the app contains working RCE (cmdi command injection, SSTI,
unrestricted upload served back over HTTP, plus 280 marked flaws). The
attacker is the student, and the assets to protect are: other students'
instances, the host, and the lab network. The app must never leave localhost
or an isolated lab net (the about page and README already say this; the
compose file does not enforce it).

Ranked isolation findings:

1. **Default bind is all-interfaces (app) + all-interfaces publish
   (compose).** Two independent defaults combine into LAN exposure. Fix the
   compose line; the app-level `app.listen(PORT)` binding 0.0.0.0 is then
   harmless behind it. (Unintended, highest leverage.)
2. **Single process = shared fate.** ReDoS catastrophic backtracking
   (`new RegExp('^((' + s + ')+)+$')` on user input, no timeout, OBSERVED in
   modules/redos/router.js), unbounded SQLi queries, and un-rate-limited
   `child_process.exec` per request can hang or exhaust the one Node process.
   One student can deny the lab to everyone sharing that process. The code
   cannot fix this without neutering the labs themselves; the fix is
   architectural: **one container per student**.
3. **Container runs as root with compilers installed.** Post-exploit, the
   student is root in the container with gcc, make, python3, and ping.
   Minimal hardening: `USER node` (the image already has the `node` user),
   drop build tools from the final image (multi-stage or purge), `cap_drop:
   ALL` in compose. Caveat: verify `ping` still works as non-root
   (HYPOTHESIS H6; Debian's iputils-ping normally carries the needed file
   capability, but confirm inside the real image).
4. **No resource limits.** Add `mem_limit`/`cpus` (or compose `deploy`
   resources) per student container so a ReDoS or process-spawn loop is
   contained to that student's container.
5. **Fixed localhost port at module load (hostheader, 13919).** Safe inside
   per-student bridge-networked containers (loopback is per-namespace);
   collides only with host-network mode or two processes on one host
   (HYPOTHESIS H7). Do not use `--network host` for student containers.
6. **Volume hygiene.** One `./data` (or one named volume) per student
   container. Never mount one sqlite file into two writers. Document the
   `uploads/` ephemerality decision.
7. **Classroom LAN deployments** need a reverse proxy with authentication in
   front of per-student containers, never direct port publishes per student to
   the LAN. Out of scope for the compose file, but it is the deployment
   topology this assessment recommends.

What does NOT need to change for isolation: the vulnerabilities themselves.
They are the product. Every hardening step above is about the container and
the publish surface, not the labs.

## 8. Tech debt list (OBSERVED, no fashion rewrites)

1. No error-handling middleware; async rejections can terminate the process
   (section 2.2).
2. MemoryStore sessions: progress lost on restart, memory grows with
   `saveUninitialized: true`, no pruning.
3. Hardcoded, committed session secret; scoreboard forgeable by anyone who
   reads the repo (section 4).
4. No rate limiting at the app/shell layer (several labs intentionally lack
   it; the home/scoreboard/session layer has none either).
5. `X-Powered-By: Express` header sent.
6. Module `id` not validated (format, uniqueness, reserved words
   `scoreboard`, `about`, `uploads`); modules mount before shell routes, so a
   colliding id would shadow them.
7. `/upload` body-parser exemption hardcodes a module id in app.js (accepted
   coupling; documented here).
8. `data/vulnlab.db` is committed to git while `.gitignore` lists `data/` and
   `.dockerignore` excludes it: contradictory. Every clone carries a stale DB
   and local runs dirty the working tree.
9. Dockerfile: root user, build tools in final image, `chmod 777`, no
   healthcheck. Compose: all-interface publish, no restart policy, no
   resource limits, no healthcheck.
10. `uploads/` ephemeral, `data/` persistent: inconsistent lifecycle,
    undocumented.
11. 15k lines of template-string HTML with duplicated patterns; shared
    helpers are only `page/esc/flagBox/hintBox/brief`. Any redesign must add
    components without touching the module contract.
12. No request logging; debugging a deployed instance is blind.
13. `// VULN:` markers (280) make solutions grep-able. Deliberate pedagogical
    tradeoff per the about page; keep, but never put flags or full payloads in
    comments (spot-check occasionally).
14. JWT module's weak-secret lab uses a hardcoded weak secret. This is the
    lab's entire point (intentional), not a leak; noted so a future
    "remove hardcoded secrets" sweep does not break the lab.

## 9. Minimal justified improvements

Only changes with a concrete justification. Each is small, reversible, and
keeps the loader contract stable. None alter any lab's vulnerability.

1. **Compose: `"127.0.0.1:3000:3000"`.** Justification: the app is
   deliberately RCE-vulnerable; the one-line change removes default LAN
   exposure. Reversible, documented.
2. **`app.disable('x-powered-by')`.** Justification: removes server
   fingerprinting with zero behavior change.
3. **`saveUninitialized: false`.** Justification: stops minting sessions for
   every bot/crawler hit (MemoryStore growth); `award()` still persists the
   session on first flag capture because it mutates `req.session`. Verify with
   the Phase Zero exploit test after changing.
4. **`secret: process.env.SESSION_SECRET || 'pentrix-vulnlab-insecure-dev-secret'`.**
   Justification: lets classroom/graded deployments set a real secret without
   forking; local default behavior unchanged. Does not un-commit the default,
   but makes the fix deployable.
5. **Global error-handling middleware** (4-arg, after all routes) returning a
   minimal 500 page. Justification: a single bad module request should not
   kill the process and everyone's sessions. Note honestly: this catches sync
   throws; Express 4 async rejections still need per-handler try/catch, which
   becomes a per-module fix list for a later phase (H4).
6. **Dockerfile `USER node`** (with `chown node:node` on uploads/data instead
   of `chmod 777`). Justification: RCE labs currently yield container root;
   dropping privileges shrinks post-exploit impact. Verify the cmdi `ping`
   lab still works as non-root before merging (H6).
7. **Multi-stage build (or purge build tools after `npm ci`).**
   Justification: compilers in an RCE-able final image widen post-exploit
   options; `iputils-ping` stays, `python3/make/g++` go. Verify
   better-sqlite3@11 installs from prebuild on node:20-slim first (H5).
8. **Compose: `restart: unless-stopped`, `healthcheck` via node fetch
   (Node 20 has global fetch; no curl in the slim image), `mem_limit` and
   `cpus`.** Justification: crash recovery and blast-radius containment for
   classroom use; healthcheck needs no new packages.
9. **Loader: validate `id`** (lowercase alphanumerics, unique across
   registry, not in `['scoreboard', 'about', 'uploads']`), warn-and-skip on
   violation like the existing bad-shape path. Justification: prevents route
   shadowing and double-mounts at negligible cost, in the spirit of the
   existing validation.
10. **Git: stop tracking `data/vulnlab.db`** (`git rm --cached`, keep the
    `.gitignore` entry). Justification: the file is already excluded by
    `.dockerignore` and regenerated by seed-on-boot; tracking it only ships a
    stale DB and dirties clones. No code change; seed path already handles a
    missing file.
11. **Document the `/upload` parser exemption and the `uploads/`
    ephemerality** in README/CONTRIBUTING. Justification: both are
    non-obvious behaviors a future contributor will trip over; docs, not
    code.

Explicitly NOT recommended: rewriting template strings into a view engine,
adding an ORM, splitting routers into MVC layers, switching session stores to
Redis, or any dependency additions. None have a concrete justification at this
scale, and all risk breaking the module contract.

## 10. What must stay compatible

The loader contract is the compatibility surface for all 29 modules and any
future frontend redesign. These are load-bearing:

- Module export shape: `{ id, name, tagline, description, difficulty,
  vulns[], router }`. Shell consumes `id/router/vulns` (loader),
  `name/tagline/difficulty` (home), `name` + per-vuln `id/name/difficulty`
  (scoreboard).
- Vuln entry fields: `id`, `name`, `difficulty`, `hint`, `how`, `link`
  (index-page convention; shell uses the first three).
- `lib/flags`: `award(req, modId, vulnId)` returns `PENTRIX{modId_vulnId}` and
  marks capture; `captured(req, modId, vulnId)` reads it. Flag format is fixed.
  Session key namespace: `req.session.flags['<modId>:<vulnId>'] = true`.
- `lib/page`: `page(title, bodyHtml)`, `esc(s)`, `flagBox(flag)`,
  `hintBox(hint)`, `brief(title, html)`.
- `lib/db`: `getDb()` singleton, `DB_PATH` env override, seed-on-empty
  behavior, prefixed per-module tables with `IF NOT EXISTS`.
- Mounting: an `express.Router()` mounted at `/<id>` with routes relative to
  that prefix. Static: `/` serves `public/`, `/uploads` serves `uploads/`.
- Contract rules 1-10 (real vulns only, award on success, `// VULN:` markers,
  self-contained routers, no new deps, module index page, visible attack
  surface, fixed flag format, `node --check` robustness, honest difficulty).

## 11. Ranked risks

| # | Risk | Kind | Severity | Notes |
|---|------|------|----------|-------|
| 1 | LAN exposure by default (`3000:3000` + 0.0.0.0 bind) on an RCE-vulnerable app | unintended | high | one-line compose fix (9.1) |
| 2 | One student's ReDoS / heavy SQLi / process-spawn payload hangs the single shared process | intended vuln, unintended blast radius | high for shared use | fix is per-student containers, not code (7.2) |
| 3 | Async handler rejection kills the process; all sessions lost; no error middleware | unintended | medium | small fix (9.5) + per-module audit (H4) |
| 4 | Hardcoded session secret allows scoreboard forgery | unintended | medium solo / high graded | env override (9.4) |
| 5 | Container runs as root with compilers; RCE labs yield root shells in-container | unintended hardening gap | medium | USER + multi-stage (9.6, 9.7) |
| 6 | MemoryStore: progress lost on restart, unbounded growth via saveUninitialized | unintended | low-medium | 9.3; durable store only if grading needs it |
| 7 | No restart policy, healthcheck, or resource limits | operational | low-medium | 9.8 |
| 8 | DB committed to git vs gitignored; hostheader fixed port blocks 2nd instance per host | integrity/ops | low | 9.10; H7 |
| 9 | Fingerprinting (`X-Powered-By`), default 404, no request logging | minor | low | 9.2; logging optional |
| 10 | Challenge verification is by convention, not construction: shell trusts module award() calls; no independent exploit check | lab-engine integrity | medium solo / high graded | contract verification hook needed (12.1; H9) |
| 11 | No per-lab/per-module reset; restart alone clears flags but keeps dirty DB and uploads (worst combination) | lab-engine UX | medium | reset contract hook + documented full-reset procedure (12.2; 9.11) |

## 12. Lab-engine deep dive (per the Balance Rule)

izaz's Balance Rule gives the lab engine equal weight to visual quality:
target isolation, challenge verification, reset behavior, learning outcomes,
realistic tool usage. This section treats those as architecture concerns with
observed evidence.

### 12.1 Challenge verification: the shell trusts module code completely

OBSERVED: `award(req, modId, vulnId)` is called from inside module routers
(29 modules contain award call sites). Nothing in app.js, lib/flags.js, or the
loader verifies that an exploit actually happened before the flag is recorded.
Contract rule 2 ("award on success, never before") is enforced only by code
review. A module that called `award()` unconditionally would produce a
green scoreboard with zero exploitation, and the shell could not tell.

Consequences:
- For solo self-study this is fine (cheating yourself is pointless).
- For classroom, grading, or any "verified solve" learning-outcome tracking,
  the current architecture cannot distinguish a real exploit from a
  self-awarded flag. The hardcoded session secret (section 4) is the trivial
  exploit of this trust model: forge a session cookie with all flags set.
- The one place where verification IS server-side and real: the blind-SQLi
  lab's `/sqli/blind-submit` compares the submitted secret with `===`
  against the server-computed `adminSecret()` (modules/sqli/router.js:280-290).
  That is the pattern to generalize: the success condition is computed
  server-side from ground truth, not from client claims.

Architectural implication: any future "verified challenge" engine needs a
verification hook in the module contract (for example, each vuln declaring a
`verify(req)` predicate the shell calls before recording the capture, or the
shell owning the only path to `award()`). This is a contract addition, so it
belongs to a later phase, but the assessment must record that verification is
currently by convention, not by construction. (H9)

### 12.2 Reset behavior: four state layers, one reset procedure, no granularity

OBSERVED state layers a reset must cover:

1. **SQLite** (`data/vulnlab.db`): core tables plus per-module prefixed tables.
   Student actions INSERT rows (guestbook comments, XSS profiles, feedback,
   IDOR notes, invoices), UPDATE rows, and in SQLi labs can run arbitrary
   writes. `getDb()` only seeds on empty tables; it never repairs dirty rows.
2. **Filesystem, three write locations plus one self-healing:**
   - `uploads/` (project root): the upload module's webshell target, served
     at `/uploads`, 2mb per file via `express.raw`.
   - `modules/xss/uploads/`: the XSS module's own upload dir (module-local).
   - the misconfig module's files dir: unauthenticated `PUT
     /misconfig/files/:name` writes arbitrary files (1mb cap), tracked in an
     in-memory `uploadedFiles` Set.
   - `modules/lfi/`: `lfi_secret.conf` and `docs/lang/*.txt` are rewritten
     unconditionally at module load, so this layer self-heals on restart.
3. **express-session MemoryStore:** flags (`req.session.flags`) plus lab
   state the modules keep in the session: `user` (api module login),
   `authAttempts`, `authUser`, `issuedResets`, `enumFound` (auth module).
   Clearing flags does not log a student out of lab sessions; the two are
   independent keys in one store.
4. **Module in-memory state (dies with the process, invisible to any
   session/DB reset):** the session module's six Maps (`fixationStore`,
   `logoutStore`, `predictableStore`, `urlStore`, `legacyStore`, `leakStore`),
   the race module's `R.files` (with `setTimeout` cleanup), the hostheader
   internal agent's state.

OBSERVED reset story today:
- Full reset works: stop the process, delete `data/vulnlab.db`, empty
  `uploads/`, `modules/xss/uploads/`, and the misconfig files dir, restart.
  The DB reseeds, lfi self-heals, in-memory state is gone. (The DB
  delete-and-reseed path was listed as untested in Phase Zero; H10.)
- There is **no per-lab and no per-module reset**: no endpoint, no button,
  no contract hook. A student who pollutes one lab's state (e.g. drops the
  `users` table via SQLi, which the labs permit) must nuke everything.
- Restart alone is a partial reset: it clears layers 3 and 4 but keeps the
  dirty DB and all uploaded files. This is the worst combination for a
  confused student: progress flags vanish while the damage persists.

Architectural implication: a proper lab engine wants a `reset` hook in the
module contract (each module declares how to restore its own state layers)
plus a shell-level reset endpoint scoped per module. Until then, document the
full-reset procedure exactly (which directories, which file) because a partial
reset is actively misleading.

### 12.3 Session/flag system under the Balance Rule lens

Beyond section 4, three observations matter for the lab engine:

1. **The session module deliberately bypasses express-session.** Its six
   session implementations use custom cookies (`setSid`) and module-level
   Maps, with the fixation lab explicitly marked `// VULN:` for keeping the
   pre-login sid. This is correct lab design (the weakness is the subject),
   but it means any future migration to a durable session store would NOT
   cover the session labs. They need explicit exclusion or their own
   persistence story. (H11)
2. **The shell itself never regenerates session ids** (no
   `req.session.regenerate()` anywhere; the shell has no login at all, any
   visitor is the student). Session fixation against the flag store is
   therefore structurally possible, though only meaningful in a shared
   deployment, which the architecture already forbids.
3. **Learning-outcome tracking has no foundation today.** No timestamps on
   captures, no attempt counts, no per-student identity, no solve-duration.
   If the transformation wants learning outcomes (time-to-solve, hint usage,
   retry counts), the flag system needs an event log, not just a boolean map.
   That is a deliberate architecture decision for a later phase, recorded
   here so the redesign does not paint over it.

### 12.4 Realistic tool usage (OBSERVED)

The architecture does not fight standard tooling: plain HTTP, real forms,
no WAF, no bot checks, no CSRF tokens on most labs (the csrf module's labs
are the deliberate exception), `curl --data-binary` works against the raw
upload endpoints, Burp/ZAP proxying works because there is no certificate
pinning or header validation beyond the labs' own subjects. Two caveats:
- `saveUninitialized: true` plus no rate limiting means a student's scanner
  mints sessions freely and can trigger expensive endpoints; a fuzzer
  hammering the ReDoS endpoint with long inputs can hang the process for
  everyone on it (shared-deployment concern, section 7.2).
- The `X-Powered-By: Express` header and default error pages are the only
  fingerprinting surface; trivially removable (improvement 9.2).

### 12.5 Reference per-student deployment sketch

For the implementation plan, the isolation findings in section 7 compose
into this reference topology (all OBSERVED-derived, no new code required in
the app):

- One container per student, bridge network (never host network, so the
  hostheader 13919 loopback stays per-namespace).
- Compose per student (or one compose file parameterized per student):
  `127.0.0.1`-bound publish or, better, no published port at all with a
  reverse proxy in front carrying authentication.
- Per-student `./data` volume (never a shared sqlite file, H8).
- `USER node`, `cap_drop: ALL`, `mem_limit`/`cpus`, `restart:
  unless-stopped`, node-fetch `healthcheck`.
- Multi-stage image without compilers; `iputils-ping` retained for the cmdi
  lab (verify H5/H6 in a real build).
- Documented full-reset procedure covering all four state layers (12.2).

## 13. Open hypotheses to verify later

- H1 (Phase Zero, carried): some of the 235 vulns may be shallow or duplicated
  across modules. Needs the lab quality matrix (Phase Five).
- H2 (Phase Zero, carried): the `race` module may behave nondeterministically
  under load. Needs a concurrency test.
- H3 (Phase Zero, carried): session/cookie weaknesses are intentionally weak
  for cookie-stealing demos; confirm each is marked `// VULN:` and covered by
  a session-module lab. (`httpOnly: false` is marked; fixation coverage
  unconfirmed.)
- H4 (new): which of the 21 async handlers can crash the process with a
  malformed request. Needs a fault-injection sweep per module.
- H5 (new): does `npm ci` on `node:20-slim` use the better-sqlite3@11
  prebuild (no compilers needed)? Needs a real `docker build` (no daemon on
  this VM; verify on the maintainer's machine).
- H6 (new): does the cmdi `ping` lab still work as the `node` user inside the
  container (file capabilities on iputils-ping)? Verify after the USER change.
- H7 (new): per-student bridge-networked containers do not collide on the
  hostheader module's fixed 127.0.0.1:13919 (loopback is per net namespace).
  Verify with two containers.
- H8 (new): sharing one sqlite file between containers via `DB_PATH` risks
  locking corruption; recommend one DB per container and verify only if
  attempted.
- H9 (new): no module currently calls award() without a genuine exploit check,
  but nothing enforces it; a contract-level verification hook would be needed
  for trustworthy challenge verification (12.1).
- H10 (new): the full reset procedure (delete DB, empty the three upload
  dirs, restart) restores all four state layers, but the DB delete-and-reseed
  path has not been tested end to end (12.2).
- H11 (new): the session module's custom session Maps bypass express-session,
  so a future durable session store migration would not cover the session
  labs; they need explicit exclusion or their own persistence story (12.3).
