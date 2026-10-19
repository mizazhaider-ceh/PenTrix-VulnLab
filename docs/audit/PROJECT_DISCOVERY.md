# PROJECT_DISCOVERY: PenTrix VulnLab (Phase Zero)

Date: 2026-10-19. All facts below were observed directly (code, git, live run).
Hypotheses are marked as such.

## What it is

Intentionally vulnerable web app for security training. Students pick a module,
exploit real vulnerabilities, capture flags (random `PENTRIX{...}` per deployment,
generated at first boot on the student's machine), track
progress on a scoreboard. Marked everywhere: run locally only, never public.

## Stack (observed, not assumed)

- Runtime: Node 20 (Dockerfile `node:20-slim`) / verified working on Node 24 with
  better-sqlite3 v12 (see INITIAL_TEST_RESULTS.md).
- Backend: Express 4.19.2, server-rendered HTML via template strings in
  `lib/page.js`. No view engine, no frontend framework, no build step.
- Database: better-sqlite3 (SQLite file at `data/vulnlab.db`, committed to repo,
  147456 bytes). Seeded in `lib/db.js` plus per-module prefixed tables.
- Deps: cookie-parser, express-session (MemoryStore), jsonwebtoken, multer.
  Total: 140 packages installed.
- Frontend: one 83-line stylesheet (`public/style.css`), dark theme via CSS vars.
  No JS framework, no client-side JS at all (grep confirms zero script tags
  outside inline challenge pages; to be verified per module).

## Structure

- `app.js` (124 lines): middleware, session, static files, auto-mounts every
  `modules/<id>/router.js` at `/<id>`, home page, scoreboard, about page.
- `modules/`: 29 modules, each one `router.js` exporting
  `{ id, name, tagline, description, difficulty, vulns[], router }`
  per `MODULE_CONTRACT.md`. 15,262 lines total across routers + app + lib.
- `lib/`: `db.js` (77), `flags.js` (18), `page.js` (41).
- `data/vulnlab.db`: committed seeded database. `.gitignore` lists `data/` but
  the file is tracked anyway (force-added at some point).
- `uploads/`: contains `.gitkeep`, `avatars/`, and `shell.php.jpg` holding
  `<?php echo 1; ?>` (seeded webshell sample for the upload module).
- `SOLUTIONS.md` (132 KB) + `solutions/batch-01..12.md`: full walkthroughs.
- `README.md`: claims "235 intentionally vulnerable challenges across 29 modules".
  CORRECTION (Phase One, verified twice independently via node probe summing
  `vulns.length` and via the live scoreboard): the code exports 235 vulns.
  The earlier "244 by hint-count" was a grep overcount (lfi has 10 vulns, not
  20). The README figure is correct.

## Module inventory (observed vuln counts)

api:11 auth:11 bizlogic:8 cmdi:10 cors:6 crypto:8 csrf:11 csti:5 formula:4
hostheader:6 http:6 idor:11 jsonp:5 jwt:8 lfi:10 misconfig:11 oauth:8 postmsg:5
proto:6 race:8 redirect:6 redos:4 session:6 sqli:12 ssrf:10 ssti:10 upload:10
xss:11 xxe:8 = 235 total. 280 `// VULN:` markers in code (markers exceed vulns;
some mark helper code, not separate challenges).

## Docker / deployment (observed)

- `Dockerfile`: node:20-slim, installs python3/make/g++/iputils-ping for
  better-sqlite3 build, `npm ci --omit=dev`, exposes 3000.
- `docker-compose.yml`: one service `vulnlab`, `3000:3000`, volume
  `./data:/app/data`, `PORT=3000`.
- No healthcheck, no resource limits, no restart policy, no networks defined.

## Git state (observed)

- 5 commits on `main`, working tree clean at discovery time.
- History: v1 (13 modules, 34 challenges) -> "200+ new labs" -> "Remove committed
  node_modules". No branches, no tags, no CI config.

## Seed data (observed in lib/db.js)

- users: admin/admin123 (role admin, secret random per deployment),
  alice/alice123, bob/bob123. Weak creds are intentional per code comment.
- products, orders, comments, reset_tokens tables.

## What was NOT found

- No tests, no lint config, no CI.
- No API docs beyond MODULE_CONTRACT.md.
- No auth on the app itself (any visitor is the "student"; progress is per
  browser session).
- No .env file or env template; PORT and DB_PATH are the only env vars read.
