# INITIAL_TEST_RESULTS: PenTrix VulnLab (Phase Zero)

Date: 2026-10-19. Environment: this assistant's Linux VM (no Docker available).

## Baseline: does it run?

| Check | Result |
|---|---|
| `git clone` | OK (5.24 MiB, 1893 objects) |
| `git status` | clean tree, `main`, 5 commits |
| `npm ci --omit=dev` (Node 24.20.0) | FAILED first: better-sqlite3@11.10.0 has no Node 24 prebuild; node-gyp rebuild failed with `EPERM: fchown` extracting headers in this sandbox |
| Workaround | manually extracted Node headers with `--no-same-owner` to `~/.cache/node-gyp/24.20.0`, then `npm_config_nodedir=... npm ci` -> OK, 140 packages |
| Boot `node app.js` (better-sqlite3@11) | CRASH: assertion in `RemoveEnvironmentCleanupHook` (better-sqlite3 v11 does not support Node 24) |
| Boot with better-sqlite3@12.11.1 (in /tmp/pentrix-verify copy, NOT in the repo) | OK: all 29 modules mounted, listening on :3000 |

Note: the repo itself is untouched (still pins better-sqlite3 ^11.10.0, correct
for its Node 20 Docker target). The v12 swap exists only in the throwaway
verify copy.

## Live HTTP checks (all against the local verify instance)

| Check | Result |
|---|---|
| `GET /` | 200, 29 module cards rendered |
| `GET /scoreboard` | 200 |
| `GET /about` | 200 (not curled in detail yet) |
| `GET /sqli` | 200, briefing + vuln table |
| `GET /sqli/login` | 200, form fields `username`, `password` |
| `POST /sqli/login` with `admin' OR '1'='1' -- ` | REAL EXPLOIT VERIFIED: logged in as admin, response contained `PENTRIX{sqli_login-bypass}` |

## Exploit validation method

Session cookie jar (`curl -c/-b`) used across requests, proving the flag award
is tied to a real session and the scoreboard path works. This is the minimum
bar for every lab (Rule 2): no fake gates.

## Not yet tested (scheduled)

- Remaining 28 module index pages (scripted curl sweep).
- At least one exploit per module (sample-based, prioritizing high-value labs).
- `race` module under concurrent load.
- DB reset/rebuild path (`rm data/vulnlab.db` -> reboot reseeds).
- Static asset serving (`/style.css`, `/uploads/*`).
- The user's own Docker run on Windows (cannot reach his localhost:3000 from
  this VM; he confirms that side).

## Environment limits (honest)

- No Docker on this VM, so the exact `docker compose up --build` path is not
  reproducible here. The Dockerfile was reviewed line by line instead.
- No browser automation was used in Phase Zero; visual verification of the
  current UI is pending (screenshots to come with the redesign).
- Node version skew (24 here vs 20 in Docker) is documented above and contained
  to the verify copy.
