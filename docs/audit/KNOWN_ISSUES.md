# Known issues (fresh audit, 2026-10-19)

Status tags: **VERIFIED** = observed on a running instance or in the code this
session; **STATIC** = read in code/config but not exercised; **OPEN** = not yet
investigated. Earlier docs in `docs/audit/` and `docs/roadmap/` were treated as
leads only.

## Verified baseline

| Check | Result | Evidence |
|---|---|---|
| Docker image builds (Node 20, better-sqlite3 11) | VERIFIED | `docker build` of the repo Dockerfile, 366 MB image |
| Boot: 29 modules / 201 challenges / 201 flags generated | VERIFIED | container log; matches the 201/29 target |
| `/`, `/scoreboard`, `/about`, `/sqli`, `/sqli/login` return 200, unknown path 404 | VERIFIED | curl against isolated container on 127.0.0.1:3100 |
| SQLi login bypass (`admin'--`) awards the flag, scoreboard 1/201, repeat does not double count | VERIFIED | curl with cookie jar, then `tests/platform.test.js` |
| Flags are random per deployment, no flag-shaped literal in tracked files | VERIFIED | `tests/platform.test.js` |
| No flag shown on any normal GET of `/`, `/scoreboard`, `/about`, or a module index | VERIFIED | `tests/platform.test.js` |

The audit used a separate container and temp data directory. The owner's
running `dvws-node` containers were not touched.

## Issues

| ID | Severity | Status | Issue |
|---|---|---|---|
| KI-1 | High | FIXED this session | Progress (captured flags) lived in express-session `MemoryStore`: a restart reset every student to 0/201, while the 500 page claimed "Your progress is safe". Now stored in `data/sessions.db` (`lib/session-store.js`); covered by the restart test. |
| KI-2 | Low | FIXED this session | `/about` told students the flag format was `PENTRIX{module_challenge}`; real format is `PENTRIX{<32 hex>}`. |
| KI-3 | Medium | FIXED this session | README claimed each challenge lives in `modules/<id>/challenges/`. Actual: one `router.js` per module (the split is only specified). README corrected. |
| KI-4 | High | OPEN | **Only 1 of 201 challenges has an automated end-to-end exploit test.** Challenge authenticity (exploit works, bypass fails, flag only on success) is unproven for the other 200. About 70 declared challenges (SSRF, XSS claim flow, cmdi, ssti, ...) award through helper or variable ids, so a static scan cannot prove an award path; they need runtime tests. |
| KI-5 | Medium | STATIC | Progress is per browser session only: no accounts, no identity, no per-student reset. Clearing cookies loses progress; the scoreboard is not a ranking. |
| KI-6 | Medium | STATIC | Session secret fallback is committed (`app.js`); with `SESSION_SECRET` unset, cookies can be forged. Acceptable for a local lab, wrong for grading. |
| KI-7 | Medium | STATIC | Compose has no isolated network and no outbound restriction. The SSRF, cmdi (`ping`), and XXE modules run in a container that can reach the internet and the host network gateway. |
| KI-8 | Low | STATIC | Compose lacks `read_only`, `no-new-privileges`, `pids_limit`. `cap_drop: ALL`, localhost-only binding, non-root user, CPU/memory limits are present. |
| KI-9 | Low | VERIFIED | `better-sqlite3@11` does not install/run on Node 24 (host). Tests and the app must run on Node 20 (Docker image). |
| KI-10 | Medium | OPEN | No browser-rendered UI audit yet (desktop/tablet/mobile, focus, reduced motion). Earlier docs used a WeasyPrint static render pipeline only. |
| KI-11 | Low | OPEN | `docs/roadmap/PROGRESS.md` previously described the project as awaiting Phase One review while git history shows M3-M7 merged; reconciled in this session. |
| KI-12 | Info | OPEN | `docs/qa/shots/` holds several MB of PNG/PDF/HTML artifacts committed to git. |

## Retain / repair / rebuild (initial view)

- **Retain:** loader contract and reserved-id checks, per-deployment random flags, claymorphism shell, `award()` server-side flow, Compose hardening basics.
- **Repair next:** KI-4 (exploit test coverage, module by module), KI-7 (lab network isolation), KI-10 (browser UI audit).
- **Not started:** challenge file split, fix/remediation mode, scenarios, learning-path enforcement.
