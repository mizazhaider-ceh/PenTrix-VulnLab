# PenTrix-VulnLab: Code Quality Audit (Infrastructure)

**Date:** 2026-10-20
**Scope:** lab infrastructure only (session handling, flag awarding plumbing, error handling, routing, fix-mode sandbox, test coverage, robustness under load). The deliberately planted challenge vulnerabilities were NOT treated as defects.
**Method:** static review of `app.js`, `lib/*`, `modules/*/index.js`, `modules/*/shared.js`, sampled challenge files, `scenarios/`, `paths/`, `tests/` (static mapping, suite not executed), plus live behavior probes against the test instance at `http://127.0.0.1:18406/` and a controlled sandbox-escape experiment in a scratch Node process.
**Doctrines respected:** no code changed, nothing pushed, no flag storage details disclosed, no em dashes used.

**Headline:** the core contracts hold up well (all 155 award calls target registered challenges, every flag display is gated on capture, the fix-mode sandbox resists code escape). The serious problems are all about shared-classroom robustness: global mutable lab state shared across students, fix-mode CPU/memory denial of service, and a missing process-level safety net on Node 24.

---

## 1. Architecture compliance

### Finding A1 (Medium): six modules keep challenge-critical routes in `index.js` instead of per-challenge files

**Severity:** Medium
**Location:** `modules/oauth/index.js` (399 lines), `modules/cors/index.js:161-233` (`/prove`), `modules/csti/index.js:66-90` (`/beacon`), `modules/hostheader/index.js:108-130` (`/evil-collect`), `modules/jsonp/index.js:27-50` (`/beacon-xss`), `modules/postmsg/index.js:30-70` (`/beacon`)

**Description:** MODULE_CONTRACT.md rule 4 says "All logic lives in your challenge files" and describes `index.js` as a "thin aggregator". Six modules instead implement shared verifier/beacon/IdP endpoints directly in `index.js`, including routes that call `award()` (`cors/index.js:212`, `csti/index.js:75`, `hostheader/index.js:116`, `jsonp/index.js:33`, `postmsg/index.js:58`, `oauth/index.js:119,157,176,234`). The pattern is understandable (one beacon endpoint per module avoids duplicating nonce-verification logic in five files), but it means the highest-risk code in the system, the code that mints flags, lives exactly where the contract says it should not.

**Evidence:** `modules/oauth/index.js` is 399 lines and contains the full IdP (`/idp/authorize`, `/idp/token`, `/idp/userinfo`) plus four separate `award()` call sites. The automated structural check I ran (every `index.js` exports the required shape, every challenge file exports `{vuln, router}`, filename matches `vuln.id`) passes with 0 issues, so this is a contract-spirit violation, not a shape violation.

**Recommendation:** keep the shared verifier endpoints but move them into `modules/<id>/shared.js` (as exported route-registration functions) so `index.js` stays a thin aggregator and all award-adjacent logic is in one auditable place per module. At minimum, add a contract rule: "any route that calls `award()` must live in `challenges/` or `shared.js`, never inline in `index.js`", plus a lint check that greps `index.js` files for `award(`.

### Finding A2 (Low): 20 of 201 challenge files lack the required `// VULN:` marker

**Severity:** Low
**Location:** `modules/api/challenges/exposure.js`, `modules/cmdi/challenges/basic.js`, `modules/jwt/challenges/weak-secret.js`, `modules/lfi/challenges/traversal.js`, `modules/oauth/challenges/code-leak.js`, `code-replay.js`, `implicit.js`, `no-state.js`, `pkce-skip.js`, `redirect-bypass.js`, `secret-in-js.js`, `modules/postmsg/challenges/data-xss.js`, `substring.js`, `modules/race/challenges/race-upload-scan.js`, `modules/redos/challenges/redos-email.js`, `redos-url.js`, `redos-username.js`, `modules/ssrf/challenges/ssrf-hex-ip.js`, `ssrf-octal-ip.js`, `ssrf-zero-ip.js`

**Description:** Contract rule 3 requires every vulnerability to be marked with `// VULN:`. 20 files have no such marker (some park the marker in `shared.js` or `index.js` instead, e.g. the oauth set, but several like `lfi/challenges/traversal.js` have it nowhere near the flaw). Students study these files after solving; unmarked flaws defeat the purpose.

**Evidence:** scripted grep over all 201 challenge files; 20 missing.

**Recommendation:** add a CI/test check: every file under `modules/*/challenges/*.js` must contain `VULN:`. The platform test already boots the app; a 10-line static assertion fits there.

### Positive (architecture)

No legacy `router.js` files remain; the `app.js` fallback branch is dead code but harmless. The fail-fast boot checks in `app.js` (module id regex, reserved ids, duplicate ids) are good. The structural audit (exports shape, vuln id registry consistency) passes cleanly.

---

## 2. Flag award integrity

### Positive: award plumbing is sound

* Scripted check over all 155 `award(req, '<mod>', '<vuln>')` call sites: every target pair is registered in the module registry or the scenario list. Zero dangling award targets, so no flag can be minted for a challenge that does not exist on the scoreboard.
* Every `flagFor()` display path is gated by `captured()` (or an equivalent `done` flag): `modules/http/challenges/cache-deception.js:34,80`, `modules/lfi/shared.js:145-149`, `modules/api/challenges/exposure.js:37-39`, `modules/auth/index.js:27-29`, `scenarios/index.js:108-114`. No code path renders a flag on a plain page view.
* `award()` in `lib/flags.js:14-18` is idempotent (sets a session boolean, returns the issued value), so double submission cannot double count. `awardFixBadge()` in `lib/fixbadges.js:30-41` uses `INSERT OR IGNORE` on a `(user_key, module, vuln_id)` primary key, so badges cannot double award either.
* Scenario completion (`scenarios/index.js:104-114`) awards only when every stage flag is already captured, and re-renders via read-only `flagFor()` on revisit. No re-award path.
* The beacon/nonce pattern (`csti`, `jsonp`, `postmsg`) correctly requires a single-use page-bound token echo before awarding, so a bare GET to the beacon cannot mint a flag.

### Finding F1 (Low): `flagFor()` throws on unregistered pairs, turning a data problem into a 500

**Severity:** Low
**Location:** `lib/flags.js:8-13`

**Description:** `flagFor()` throws `no flag registered for ...` when the pair is missing. Any caller that reaches it with a bad pair (today: none, per the scripted check) produces a 500 instead of a graceful error. This is a latent landmine for future modules.

**Evidence:** all current call sites are consistent, so this is defensive only.

**Recommendation:** return `null` and let callers render "flag unavailable", or keep the throw but add a boot-time assertion that every `flagFor`/`award` literal pair in the codebase exists in the registry (cheap static test).

---

## 3. Session and scoreboard correctness

### Finding S1 (Medium): shipped deployment config leaves the session signing secret at the public insecure fallback

**Severity:** Medium
**Location:** `app.js:30` (fallback value), `docker-compose.yml:15` (`SESSION_SECRET` commented out)

**Description:** The code documents that the fallback secret is "committed and insecure by design" and warns at boot, which is honest. But the shipped `docker-compose.yml` leaves `SESSION_SECRET` commented out, so the default deployment path (the one a teacher will actually use for 30 students) runs with a publicly known signing secret. Session integrity matters here: captured flags live in the session. Combined with the deliberately non-`httpOnly` cookies (`app.js:55-56`, documented as an XSS-demo requirement), any student who completes the cookie-stealing challenge against a classmate can mint valid signed session cookies for the victim's session id with the known secret. That is cross-student progress theft/hijack with zero exploit sophistication beyond the intended lab exercise.

**Evidence:** `docker-compose.yml:15` shows the variable commented out; `app.js:42-44` prints the warning but boots anyway.

**Recommendation:** generate a random secret at first boot and persist it next to the other local data when `SESSION_SECRET` is unset (same pattern as the install id in `lib/db.js`), instead of falling back to a constant. Keep the warning. This preserves the "just run it" UX while making the default deployment safe for shared use.

### Finding S2 (Medium): `saveUninitialized: true` plus purge-only-at-boot grows the session store without bound

**Severity:** Medium
**Location:** `app.js:39`, `lib/session-store.js:37`

**Description:** Every new visitor gets a session row, including unauthenticated curl probes, bots, and every first static-asset hit (the session middleware runs before `express.static`). Expired rows are deleted only in the `SqliteStore` constructor, i.e. at process boot. Between restarts the store grows monotonically. For 30 students this is slow, but a classroom NAT with scanners (or students hammering with fresh curl sessions) can bloat it meaningfully, and each row carries a full serialized session.

**Evidence:** `this.stmts.purge.run(Date.now())` runs once in the constructor; no interval, no `SET`/`touch`-triggered cleanup.

**Recommendation:** set `saveUninitialized: false` (no login-less state needs persisting before first capture; the fix-badge and flag flows both write to the session, which then saves), and run the purge on a timer (e.g. hourly) or lazily on a small probability per `set()`.

### Positive (scoreboard)

`totals()`/`moduleProgress()` in `app.js` count each registered vuln exactly once; scenarios are tallied separately, so no double counting between the two systems. `captured()` is a pure session read, no side effects.

---

## 4. Error handling

### Finding E1 (High): no `unhandledRejection` handler on Node 24; a throw inside any `async` route handler crashes the whole lab

**Severity:** High
**Location:** `app.js` (no handler registered; verified Node v24.20.0, where the default is `throw`), e.g. `modules/race/challenges/race-ratelimit.js:61`, `race-coupon.js:53`, `race-stock.js:62`, `race-balance.js:66`, `race-vote.js:63`, `race-referral.js:60`, `race-register.js:71` (zero `try/catch` in these handlers)

**Description:** Express 4 does not catch rejected promises from async handlers. Every `async (req, res)` handler without its own `try/catch` is a potential process killer: any synchronous throw after the first `await` (for example, the backend read inside `award()` failing if its backing file is missing, locked, or corrupt) becomes an unhandled rejection, and Node 24's default `unhandled-rejection=throw` terminates the process. All 30 students lose the lab until someone restarts it. The well-audited handlers (`jwt/jku.js`, `hostheader/host-ssrf.js`, `ssrf/*`, `cors/prove`) wrap their awaits; the seven race handlers do not wrap anything.

**Evidence:** grep for `unhandledRejection`/`uncaughtException` across `app.js`, `lib/`, `modules/`, `scenarios/`, `paths/` returns nothing. `race-ratelimit.js` contains 0 occurrences of `try`.

**Recommendation:** add an `asyncHandler` wrapper (or a tiny middleware) applied to every async route, forwarding rejections to the existing 500 handler in `app.js`. Belt and braces: register `process.on('unhandledRejection')` to log loudly without crashing (acceptable for a lab; crashing is worse).

### Finding E2 (Low): oversized request bodies return 500 instead of 413

**Severity:** Low
**Location:** `app.js:33` (`express.json()` with default 100kb limit)

**Description:** Verified live: `POST /jwt/jku` with a 200KB JSON body returns the generic 500 page ("Something broke"). The process survives (no crash), but a 500 for a client error is misleading and the error page tells the student to restart the lab, which is the wrong advice.

**Evidence:** live probe returned HTTP 500 with `<title>Error</title>`; the error handler in `app.js` catches the `entity.too.large` error.

**Recommendation:** add an error-handling branch for `err.type === 'entity.too.large'` (and `err.status === 413`) that returns 413 with a plain message. Same for the urlencoded parser.

### Positive (error handling)

The 404 and 500 handlers render inside the page shell and never leak stack traces. XXE entity resolution (`modules/xxe/shared.js:18-53`) converts every failure mode (bad file, bad URL, timeout, unsupported scheme) into a string, so the async XXE handlers cannot throw from entity expansion. `cmdi`'s `exec` has an 8s timeout (`modules/cmdi/shared.js:25`).

---

## 5. Fix-mode sandbox (`lib/fixmode.js`)

### Positive: realm isolation is sound; I could not escape it

I replicated the exact `makeSandbox()` construction (`vm.createContext(Object.create(null))`, no host intrinsics, bootstrap-defined neutered `console`) and ran the standard escape battery: `typeof process` is `undefined`; `this.constructor.constructor('return process')()`, `vulnFn.constructor.constructor('return process')()`, and `console.constructor.constructor('return process')()` all throw `process is not defined` because the `Function` constructor chain stays inside the guest realm. The `// VULN:`-style comment terminator (`'\n;(' + expression + ')'`) correctly neutralizes trailing line comments in student code. Error messages are student-safe (no host paths leak through `friendlyRunError`). `safeId()` gating on `getFixBlock()` blocks path traversal via `/fix/:module/:vuln`. This part of the design is genuinely good.

### Finding X1 (High): no memory cap; student code can OOM-kill the lab for everyone

**Severity:** High
**Location:** `lib/fixmode.js:20-21`, `lib/fixmode.js:72-100` (`runCodeAndExpression`)

**Description:** `RUN_TIMEOUT_MS` caps CPU at 2s per run, and `CODE_SIZE_LIMIT` caps source at 50KB, but nothing caps heap allocation. Inside the 2s budget a submission can allocate gigabytes (`let a=[]; while(true) a.push(Buffer.alloc(1<<20))` style, or plain array growth), and `node:vm` offers no memory limit. An OOM kills the Node process outright: no graceful degradation, all 30 students disconnected, no per-request isolation. This is reachable from an unauthenticated POST to `/fix/:module/:vuln/test`.

**Evidence:** code inspection; `vm.Script`/`runInContext` accept no memory option, and no `worker_threads` or cgroup guard exists.

**Recommendation:** run student code in a `worker_threads` worker with `resourceLimits: { maxOldGenerationSizeMb, maxYoungGenerationSizeMb }` and terminate the worker on timeout/OOM. That gives a real memory ceiling plus CPU isolation (a worker spinning also stops blocking the main event loop, which addresses X2 as well). Short-term mitigation: rate-limit `/fix/*/test` per IP/session.

### Finding X2 (High): each submission can block the event loop for ~6s; validation is needlessly repeated

**Severity:** High
**Location:** `lib/fixmode.js:237-300` (`testFix`), `lib/fixmode.js:200-234` (`validateBlock`)

**Description:** `testFix()` calls `validateBlock(block)` on EVERY student submission, which executes the (trusted, unchanging) vulnerable code three times (`definesVulnFn`, `testExploit`, `testLegit`). It then runs the student's code three more times, each with a 2s budget. Crafted-but-valid student code (e.g. a busy loop just under the timeout inside `vulnFn`) burns close to 2s per run, so one POST can hold the single-threaded event loop for roughly 6s doing nothing useful. Verified live: an infinite-loop submission took 2.047s (it fails fast at `definesVulnFn`, so the worst case needs code that defines `vulnFn` and burns time per invocation). Thirty students pressing "Test my fix" in a loop is a trivial, unauthenticated DoS against the whole classroom.

**Evidence:** live timing (`time curl ... /fix/sqli/login-bypass/test` with `while(true){}` → 2.047s, message "took too long to run (over 2 seconds)"); code path analysis for the 6-run worst case.

**Recommendation:** cache `validateBlock()` results per block key (block files do not change at runtime; `resetFixCache()` already exists for tests). Collapse the three student-code runs where possible, or at minimum enforce a per-session concurrency limit of 1 and a per-minute rate limit on the test endpoint. The worker-thread move from X1 fixes the event-loop blocking too.

---

## 6. Test gaps

Coverage is genuinely broad (43 files, ~394 test blocks, all 29 modules exercised, platform inventory + flag-format + exploit-to-scoreboard journey in `tests/platform.test.js`). The gaps are all in adversarial and failure paths:

### Finding T1 (Medium): zero assertions on 500 paths; thin 4xx coverage

**Severity:** Medium
**Location:** `tests/` (all files)

**Description:** Not a single test asserts an HTTP 500, and only 7 of 43 test files assert any 4xx status. The error-handling findings above (E1, E2) survive precisely because the suite never exercises failure: oversized bodies, malformed JSON, backend-unavailable behavior, and the 404/500 shell pages are untested.

**Recommendation:** add a `platform-errors.test.js`: oversized JSON → 413 (after E2 fix), malformed JSON → 400/500-without-crash, unknown route → 404 shell, `/fix/nope/nope` → 404, and (with a temp data dir) missing-backend behavior.

### Finding T2 (Medium): no concurrency tests, despite a race-condition module and shared global state

**Severity:** Medium
**Location:** `tests/race.test.js`, `modules/race/shared.js`

**Description:** The race module's entire subject is concurrency, yet tests run sequentially. Nothing asserts behavior under parallel requests, and nothing pins the (currently broken, see P1) cross-student isolation.

**Recommendation:** add parallel-burst tests using `Promise.all` over the existing client (10-20 concurrent POSTs to `/race/coupon/redeem`), asserting the flag is awarded. Add a two-client test asserting one client's `/race/reset` or coupon redemption does not corrupt the other's session view (this test will fail until P1 is fixed, which is the point).

### Finding T3 (Low): fix-mode tests do not cover adversarial runner input

**Severity:** Low
**Location:** `tests/fixmode*.test.js`

**Description:** The fix-mode suites test the happy path and broken-code feedback, but not infinite loops (timeout path), 51KB+ payloads (size cap), non-string input, or memory-hungry code. The DoS findings X1/X2 have no regression coverage.

**Recommendation:** add adversarial cases: `while(true){}` → friendly timeout message and response time < ~3s; 60KB code → size error; allocation-bomb code → process survives (after X1's worker isolation lands).

---

## 7. Performance and robustness (30 concurrent students)

### Finding P1 (High): race module state is global across all students; `GET /race/reset` wipes everyone's lab

**Severity:** High
**Location:** `modules/race/shared.js:23` (`let R = freshState()`), `modules/race/shared.js:25-29` (`state()` returns the global), `modules/race/index.js:22-27` (`GET /race/reset`)

**Description:** Every race challenge reads and writes one module-global object: coupon usage, balances, ledgers, votes, referrals, stock, rate-limit counters. Student A redeeming the coupon sets `coupon.used = true` for student B. Student B's legitimate sequential testing then sees "Already redeemed". Worse, `GET /race/reset` is an unauthenticated, CSRF-able link (it is rendered as a plain anchor on every race page, `shared.js` `backLink`) that resets the global state for all 30 students at once. One bored student with `<img src="http://lab:3000/race/reset">` on a page, or a loop of curl, can keep the entire classroom's race module permanently broken.

**Evidence:** code inspection; `race-coupon.js:56` checks the global `shared.state().coupon.used`; `race-ratelimit.js:65` checks the global counter.

**Recommendation:** scope race state per session (`req.session.race = req.session.race || freshState()`), which also makes `/race/reset` per-student and safe. If a global reset is wanted for teachers, put it behind a POST with a token, not a GET link.

### Finding P2 (Medium): `hostheader` internal agent binds a fixed port at require time; silent degradation on conflict

**Severity:** Medium
**Location:** `modules/hostheader/challenges/host-ssrf.js:32-50`

**Description:** Requiring the module starts an HTTP server on `127.0.0.1:13919`. The error handler logs and continues (no crash, good), but if the port is taken the challenge silently degrades to "agent failed to start". Requiring modules also has side effects in general (my own audit script hit `EADDRINUSE` just by loading the module set). A fixed port also collides if two lab instances run on one box.

**Evidence:** observed `[hostheader] internal agent could not start: listen EADDRINUSE` during a read-only audit.

**Recommendation:** bind port 0 and expose the actual port to the challenge (or derive it from config), and fail the health-check page loudly rather than rendering a confusing half-working lab. At minimum, document that the port must be free.

### Finding P3 (Low): uploads accumulate on disk with no quota or cleanup

**Severity:** Low
**Location:** `modules/upload/shared.js:11` (2MB per-file cap), `app.js:56` (served statically), `uploads/` (132KB already, gitignored)

**Description:** The 2MB per-file cap is good, but there is no per-student quota, no expiry, and no cleanup job. Thirty students uploading repeatedly (the traversal challenge encourages writing outside the intended dir, and its test artifacts `sb-escape.txt` / `trav-escape.txt` are currently committed at the repo root, see P4) will grow the directory indefinitely. Low risk on a lab VM, but worth a periodic sweep.

**Recommendation:** cron or boot-time sweep deleting files older than N days; keep an allowlist for seeded fixtures.

### Finding P4 (Low): test artifacts committed to the repo root

**Severity:** Low
**Location:** `sb-escape.txt`, `trav-escape.txt` (repo root)

**Description:** These are outputs of `tests/upload.test.js:136,203` (the traversal challenge writes outside `uploads/` by design). They were committed instead of cleaned up. `trav-escape.txt` containing "escaped-by-test" in the repo root looks alarming out of context and suggests the traversal test escaped its sandbox at some point.

**Recommendation:** delete both files, add them (or `*-escape.txt`) to `.gitignore`, and make the test clean up after itself.

### Notes (by design, no action required)

* The ReDoS challenges intentionally block the event loop; that is the lesson. In a 30-student classroom, mention that one student's ReDoS demo pauses everyone for a few seconds.
* `cmdi` `exec` has an 8s timeout (`modules/cmdi/shared.js:25`); concurrent injections can pile up child processes but each is reaped on timeout.
* `express-session` `touch()` issues a write per request; with WAL mode this is fine for 30 students.

---

## Top-10 prioritized list

1. **P1 (High):** race module global state shared across students + CSRF-able `GET /race/reset`. Scope state per session; make reset a POST.
2. **X1 (High):** fix-mode runner has no memory cap; student code can OOM-kill the lab. Isolate in `worker_threads` with `resourceLimits`.
3. **X2 (High):** fix-mode submissions can block the event loop ~6s each; `validateBlock()` re-runs per submission. Cache validation; rate-limit the endpoint (worker isolation also fixes this).
4. **E1 (High):** no `unhandledRejection` handler on Node 24; unguarded `async` handlers (all seven race handlers) can crash the process. Add an async-handler wrapper + process-level logging.
5. **S1 (Medium):** `docker-compose.yml` ships with `SESSION_SECRET` commented out, so real deployments use the public fallback secret. Generate and persist a random secret on first boot.
6. **S2 (Medium):** `saveUninitialized: true` with purge-only-at-boot grows the session store unboundedly. Set `saveUninitialized: false`; purge on a timer.
7. **T1 (Medium):** zero tests assert 500 paths; only 7/43 files check 4xx. Add `platform-errors.test.js`.
8. **T2 (Medium):** no concurrency tests for the race module. Add parallel-burst and two-client isolation tests.
9. **P2 (Medium):** fixed-port internal agent (`127.0.0.1:13919`) bound at require time; silent degradation on conflict. Bind port 0 or make it configurable.
10. **A1 (Medium):** six modules implement award-adjacent verifier routes in `index.js` against the contract's "thin aggregator" rule. Move to `shared.js`; lint `index.js` for `award(`.

Honorable mentions (Low): A2 (20 files missing `// VULN:` markers), E2 (oversized bodies return 500 not 413), F1 (`flagFor()` throws instead of returning null), T3 (no adversarial fix-mode tests), P3 (upload disk growth), P4 (committed `sb-escape.txt`/`trav-escape.txt`).

## What is solid

For balance: the per-challenge-file architecture is fully realized (29/29 modules, 201/201 challenges, no monolithic leftovers at the file level), the flag award plumbing survived an aggressive scripted audit (155/155 award targets registered, all display paths capture-gated, idempotent awarding), the fix-mode sandbox genuinely resists code escape (verified experimentally), error pages never leak stacks, and the test suite's breadth (inventory, flag format, exploit-to-scoreboard journey) is well above average for a lab of this kind. Fix the ten items above and this is classroom-ready for 30 concurrent students.
