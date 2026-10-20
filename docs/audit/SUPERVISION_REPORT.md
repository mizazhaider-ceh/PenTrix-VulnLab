# Supervision Report: PenTrix-VulnLab Improvement Wave

Date: 2026-10-20. Scope: independent verification of the improvement wave working tree at `~/workspace/pentrix-vulnlab/` (git main, 263 files changed vs HEAD: 242 tracked files modified, 21 new untracked files), driven by `docs/roadmap/STUDENT_REVIEW_BACKLOG.md`.

Method: the current tree was snapshotted into `~/workspace/pentrix-verify/` (synced copy with the Node 24 compatible node_modules) so live testing ran against a stable state, insulated from the improvement team's ongoing edits. Three senior experts worked in parallel and read-only: a pentest reviewer, a code reviewer, and QA. No product code was edited by the supervision team and nothing was pushed.

## 1. Senior Pentest Reviewer

Setup: lab booted from the snapshot on Node 24 at `http://127.0.0.1:19399` with a throwaway database; all 29 modules mounted; server killed by PID after testing and the port confirmed free. Award evidence throughout: per-session scoreboard capture set (before and after diff) plus presence or absence of the award banner in responses. Every item was tested in both directions: the confirmed cheat must fail, the genuine intended exploit must still succeed.

| # | Item | Verdict |
|---|------|---------|
| 1 | XXE literal-marker award (module xxe) | PASS |
| 2 | Beacon nonce forging via curl (xss, csti, jsonp sampled) | PASS, one advisory (see below) |
| 3 | CSRF self-request award (module csrf) | PASS |
| 4 | Upload stored-XSS award at upload time (module upload) | PASS |
| 5 | CMDI quoted-echo spoof (module cmdi) | PASS |
| 6 | LFI bare-percent check (module lfi) | PASS |
| 7 | Host-header SSRF marker check (module hostheader) | PASS |
| 8 | Race reset isolation (module race) | PASS |
| 9 | Prototype pollution scope (module proto) | PASS |
| 10 | Alice silent admin promotion (module idor) | PASS |

Details per item:

1. XXE: `POST /xxe/import` with the marker typed literally (no entity declaration) awarded nothing; a variant whose internal entity merely expands to the literal marker text also awarded nothing. A genuine external-entity file read captured the XXE File Read challenge, and the HTTP entity variant captured the SSRF via XXE challenge. The award check now requires proof of entity resolution: marker present in expanded output, absent from raw input, entity declaration present.
2. Beacon forging: the raw token no longer appears in page HTML (only two XOR share arrays are served). Bare beacon hits, hits with a scraped share pasted as the token, and hits with a guessed token all returned HTTP 400 with zero captures across xss reflected, csti basic, and jsonp callback-xss. Genuine in-context execution (page scripts run in a Node vm sandbox, per the lab's own test approach) awarded in all three modules, and a replayed delivery was correctly rejected as the nonce is single-use. Victim-bound challenges (xss stored, csti stored, upload) were also verified: their secrets never leave the server.
3. CSRF: a state-changing request from the victim's own session with no Referer and no Origin changed the email (the app's own feature) but produced no award, with the response explicitly reporting no cross-site evidence. The same request with a foreign Referer awarded; a fresh session using a foreign Origin header instead also awarded.
4. Upload: a one-byte inert .html upload was stored but awarded nothing at upload time; storing now only arms the award check. The genuine flow (upload a file whose bytes contain the per-session beacon snippet, confirm it is served inline with the script intact, fire the beacon exactly as the served file's own script prescribes) awarded. The server independently re-verifies the stored artifact before awarding.
5. CMDI: three quoted-echo spoof variants against `GET /cmdi/ping` (double quotes, single quotes, fake passwd line) printed the fake evidence text but awarded nothing; the check strips quote and escape variants from the input before comparing. A genuine `;id` injection produced real command output and awarded.
6. LFI: `GET /lfi/double?page=%73ecret.txt` displays the in-directory file but awards nothing because no traversal occurred. A genuine double-encoded traversal (`%252e%252e%252fdocs%252fsecret.txt`) awarded the Encoding Bypass challenge.
7. Host-header SSRF: a stand-in server returning the internal marker body was fetched and displayed, but awarded nothing; the check additionally requires a per-boot seal header that only the real internal agent sets and that never appears on any page. Pointing the Host header at the real loopback-only agent awarded.
8. Race: the old GET reset route now returns 404. Session B calling `POST /race/reset` reset only its own state; session A's vote survived. Session A's own reset still works.
9. Prototype pollution: pollution via `POST /proto/json/merge` awarded the polluting session (genuine exploit intact), while two separate fresh sessions were denied at the admin endpoints. Pollution now lives on a per-session stand-in object, not the process-global prototype, and is invisible to other sessions and challenges.
10. IDOR / alice: a fresh session shows alice with role `user` on both the account badge and the profile role row; no silent promotion. The genuine IDOR (opening the unprotected admin panel as the non-admin user) still awards.

Advisory from the pentest reviewer (non-blocking, parent decision): for the page-token beacon challenges (xss reflected, csti basic, jsonp), the served XOR shares can be recombined outside any JavaScript context; the reviewer recombined them in Python and a forged beacon was accepted. The verbatim-scrape cheat from the student reviews is dead and no raw token is served, and the token helper in `lib/jstoken.js` documents "running the same computation" as its accepted bar. Victim-bound challenges are unaffected. Whether this residual is acceptable is a product decision, not a defect against the specified reproductions.

Blocking items from the pentest reviewer: none.

## 2. Senior Code Reviewer

Scope: full `git status` and `git diff` inventory; deep review of modules/xxe, modules/upload, modules/race, modules/oauth, modules/cmdi, modules/auth, modules/misconfig, lib/, and app.js; the tests/ diff reviewed for gaming; remaining modules, docs, SOLUTIONS.md, paths/, and public/ skimmed. The reviewer also booted the app three times against throwaway databases: all 29 module index pages returned 200 with zero error log lines, and a full `node --check` sweep over every changed and newly added JS file reported zero syntax failures.

Check 1, flag secrecy (D18): PASS, no violations. A repo-wide scan for a real flag value pattern matched exactly one file, a pre-existing binary runtime data file that is not among the changed files and is not a source or docs file; no added line anywhere in the diff contains a real flag value. The only flag-shaped strings added are format placeholders and a template interpolating a runtime value. Positive notes: MODULE_CONTRACT.md rule 8 was rewritten from wording that named internal mechanics to the approved doctrine wording (flags randomly generated per install at first boot, no flag literal in any tracked file, only genuine exploits earn flags), with the same scrub direction in README.md and docker-compose.yml comments; the decoy token line was deleted from modules/misconfig/backup.sql and its challenge, so students can no longer copy a decoy as their answer.

Check 2, flag bar: PASS. The dominant direction of the diff is bar raising, with per-challenge evidence checks replacing pattern matching: modules/cmdi/shared.js `evidenceInOutput`, modules/xxe/shared.js `markerProven` and `oobProven`, modules/csrf/shared.js `crossSiteEvidence`, the per-boot seal requirement in modules/hostheader, per-challenge derived targets in modules/sqli/shared.js, one-time proof tokens in modules/proto, victim-bound stored beacons in modules/xss and modules/csti, removal of all eight store-time awards in modules/upload, and removal of the printed admin session id giveaway in modules/session (P3-7). No award check was found loosened, widened, or stripped of a verification step. One MINOR: the comment on the upload beacon handler in modules/upload/index.js and `verifyBeacon` in modules/upload/shared.js overstates the guarantee (claims a manual beacon POST can never stand in for real execution; the endpoint does accept a direct POST but verifies the genuine artifact: pending upload through that challenge endpoint, stored file present, bypass shape satisfied, executable served type, executable script present, per-session token embedded in the file bytes). The bar is strictly higher than HEAD; only the comment needs correcting. Two NOTEs recorded for consciousness: modules/crypto rand-pin deliberately reduced the PIN space from 6 digits to 4 (rationale documented in the file header; full-space brute force still required, now honestly walkable with Burp Community Intruder), and modules/auth reset anti-replay state moved from a process-global set to per-session state (within-session protection unchanged; the removed cross-session blocking was itself the multi-student bug P1-1).

Check 3, per-challenge-file architecture: PASS with two MINOR deviations. modules/oauth/idp.js and modules/oauth/client.js are new module-level router files, which MODULE_CONTRACT.md does not provide for; the moved route code is verified unchanged from HEAD including every award call, and each OAuth challenge still owns its file. modules/xxe/importer.js is a new module-level file holding the shared /xxe/import endpoint including the award calls for two challenges (file.js re-exports it, ssrf.js exports an intentionally empty router); this bends the "exploit logic lives in the challenge file" rule but fixes a real defect (the route previously existed in two challenge files and the second copy was silently shadowed by Express), and award conditions were preserved and strengthened. NOTE: modules/upload upload-case and upload-double-ext still register an identical POST /ext-blacklist handler (pre-existing duplication, second registration shadowed; both copies remain byte-identical in behavior).

Check 4, em dashes: PASS. Every changed tracked file, every new untracked file (including the docs/audit/ subdirectories), and the full JS tree scanned for U+2014: zero hits.

Check 5, test-gaming: PASS, none found. No test deleted, skipped, or marked todo (grep over added lines for skip and only patterns: zero). Assertion balance across tests/: 48 removed, 324 added, and every sampled removal is replaced by an equal or stronger assertion tracking a real product change (crypto burst now tolerates a genuine 200 solve inside the burst range while still asserting no throttling; session predictable now asserts the giveaway is gone and derives the target id; cors negative case strengthened with a new positive; idor gained a cross-session assertion; http cache-deception rewritten for per-session cache with a stranger-session assertion; jsonp and xss page-token assertions moved from HTML scraping to executing page scripts in a vm browser simulator with new negatives; fixmode calls converted to await with identical assertions after the worker-thread runner made the API async). Four new test files are additive coverage (demo-creds, drift, two-session-isolation, runner-hardening). One NOTE: tests/scenarios-ghost.test.js now fires POST /upload/beacon directly instead of executing the stored payload in the browser simulator; it still asserts the served content type first and matches the server-side verification model, but the suite no longer end-to-end proves browser execution for the upload challenges.

Check 6, dead code and regressions: two BLOCKERs, detailed in the gate section below. One MINOR cosmetic cluster (stray indentation in two xxe challenge files, trailing whitespace in one, unused destructured imports in several module index files; all syntactically valid and verified harmless). NOTEs: app.js boot gate `markReady()` only fires on the `require.main === module` listen path (fine for the app and the suite today; a future embedding via require plus a custom listen would serve the 503 boot page forever); modules/oauth/shared.js request log and simulated browser history remain process-global by design (the leak is the intended challenge mechanic). No leftover debug logging of sensitive data; the only added console output is operational boot lines and a process-guard stack logger that writes to the server log only. Runtime spot checks: POST /upload/beacon rejects junk with 403, GET /upload/traverse-prove returns 403 when unproven, GET /race/reset returns 404 after its conversion to a per-session POST, and all in-app reset links were converted to POST forms.

Check 7, mid-edit state: no file is syntactically broken or half-finished; the full application requires and mounts every module and the pages render. NOTE: modules/xxe/challenges/ssrf.js carries a dated in-flight incident note (stream D2, 2026-10-20) describing an earlier broken state that is already repaired within this same tree; the team should delete the stale note before commit so it does not read as a live warning.

Severity counts: BLOCKER 2, MAJOR 0, MINOR 5, NOTE 9.

## 3. Senior QA

Command: `node --test "tests/*.test.js"` from the snapshot copy, Node 24. The suite ran end to end in about 5 minutes with no syntax error, no missing module, and no crash.

| Metric | Count |
|--------|-------|
| Tests reported | 553 |
| Pass | 542 |
| Fail | 11 (7 leaf tests plus their 4 parent suites) |
| Skipped | 0 |
| Todo | 0 |
| Cancelled | 0 |

Test count delta: 553 now vs the historical 490, net +63, with 4 brand new test files (demo-creds, drift, runner-hardening, two-session-isolation, all passing) and several suites expanded (xss, upload, sqli, csti, jsonp, xxe). Nothing was removed on balance.

Failures (all 7 leaf failures):

| # | File | Test | Failure |
|---|------|------|---------|
| 1 | tests/fixmode-badges.test.js | HTTP integration: POST fixedCode, badge row recovery | Assertion at line 279: the test client never received a session cookie to recover an id from, so `sessionIdOf()` returned null. The fix itself was accepted and the badge was earned; only the cookie recovery failed. |
| 2 | tests/paths-cert.test.js | all 10 steps fall to the real exploits, in order, on one session | Step 10 (xss:stored): exploit response 400, expected 200. Steps 1 to 9 passed. |
| 3 | tests/paths-cert.test.js | certificate unlocks (200, image/png, real PNG, over 10KB) | 403, expected 200. Downstream of failure 2: the path never completes. |
| 4 | tests/paths-cert.test.js | path page shows the certificate button after completion | Page shows 10/10 progress: false. Downstream of failure 2. |
| 5 | tests/paths-verify.test.js | completing the path via real exploits captures all ten steps | "stored XSS beacon must be accepted": false, thrown in capturePathSteps. |
| 6 | tests/paths-verify.test.js | certificate renders after path completion | Same stored-step assertion in capturePathSteps. Downstream of failure 5. |
| 7 | tests/scenarios-shop.test.js | stage 4: real xss/stored beacon exploit completes the scenario | strictEqual 400 !== 200. Stages 1 to 3 passed. |

Root causes, verified in the tree:

- Failures 2 to 7 share one cause. The wave deliberately made stored XSS victim-bound: `modules/xss/index.js` returns HTTP 400 ("Victim visit required") from `/xss/collect` for `v=stored`, and the award now flows only through the new simulated-victim route in `modules/xss/challenges/stored.js`. The downstream tests were never migrated to the new flow: tests/scenarios-shop.test.js is untouched vs HEAD, and the working-tree diffs in tests/paths-cert.test.js and tests/paths-verify.test.js only update the csrf step (foreign Referer evidence), not the stored step. tests/xss.test.js itself was migrated and the whole xss suite passes, including its adversarial negatives.
- Failure 1 has a separate cause. app.js session config changed to `saveUninitialized: false` (in-code comment cites backlog item P1-9). A client that stores nothing in its session receives no session cookie, so the fixmode-badges test helper finds nothing in the jar even though the fix was accepted and the badge earned.

QA assessment: RED due to in-progress edits, not a shipped product regression. Evidence: the failures cluster exactly on the two deliberate behavior changes; app code and the updated xss tests agree with each other; every other heavily edited area passes (upload, sqli, csti, jsonp, xxe, csrf, race, postmsg, platform, drift, two-session isolation, runner hardening, demo creds); all files parse cleanly. To finish: migrate the stored step in tests/paths-cert.test.js, tests/paths-verify.test.js, and tests/scenarios-shop.test.js to plant the payload and drive the victim-visit flow instead of posting the beacon to /xss/collect, and adapt the fixmode-badges HTTP test so its client establishes a stored session before expecting a cookie (or key the badge-row lookup differently) under `saveUninitialized: false`. Caveat recorded by QA: the tests alone cannot prove the victim-bound model is the team's final intended spec rather than a change they may still revert; what is certain is that app code and the updated xss tests agree, and the 7 leaf failures are exactly the unmigrated spots.

## Gate Verdict: FIX FIRST

The wave's security direction is verified strong: every confirmed student cheat now fails live testing, every genuine exploit still works, flag secrecy and the flag bar hold across the diff, isolation between students is real, and the suite grew by 63 tests with zero gaming. It must not ship yet, for the following blocking items.

Blocking items:

1. VM sandbox host escape, modules/xss/challenges/stored.js, GET /xss/victim-visit (sandbox construction and the `vm.runInContext` call at line 83). The simulated-victim runner places host-realm values into the vm sandbox (a host arrow-function `fetch`, the host `console`, the host `URLSearchParams` class) and then executes attacker-controlled stored guestbook scripts inside it. Guest code can walk from any of those to the host `Function` constructor and reach the host process; the code reviewer reproduced the escape locally with the exact sandbox shape (`URLSearchParams.constructor('return typeof process')()` returns "object", the host process object). A planted guestbook comment therefore executes arbitrary host code the next time anyone, including the test suite, opens the victim-visit route, and the payload persists. This is precisely the escape lib/fix-worker.js was written to prevent; the sandbox helpers must be built inside the guest context the same way.
2. Same defect class, modules/csti/challenges/stored.js, GET /csti/stored/victim-visit (sandbox at lines 124 to 138). Host functions (`fetch`, `encodeURIComponent`, `console`) are injected into the vm context while attacker-controlled stored templates are evaluated by the in-context renderer, giving template payloads a path to the host `Function` constructor via `fetch.constructor` or `encodeURIComponent.constructor`.
3. Test suite red (7 leaf failures): the stored-XSS victim-flow migration is unfinished in tests/paths-cert.test.js, tests/paths-verify.test.js, and tests/scenarios-shop.test.js, and the fixmode-badges HTTP test is incompatible with the new `saveUninitialized: false` session config. QA classifies this as in-progress migration rather than a product regression, but the suite was 490/490 before the wave and the wave cannot be called done while its own acceptance suite is red.

Non-blocking advisories for the parent to decide or schedule:

- Pentest advisory: page-token beacon challenges (xss reflected, csti basic, jsonp) still accept a beacon whose token was recombined from the served XOR shares outside any JavaScript execution (verified with a Python recomputation). The raw-token scrape cheat is dead; victim-bound challenges are unaffected. Decide whether the documented `lib/jstoken.js` bar is acceptable or should be raised.
- MINOR: correct the overstated guarantee comment on the upload beacon handler (modules/upload/index.js, modules/upload/shared.js `verifyBeacon`).
- MINOR: resolve the two architecture deviations explicitly (modules/oauth/idp.js and client.js; modules/xxe/importer.js): either amend MODULE_CONTRACT.md to bless module endpoint files or accept the deviations on record.
- MINOR: cosmetic cluster (indentation and trailing whitespace in three xxe challenge files, unused imports in several module index files).
- Before commit: delete the stale in-flight incident note in modules/xxe/challenges/ssrf.js.
- NOTE: the scenarios-ghost test no longer end-to-end proves browser execution for upload challenges; consider restoring a simulator-driven upload stage later.

Snapshot caveat: the improvement team was still editing during supervision (263 files in flight). This report covers the tree as snapshotted at supervision start; files changed after that point, and the final state of the in-progress test migration, need a confirmation pass once the team declares the wave complete.
