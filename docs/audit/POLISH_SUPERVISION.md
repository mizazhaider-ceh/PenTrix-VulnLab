# Supervision Report: PenTrix-VulnLab Polish Wave

Date: 2026-10-20. Scope: independent verification of the polish wave working tree at `~/workspace/pentrix-vulnlab/` (git main, uncommitted polish changes in flight), covering the postmsg csrf-action tightening, the banner-once award change, the per-session upload quota, regression spot-checks of the improvement wave cheat closures, and the P1A test updates in tests/auth.test.js, tests/lfi.test.js, tests/hostheader.test.js.

Method: the current tree was snapshotted with rsync (excluding node_modules, .git, database files) into `~/workspace/pentrix-verify/`, and the lab was booted from that snapshot on Node at `http://127.0.0.1:19710` with a throwaway database (`DB_PATH=/tmp/polish-pentest.db`), so live testing ran insulated from ongoing edits. Each session used its own cookie jar. Every item was tested in both directions: the shortcut must fail and the genuine exploit must still succeed. Award evidence: per-session scoreboard capture sets plus presence or absence of the `flag-banner` markup in responses. The server was killed by PID after testing and the port confirmed free. No product code was edited by the reviewer and nothing was pushed. This report contains no flag literals and no flag-storage details (D18 clean).

## Pentest reviewer

Verdict summary: all five items PASS. Blockers: none.

### Item 1: postmsg csrf-action tightening, PASS (7/7 checks)

Requests made, responses seen:

- Cheat A, bare curl delete plus beacon, no token. Fresh jar. `GET /postmsg/csrf-action` returned 200 (session established). `POST /postmsg/csrf-action/delete` with an empty body returned 200 (`account deleted (lab only)` in JSON). `GET /postmsg/beacon?v=csrf-action&d=csrf-action:account-deleted` returned 400 with the "No flag" page. Scoreboard: 0 postmsg captures.
- Cheat B, forged foreign Origin and Referer. Fresh jar. Page load 200. Delete POST with `Origin: http://evil.test` and `Referer: http://evil.test/attack` returned 200. Beacon with the same forged headers and no token returned 400. Beacon with a guessed token (`n=deadbeef`) and forged headers returned 400. Scoreboard: 0 captures. Foreign headers buy nothing here, which matches the module's own design note: the genuine flow's HTTP requests are all same-origin from the victim page, so header checks would fail the real exploit while a non-browser client could forge them anyway.
- Genuine path, real victim page script executed. Fresh jar. Fetched the live victim page, confirmed the inline script contains the PM_NONCE computation and the `delete-account` message handler, and ran the exact script bytes in a Node `vm` context with stubbed `window.addEventListener`, `document.getElementById`, and `fetch` (the stub proxied to the lab with the same session cookie). Dispatched `{data: {action: 'delete-account'}}` to the captured listener. The handler POSTed the delete with the runtime-computed page-bound token and fired the beacon. Scoreboard then showed exactly one capture: `postmsg:Privileged Action via Forged Message`.
- Replay: calling the beacon again with the same token returned 400 and the capture count stayed at 1. The token is single-use (consumed on first win).
- Wrong-token control: `POST /postmsg/csrf-action/delete` with `n=wrongtoken` produced 0 captures. The token alone, without the page-driven flow, is not enough.

### Item 2: banner-once, PASS (8/8 checks)

Requests made, responses seen:

- Methodology note, not a defect: my first burst attempt pinned the session with `GET /cmdi/ping`, which never touches the session, so express-session sent no cookie and all 20 burst members became 20 separate sessions (20 banners, each a legitimate first capture for its own session). Re-ran with the session pinned via `GET /postmsg/csrf-action`, which writes the page nonce to the session and forces a Set-Cookie. All 20 burst members then shared one session.
- Burst: 20 parallel `GET /cmdi/ping?host=127.0.0.1;id` (genuine `;id` injection). All 20 responses returned 200. Exactly 1 of the 20 responses contained the `flag-banner` markup. Scoreboard counted exactly one capture: `cmdi:Ping Gadget (no filtering)`.
- Second, different capture in the same session: the auth brute-force honest path (6 failed logins, then a successful `alice` login). The success response rendered exactly 1 banner. Scoreboard showed one auth capture and one cmdi capture, each counted once.
- flagFor path: `GET /auth` rendered 1 banner and 1 flag-shaped string for the already-captured brute-force flag. The flag stays viewable and copyable after its capture moment.
- Repeat: the same `;id` payload again rendered 0 banners, and the total capture count stayed at 2. No double count.

### Item 3: upload quota (per-session accounting), PASS (6/6 checks)

Requests made, responses seen:

- Session B: `GET /upload` (200) and scraped the per-session beacon token from the `data-beacon="stored-xss"` element. Uploaded `bsurvive.html` via `POST /upload?filename=bsurvive.html` with the exact beacon snippet baked in (200 stored). No beacon fired yet.
- Session A: 205 sequential uploads `flood000.html` through `flood204.html` (64-byte bodies), all 200.
- After the flood: `GET /uploads/bsurvive.html` with B's jar returned 200 and the response body still contained B's token. B's file survived A's flood.
- B then fired `POST /upload/beacon` with JSON `{id: 'stored-xss', file: 'bsurvive.html', token: <B's token>}`: 200, the "Payload executed" page rendered the flag banner. B's scoreboard counted exactly one capture: `upload:Stored XSS via File Upload`.
- Informational: A's own oldest flood file (`flood000.html`) now returns 404 while its newest (`flood204.html`) still returns 200. The quota trimmed only A's own bucket back to its 200 cap; no code path unlinked a file because a different session uploaded.

### Item 4: improvement-wave regression spot-checks, PASS (8/8 checks)

Four of the ten original cheat checks re-verified in both directions:

- XXE literal marker: `POST /xxe/import` with the marker text typed literally inside `<data>` and no entity declaration rendered the marker in the output but no banner, 0 xxe captures. Genuine external-entity `file://` read of the module's `secret.txt` in the verify copy awarded `xxe:XXE File Read`.
- CMDI quoted-echo spoof: `GET /cmdi/ping?host=;echo "uid=1000(root)"` printed the fake evidence text in the output but no banner, 0 captures. Genuine `127.0.0.1;id` awarded `cmdi:Ping Gadget (no filtering)`.
- LFI bare percent: `GET /lfi/double?page=%73ecret.txt` displayed the in-directory file with 200 but no banner, 0 captures. Genuine double-encoded traversal `page=%252e%252e%252fdocs%252fsecret.txt` awarded `lfi:Encoding Bypass`.
- Proto pollution scope: polluting session P saw the admin check deny first, a flat `{"role": "admin"}` merge still deny, then a `{"__proto__": {"role": "admin"}}` merge followed by the admin check awarded `proto:JSON Body Pollution`. Two fresh sessions F1 and F2 then hit `/proto/json/admin`: both denied, 0 captures each. Pollution stays scoped to the polluting session.

The polish wave did not regress any of these.

### Item 5: P1A test updates, verdict HONEST (9/9 live checks)

The three test files were updated to the banner-once spec. I reviewed each diff and re-verified the underlying behavior live. None was weakened to pass.

- `tests/auth.test.js`: the repeat-login assertion changed from "the flag is present in the response" to "zero flag-shaped strings in the response", plus new assertions that the flag stays viewable on the module index and that the capture count stays 1. This is strictly stronger than before: it asserts the banner renders exactly once and the flagFor display path keeps the flag viewable. Live equivalent verified in item 2 (second capture shows its own banner, module index shows the flag, repeat shows none, no double count).
- `tests/lfi.test.js`: the repeat-view assertion changed from "repeat yields the same flag" to "repeat re-renders no flag", plus "the flag stays viewable on `/lfi/log-demo`" and "no double count". Verified live end to end: poisoned the log via a marked User-Agent, read it via traversal (first read rendered exactly 1 flag, capture `lfi:Log Poisoning Chain` recorded), repeat view rendered 0 flags, the log-demo page rendered 1 flag, capture counted once.
- `tests/hostheader.test.js`: the X-Host-Override variant moved from session `c` (which had already captured the same flag via the X-Forwarded-Host collect) to a fresh session `c2`, asserting that `c2`'s own collect renders the flag and `c2`'s captured set includes the challenge. This is the correct judgment call and a stronger test, not a weakening. The old shape could not prove the variant awards: before banner-once the flag in the response could have been a repeat render of the earlier capture, and under banner-once the repeat renders nothing at all (verified live: a repeat collect in the same session rendered no banner and did not double count). The new shape genuinely proves the variant awards. Verified live in a fresh session: the override page rendered the poisoned reset link built from `http://evil.org/hostheader/reset`, the fresh-session collect rendered the banner, and the capture `hostheader:Forwarded-Host Header Poisoning` was recorded exactly once.

### Blockers

None. The cheat must fail and the honest exploit must work in every item, including under a 20-request parallel burst and a 205-upload cross-session flood.

## Code reviewer

Scope: the polish-wave working tree (`git diff HEAD`) in `~/workspace/pentrix-vulnlab` (229 files) and `~/workspace/pentrix-website` (6 files). Read-only review; no product code edited, nothing committed or pushed. Live probes were run against a throwaway-DB instance to verify the two riskiest claims (breadcrumb href escaping, nav/h1/breadcrumb behavior).

### Item 1: banner-once (lib/flags.js, lib/request-context.js, lib/page.js) - PASS, one MINOR

- Memory bound, lib/flags.js:53-61: `bannerClaims` keyed `${sid}\n${key}`, TTL 7 days, which matches the session store default (`lib/session-store.js:12`, also 7 days), hourly sweep deletes entries older than the TTL, timer is `unref()`d so it cannot hold the process open. Entries are TTL-refreshed on each award, so the map stays bounded by live sessions times the challenge count, as the comment claims. PASS.
- Atomicity: `award()` (lib/flags.js:81-109) is fully synchronous end to end: `refreshFlags` and `storedHas` use better-sqlite3 `.get` (sync, verified `lib/session-store.js:106-114`), Map check-and-set has no await between `has` and `set`, `flagFor` is a sync prepared statement, `recordAward` is sync ALS object writes. No async gap, no deadlock possible. PASS.
- `recordAward` has exactly one caller (`award()`); the old two-arg signature had no other callers, so the new `detail` parameter breaks nothing. `lastAward()` semantics unchanged (still overwritten per award), so the banner's next-challenge button behaves as before. PASS.
- Suppression correctness, verified by reading all call patterns: duplicate award in a request makes `flagBanner` return `''` via `claimBannerRender` (lib/request-context.js:77-87) WITHOUT setting `renderedFlags`, the first award renders exactly once (second same-flag render in the request is stopped by `renderedFlags`), and `flagFor` displays with no award in the request (module index `modules/auth/index.js:28`, `/lfi/log-demo`, scenario completion `scenarios/index.js:113`) render normally. The tricky ordering in `modules/lfi/challenges/traversal.js` (`showCaptured` before `award` in the same request) behaves correctly: on a repeat, the display renders the one banner and the duplicate award's banner is suppressed, exactly one banner per page. JSON/header call sites (`res.json({ ok: true, flag })` in jsonp/api challenges) are untouched: `award()` returns the flag string on first and duplicate awards alike. PASS.
- MINOR, lib/request-context.js:73-75 comment: "A suppressed claim does not consume the render slot, so an already-captured display for the same flag later in the same request can still render." The code does not honor the second half: when the request recorded a duplicate award (`awardsByFlag[key].first === false`), a later `flagBanner` for the same flag is still suppressed regardless of render-slot state. No page in the codebase uses the award-then-display ordering, so behavior matches the spec and nothing renders wrongly, but the comment misleads future maintainers. Fix the comment, not the code.

### Item 2: lib/page.js end to end (three workers' edits) - PASS, one MINOR

Read the full 820-line file. The P1A `claimBannerRender` gate (line 144), the breadcrumb placeholder (lines 31-42, inside `<main>` before the body), the UX `copyButton(label, ariaLabel)` (lines 110-113, all call sites pass sensible labels), the "(show)" hint copy (lines 172, 228, consistent), and the N2 `fixCtaCard(moduleId, vulnId, name)` (lines 598-609, name escaped) compose without contradiction or duplicated logic. `flagBox` still delegates to `flagBanner`, so the legacy signature inherits banner-once. The N2 `fixSection` change drops the old `<article class="vuln-card fix-card">` wrapper; `.fix-card` was never in `public/style.css`, so no styling is lost, and the card now uses `.clay-card` directly with the challenge name as its own `h3` (previously the name sat in an outer card wrapping an inner card). Cleaner, no visual regression. MINOR: `copyButton('Copy flag', 'Copy flag')` in `flagBanner` passes an aria-label identical to the visible text; harmless but redundant (the UX worker's own rationale was to differentiate repeated Copy buttons).

### Item 3: app.js breadcrumb middleware + public/app.js - FAIL (one blocking item)

What holds, all verified live against a throwaway-DB boot:
- The `res.send` wrapper touches string bodies only; static files (`express.static`, `sendFile`), redirects, JSON, and 4xx/5xx pass through unharmed (JSONP payload verified byte-identical).
- Full-path capture (`const fullPath = String(req.path || '')` at app level, app.js:155) fixes the mount-stripping problem: `/sqli/login` now resolves module `sqli` and renders "Modules / SQL Injection / Login Bypass". Home, scoreboard, about, fix mode, and error pages correctly get no breadcrumb; no `<!--px-...-->` placeholders leak into responses.
- Nav highlight: `hadCurrent` is captured before breadcrumb insertion, so the breadcrumb's own `aria-current` cannot suppress the top-nav highlight. Verified: exactly one `aria-current="page"` in the primary nav on `/`, `/scoreboard`, `/scenarios`; zero on module pages (pre-existing behavior, `NAV_SECTIONS` unchanged).
- Exactly-one-h1 holds on every probed page (`/`, `/sqli`, `/sqli/login`, `/scoreboard`, `/setup-guide`, `/scenarios`). The setup-guide retitle works: the guide's own heading is now the `h2` "Burp Suite and the Web Hacking Toolkit" instead of repeating the page H1.
- `public/app.js` wireFilter announcements use `textContent` only; the live region is per page (`querySelector` picks the page's single `[data-filter-live]`). Safe.
- FAIL (blocking), app.js:330 and app.js:345, in `breadcrumbHtml`: `{ href: '/scenarios/' + segments[1], ... }` and `{ href: '/paths/' + segments[1], ... }` interpolate a URL path segment into `<a href="...">` WITHOUT escaping (the label next to it is correctly `esc()`d). Empirically confirmed: `GET /scenarios/"onmouseover="alert(1)/extra` returns a 404 page containing `<a href="/scenarios/"onmouseover="alert(1)">`, a reflected attribute-breakout XSS in the shared page chrome. A raw `"` survives into `req.path` (Express does not decode percent-encoding and Node's parser accepts the raw byte). Practical exploitability is limited because browsers percent-encode `"` through URL parsing (only raw HTTP clients such as curl or Burp Repeater deliver it), but new chrome code must not contain an XSS sink, and the fix is one word: wrap the two hrefs in `esc()` (or escape hrefs centrally in `breadcrumbNav`). The module branch is safe (hrefs come from the registry), and the 2-segment case is safe (current item is a `<span>`, label escaped).

### Item 4: upload per-session quota (modules/upload/shared.js, index.js, challenges) - PASS

- Ownership model: per-session buckets via `lib/session-state` (7-day TTL matching the session store, hourly sweep, `unref()`d, `onEvict` releases claims). Claim counts (`uploadClaimCounts`) are balanced: +1 per new (session, name), re-store of an already-claimed name only refreshes recency (no double count, verified `indexOf`/`splice`/`push` logic), every eviction path (`enforceUploadQuota` shift, bucket expiry, `reset()`) releases exactly the names in that bucket. Unlink happens only when the last claim is released, and `unlinkSync` failures are swallowed. PASS.
- Coverage: every direct-root store path calls `trackStoredUpload` immediately after `fs.writeFileSync` (upload-case, upload-ctype, upload-double-ext, upload-polyglot, upload-strip-once, stored-xss). `upload-overwrite` writes under `avatars/` (explicitly out of quota scope, correct). `upload-traversal` guards with `if (!outside && path.dirname(target) === UPLOADS_DIR)`, so escaped files never enter accounting and their traverse-prove read-back can never be quota-evicted. `enforceUploadQuota(req)` has exactly one caller (the module middleware), now passes `req`, and only ever peeks the requesting session's bucket. PASS.
- Edge cases: re-storing an existing name (recency refresh, count stays 1); two sessions claiming one name (eviction by A releases A's claim only, B's claim keeps the file, verified by the pentest reviewer's live 205-upload flood); empty bucket (no-op); session-less requests (`trackStoredUpload` returns false via the try/catch around `get()`, `enforceUploadQuota` no-ops on `peek()` null). Read-back paths (`verifyBeacon`'s `existsSync`/`readFileSync`, traverse prove, view/poly/avatar serving) cannot be broken by another session's activity, only by the owning session exceeding its own 200-file cap, which is the quota working as designed. Restart behavior is deliberate and documented: buckets and claim counts are both in-memory so they reset together, orphaned files are left in place rather than guessed at. PASS.

### Item 5: postmsg csrf-action tightening - PASS, one advisory

- Token: `crypto.randomBytes(16).toString('hex')` per (session, vuln) in `modules/postmsg/shared.js`; never rendered raw (XOR shares via `lib/jstoken.js`). The victim script presents it on the delete POST and echoes it on the beacon. PASS.
- No bypass: guessing is infeasible (128-bit CSPRNG); reuse across challenges is blocked (nonce keyed by vuln id, beacon checks `m[v]`); reuse across sessions is blocked (session-bound store, adversarial test with two sessions passes); reset clears both `pm_deleted` and `pm_msg_deleted` (verified in the diff). The beacon consumes the token (`delete m[v]`, single-use, replay returns 400). The delete endpoint validates the token before setting the message-driven evidence flag; the deletion itself always happens by design (the vuln), only the flag evidence is gated. PASS.
- `lib/jstoken.js` diff is comment-only: it now honestly documents that share recomputation outside a browser is the accepted residual bar, with no logic change. PASS.
- Advisory: the csrf-action header comment ("without executing the victim page's script it cannot present the token, so that shortcut earns nothing") slightly overstates compared to the jstoken.js honesty note; the test helper `pageNonce` itself recomputes the token from the served shares. Under the documented doctrine this residual is accepted, not a flag-bar bypass, but the challenge comment should acknowledge it the way jstoken.js now does.

### Item 6: D18 (flag-storage secrecy), whole diff both repos - PASS

No `PENTRIX{...}` literal with real content anywhere in either repo's diff (only `PENTRIX{...}` placeholders in teaching text). No disclosure of where flags are stored: the closest mentions are "stored capture map" (session capture state, not flag values) and per-session page tokens (not flags). `MODULE_CONTRACT.md` says only "random `PENTRIX{...}` per deployment". The new audit docs were scanned too: `POLISH_SUPERVISION.md` explicitly records D18-clean, and `docs/audit/polish-shots/` holds screenshots only. (The `<redacted>` strings in my grep output were the tool sanitizer redacting seeded DEMO credentials such as `admin/admin123`, which `MODULE_CONTRACT.md` documents as intentional lab seed data, not real secrets.)

### Item 7: em dash scan - PASS

Zero U+2014 in all changed files: 228 files in `~/workspace/pentrix-vulnlab`, 6 files in `~/workspace/pentrix-website` (scanned current file contents, which covers the diff).

### Item 8: P1A test updates (test-gaming check) - PASS

`tests/auth.test.js`, `tests/lfi.test.js`, `tests/hostheader.test.js`, `tests/postmsg.test.js` were updated honestly; every removed assertion was replaced with a strictly stronger one (repeat renders zero flags AND the flag stays viewable on the module index / log-demo page AND no double count; the hostheader variant moved to a fresh session so it genuinely proves the variant awards). `tests/postmsg.test.js` gained new adversarial negatives: bare delete plus beacon 400, beacon token without token-driven delete 400, replayed beacon 400, cross-session beacon 400, foreign Origin/Referer without token 400, guessed token 400 with the real token still working afterward. All four files pass: postmsg 13/13, auth 12/12, lfi 15/15, hostheader 9/9.

### Item 9: FLAG BAR (no weakened evidence anywhere in the diff) - PASS, one MINOR

No `award(req, ...)` call line changed anywhere; no evidence check was loosened; no adversarial test negative was removed. The only award-path logic changes are tightenings: the postmsg csrf-action beacon now additionally requires `pm_msg_deleted`, and the upload quota is accounting only. MINOR (hint precision, not award logic): `modules/cmdi/challenges/cmdi-newline.js` and `cmdi-braces.js` hints now say "the flag is awarded only when the second command's real output shows up", but the code still requires `PASSWD_EVIDENCE` (`/^(?:root|daemon):.../m`, and the match must not be inside the attacker's own input). A student running `id` sees real output and earns nothing, contradicting the hint. The old wording ("only when the passwd lines show up ... Output from other commands (id, for example) ... is not the evidence this gadget checks for") was accurate. Suggest restoring the precise wording.

### Gate verdict: FIX FIRST

Blocking item: the reflected XSS in the breadcrumb href (app.js:330, app.js:345), empirically confirmed. Fix: `esc()` the `'/scenarios/' + segments[1]` and `'/paths/' + segments[1]` hrefs (or escape hrefs centrally in `breadcrumbNav`), then re-probe `GET /scenarios/"onmouseover="alert(1)/extra` and confirm the quote is entity-encoded.

Non-blocking advisories (ship-safe, fix at leisure): the request-context.js comment over-claim (item 1 MINOR), the redundant `aria-label` on the flag copy button (item 2 MINOR), the cmdi-newline/cmdi-braces hint precision regression (item 9 MINOR), the csrf-action comment vs the documented share-recomputation residual (item 5 advisory), `storedHas` doing a sqlite read on every award even when the snapshot already shows the capture (perf nit), the upload-polyglot `start` text losing the concrete endpoint (still present in `how` and the card curl), and the website search.js 300ms focus fallback which could yank focus back if the user tabs away within 300ms of opening search.

Website diff notes (all PASS): count-up fix (sync reset to 0 during init, once-only via script flag plus `data-count-state`, 2500ms fallback so no stat strands at 0), search focus fix (immediate plus double-rAF plus guarded 300ms retry), live-region announcements via `textContent`, difficulty pills now carry `data-level` hooks on all 29 pills with matching CSS, badge pattern changed to the link itself (`a.badge-new`, markup updated to match), terminal.css pre padding/word-wrap fix, contrast bumps (`#BE185D`, solid `#7C3AED` focus), 44px touch targets, print rule that never prints unrevealed sections blank. No flag content on the website; D18 clean.

## QA

Senior QA pass over the polish wave working tree, run 2026-10-20. No product code was edited, nothing was committed or pushed. Test infrastructure note: the repo pins better-sqlite3 v11 (Node 20 Docker target); this box runs Node 24, so all runs below used a fresh rsync verify copy at ~/workspace/pentrix-verify (flock /tmp/verify-sync.lock, excluding node_modules, .git, *.db*). better-sqlite3 loads and works on Node v24.20.0 in that copy.

### 1. node --check sweep: PASS

Every JS file in the polish wave diff plus the changed website scripts:

- pentrix-vulnlab: 225 changed .js files (git diff --name-only HEAD | grep '\.js$'), all pass node --check, zero syntax failures.
- pentrix-website: assets/js/search.js, assets/js/site.js, both pass node --check.

### 2. Full suite: PASS, 572/572

Command: node --test "tests/*.test.js" from the verify copy after a fresh sync. Final clean run:

- tests 572, suites 24, pass 572, fail 0, cancelled 0, skipped 0, todo 0, duration 187.4s, process exit 0.
- Baseline pre-polish was 565 pass / 0 fail. Delta is +7 tests, all passing:
  - tests/polish-banner-once.test.js (new): 4/4 pass (parallel burst renders one banner, sequential repeats render none, a second distinct capture still shows its own banner, repeat exploit page holds one banner with the flag still viewable).
  - tests/polish-upload-quota.test.js (new): 1/1 pass (session A flooding past its cap never evicts session B).
  - Net +2 from the updated files (tests/postmsg.test.js, tests/auth.test.js, tests/hostheader.test.js, tests/lfi.test.js); every updated file passes with zero failures, including the full postmsg module and postmsg A1B adversarial negatives.

### 3. Boot check: PASS

Booted the lab from the verify copy with a throwaway DB: PORT=19711 DB_PATH=/tmp/polish-qa.db (PID 10250).

- Boot log: 29/29 "[ok] mounted /<module>" lines, "[ok] generated 204 per-deployment challenge flags", "listening on http://localhost:19711". Zero error lines (grep for error/Unhandled/exception/EADDRINUSE/failed: no hits).
- HTTP probes, all 200: / (home), /scoreboard, beginner band (/csrf, /http, /xss), intermediate band (/api, /auth, /cmdi), advanced band (/crypto, /proto, /race), one scenario page (/scenarios/api-heist), one path page (/paths/zero-to-web-pentester).
- All 29 module indexes probed individually (/api through /xxe): 29/29 return 200, zero non-200.
- Server killed by PID after the probes; port confirmed closed.

### 4. Regression scan

One anomaly cluster appeared and was classified:

- (c) Flaky/parallel-state artifact, NOT a product regression. Two earlier full-suite attempts (run while the box was at ~90% memory with leftover server processes from a violently interrupted first attempt) each showed the same 4 cmdi subtest failures: cmdi-pipe, cmdi-tab, "quoted echo of the expected output earns nothing anywhere", "repeating an exploit does not double count the scoreboard". Those tests shell out to `ping` with an 8s exec timeout and are timing-sensitive under extreme load.
- Confirmation: tests/cmdi.test.js run alone: 12/12 pass, exits cleanly in ~18s. A 4-file parallel repro (api+auth+bizlogic+cmdi): all pass. The final full 49-file suite run on a clean box: 572/572 pass, zero failures. No code change was needed or made.
- (a) Real product regressions: none found. (b) Unfinished in-progress migrations: none found; the working tree is coherent (29 modules mount, 204 flags seed, all suites green).

### QA gate verdict: SHIP (on QA evidence)

Syntax, suite, and boot checks are all green with exact counts above. Note for the release owner: this QA verdict covers test/boot evidence only. The security review section above already carries a governing FIX FIRST for the empirically confirmed reflected XSS in the breadcrumb href (app.js:330, app.js:345); that finding is outside QA scope, was not re-tested here, and remains the blocking item until it is fixed and re-probed.
