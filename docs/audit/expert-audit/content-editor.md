# Content and Briefing Audit: PenTrix-VulnLab
**Auditor role:** Content and briefing editor
**Date:** 2026-10-20
**Scope:** briefings and challenge prose in `modules/*/index.js` and `modules/*/challenges/*.js` (all 201 challenges), `SOLUTIONS.md`, `solutions/batch-*.md`, `README.md`, `docs/TOOL_SETUP_GUIDE.md`, plus D18 and em-dash sweeps across prose.
**Method:** extracted every `hint`/`hints`/`how`/`start` field from all 201 challenge files, read SOLUTIONS.md end to end, cross-checked 10 sampled solutions against the actual route and award logic in code, verified challenge counts per module, and grepped for spelling, tone, spoiler, D18, and em-dash defects.
**Constraints honored:** no code changed, nothing pushed, no em dashes used in this report.

## Summary

The writing is, on the whole, strong: encouraging, precise, and Burp-first, with no condescending language found anywhere in student-facing prose. But the content layer has real rot in three places: (1) stale pre-generation drafts (`solutions/batch-*.md`) that describe challenges and routes that no longer exist, (2) a stale README catalog whose module rows name challenges that are not in the lab, and (3) generator scaffolding left inside SOLUTIONS.md with wrong challenge counts and references to files that do not exist. The spoiler posture is mostly good in hint ladders, but several `how` summaries (rendered on module index cards before the challenge is even opened) hand over exact payloads, and the SSTI module briefing names the exact flag variable. One SOLUTIONS.md section (XSS beacons) is stale against current code. D18: no violations in student-facing prose; four hits in internal dev/roadmap docs. Em dashes: zero in prose.

---

## Findings

### F1. Stale solution drafts describe challenges that do not exist
- **Severity:** High
- **Location:** `solutions/batch-01.md` (lines 3-9), and by extension `solutions/batch-02.md` through `solutions/batch-12.md`
- **Description:** The `solutions/batch-*.md` files are pre-M7 generation drafts (before the 235 -> 201 dedupe) that were never reconciled. They describe challenges, routes, and vuln IDs that do not exist in the current lab. The canonical `SOLUTIONS.md` was reconciled to 201 challenges; these files were not.
- **Evidence:** `solutions/batch-01.md` solution 1 is titled "Stored XSS in Profile Bio" with steps "Open `/xss/profile`" and a beacon to `/xss/collect?c=...&v=stored-xss-profile`. There is no `/xss/profile` route and no `stored-xss-profile` vuln in the repo (verified by grep across `modules/`, `app.js`, and `SOLUTIONS.md`). The same file also documents "DOM XSS via document.write", "Login CSRF (forged session switch)", "Password Change via multipart/form-data (no token)", and "Disable 2FA via GET Link", none of which exist as challenges.
- **Recommendation:** Delete the `solutions/` batch files, or move them to a clearly labeled archive (e.g. `docs/roadmap/archive/`) with a header noting they are pre-M7 drafts. They are unreferenced by README.md and SOLUTIONS.md, so removal is safe. A student who finds them will chase ghosts.

### F2. Generator scaffolding embedded in SOLUTIONS.md, with wrong counts and broken references
- **Severity:** High
- **Location:** `SOLUTIONS.md` lines 120, 726, 906, 1652, 1904, 2018, 2141, 2270, 2349, 2437, 2533, 2593, 2674, 3182, 3233 (15 of 29 module sections)
- **Description:** The last "Burp workflow" line of 15 module sections has leftover generation metadata appended, e.g. "Module: xss (Cross-Site Scripting). Challenges covered: 11. File written: docs/burp-flows/xss.md." Problems: (a) `docs/burp-flows/` does not exist, so the reference is broken; (b) five of the counts are wrong; (c) the format varies section to section; (d) only 15 of 29 sections carry it, so it reads as accidental.
- **Evidence:** Line 120 claims "Challenges covered: 11" for xss (actual: 9 challenge files, 9 numbered solutions). Line 726 claims "10 challenges covered" for ssrf (actual 9). Line 906 claims "Challenge count: 10" for upload (actual 8). Line 2349 claims "6 challenges covered" for redirect (actual 5). Line 2437 claims "Challenges covered: 6 of 6" for hostheader (actual 5).
- **Recommendation:** Strip all scaffolding lines from SOLUTIONS.md. If per-module counts are wanted, generate them from the actual numbered entries instead of hardcoding.

### F3. SOLUTIONS.md XSS beacon steps are stale: missing the page-bound nonce
- **Severity:** High
- **Location:** `SOLUTIONS.md` lines 32-35 (Reflected), 38-41 (Stored), 45-48 (DOM), and beacon payloads at lines 59, 65, 74, 79, 97
- **Description:** The solutions tell the student to fire `GET /xss/collect?c=abc&v=reflected` (and `stored`, `dom`) to earn the flag. The current code (`modules/xss/index.js`, `router.get('/collect')`) requires a page-bound single-use nonce `n` (via `xssConsumeNonce`, rendered as `window.__px`); a beacon without it returns 400 "No flag". Following the documented steps verbatim fails to earn the flag. The beacon payloads shown for the later XSS challenges (attr-breakout, js-context, markdown, svg-upload, backtick) also omit `&n='+window.__px`, while the lab's own `EXFIL_PAYLOAD` (`modules/xss/shared.js`) includes it.
- **Evidence:** "Finally request `/xss/collect?c=abc&v=reflected` in Repeater to simulate the victim beacon and confirm the flag path works end to end." Code: `if (c.length > 0 && VULN_IDS.includes(v) && xssConsumeNonce(req, v, n))` else 400.
- **Recommendation:** Update every XSS solution to include the nonce: `GET /xss/collect?c=abc&v=<id>&n=<window.__px value>`, and explain that the nonce comes from the challenge page. Verify each revised step by booting the lab and firing the beacon.

### F4. README "The lab catalog" rows are stale and name non-existent challenges
- **Severity:** High
- **Location:** `README.md` catalog table (the "201 intentionally vulnerable challenges across 29 modules" section)
- **Description:** Multiple module rows describe a different challenge set than the one that ships. This is the first thing a prospective user reads, and it is wrong in at least nine rows.
- **Evidence / fixes:**
  - **auth** row lists "JWT `alg=none`" (that challenge lives in the jwt module, not auth), plus "Remember-me tampering" and "API key in HTML comment", neither of which exists anywhere. Real auth challenges: No Rate Limiting, Password Change Without Current Password, 4-Digit OTP, SHA-256 Predictable Reset Token, Predictable Password Reset Tokens, Guessable Security Question, Support Ticket Impersonation, Username Enumeration.
  - **csrf** row lists "Login CSRF" and "2FA disable via GET"; neither exists (login CSRF is an oauth challenge; no 2FA challenge exists in the repo).
  - **http** row lists six items for three challenges ("Method override", "`X-Forwarded-For` trust", "Referer auth" do not exist in the module).
  - **redirect** row lists "OAuth code theft"; no such challenge exists in the redirect module.
  - **xss** row claims stored XSS in "guestbook, profile bio, SVG upload"; there is no profile-bio XSS challenge (the profile-name stored challenge is in csti). It also omits the template-literal (backtick) challenge.
  - **api** row lists six items for five challenges ("ID enumeration" is extra).
  - **oauth** row omits "Client Secret in Public JavaScript" and calls it "PKCE skip" where the challenge is "PKCE Downgrade".
  - **crypto** row omits "Base64 cookie tampering" and "Key in JavaScript".
  - **upload** row omits "Avatar overwrite"; **misconfig** row omits "Robots.txt Disclosure".
- **Recommendation:** Regenerate the catalog table from the actual `name` fields in the challenge files (a script can do this), and add a CI check or generation step so it cannot drift again.

### F5. SSTI module briefing names the exact flag variable
- **Severity:** Medium
- **Location:** `modules/ssti/index.js` line 48
- **Description:** The module briefing tells the student to "try `{{secretFlag}}`", which is the literal in-scope variable name in `modules/ssti/challenges/rce.js` (line 35: `const secretFlag = flagFor('ssti', 'rce')`). The rce challenge's own hint ladder is carefully written to make scope probing the exercise ("Probe for the one holding the flag: its name is the most obvious one you would pick for this job"), but the briefing removes that exercise before the student opens the challenge.
- **Evidence:** "then look for variables in scope and try `{{secretFlag}}`."
- **Recommendation:** Change to "then look for variables in scope" (keep the concept, drop the literal). The `{{7*7}}` mention in the same briefing is fine: it is the standard first-step proof for the basic challenge.

### F6. `how` summaries on module index cards hand over exact payloads
- **Severity:** Medium
- **Location:** `how` fields rendered by `modules/*/index.js` via `<p>${esc(v.how)}</p>` on each challenge card, visible before the challenge is opened
- **Description:** The `how` one-liner is meant to be a teaser, but several contain the complete working payload, so a student can copy it without ever engaging the hint ladder. The hint ladders themselves are well graded; the leak is in the card summaries.
- **Evidence (worst offenders):**
  - `modules/cmdi/challenges/cmdi-wildcard.js` (Hard): `how` contains the literal payload `host=127.0.0.1;/???/bin/?at /???/p?sswd`.
  - `modules/ssrf/challenges/ssrf-file.js`: `how` is literally "set the url parameter to file:///etc/passwd".
  - `modules/ssti/challenges/ssti-rce.js` (Hard): `how` contains `expr={{require("child_process").execSync("id").toString()}}`.
  - `modules/ssti/challenges/ssti-nounderscore.js`: `how` contains `input={{eval("db"+String.fromCharCode(95)+"pass")}}`.
  - `modules/crypto/challenges/crypto-cbc-bitflip.js`: `how` gives the full bit-flipping recipe (decode, XOR IV bytes over "guest", re-encode, POST).
  - `modules/misconfig/challenges/env.js`: "Request /misconfig/.env"; `swp.js`: "Fetch /misconfig/app.js.swp"; `manager.js`: "set to the vendor default admin:admin"; `debug.js`: "(err=1)"; `backup.js` START: "replay the page request in Repeater with the path changed to /misconfig/backup.sql"; `listing.js` HOW: "spot secret.txt in the listing".
  - `modules/upload/challenges/upload-strip-once.js` START: exact bypass filename `evil.s.svgvg`; `upload-traversal.js` START: exact `../pwn.txt` chain.
  - `modules/cors/challenges/cors-reflect.js`: exact `Origin: https://evil.com` (borderline; the concept is the lesson, but the exact winning value is handed over).
- **Recommendation:** Rewrite these `how` lines as concept teasers (what to investigate, which tool to use), moving exact payloads into SOLUTIONS.md where they belong. Keep `{{7*7}}` in the ssti/basic and csti cards: that is deliberate first-step pedagogy, not a leak.

### F7. Dropped verb in two XXE challenge summaries
- **Severity:** Medium
- **Location:** `modules/xxe/challenges/xxe-svg.js` line 57 (`how`), `modules/xxe/challenges/xxe-xinclude.js` (`how`)
- **Description:** "Burp" is used as a verb where "Proxy" was meant, producing ungrammatical sentences.
- **Evidence:** "Burp the SVG extractor form, send the POST to Repeater..." and "Burp the XInclude importer form, send the POST to Repeater..."
- **Recommendation:** Change to "Proxy the SVG extractor form in Burp, send the POST to Repeater..." (and likewise for XInclude).

### F8. Billion-laughs challenge page hands over the exact entity shape
- **Severity:** Medium
- **Location:** `modules/xxe/challenges/xxe-billion-laughs.js` line 34 (on-page `hintBox`)
- **Description:** The hint box printed on the challenge page gives the classic payload shape verbatim, including entity names and nesting depth, so the "Hard" challenge reduces to transcription.
- **Evidence:** "Classic shape: `<!ENTITY lol "xxxxxxxxxx">`, then `<!ENTITY lol2 "&lol;&lol;... (x10)">`, up to `lol7`, and reference `&lol7;` in the body. Each level multiplies the work by ten."
- **Recommendation:** Keep the concept ("entities can reference each other; each level multiplies the work") but remove the exact entity names and the x10/lol7 specifics. The `how` field already describes the shape adequately.

### F9. D18: flag-storage naming in internal docs (no student-facing hits)
- **Severity:** Medium
- **Location:** `MODULE_CONTRACT.md` line 66; `docs/roadmap/ARCHITECTURE_ASSESSMENT.md` line 425; `docs/audit/burp/w064.md` line 78; `docs/roadmap/PROGRESS.md` line 99
- **Description:** Four internal dev/roadmap/audit docs name the flag-storage mechanism explicitly. No student-facing prose does: README.md, SOLUTIONS.md, TOOL_SETUP_GUIDE.md, all module briefings, and all challenge hint/how/start text are clean. The per-deployment randomness language in README.md and SOLUTIONS.md is exemplary.
- **Evidence:** MODULE_CONTRACT.md: "Flags are random per deployment and live only in the `flags` table." ARCHITECTURE_ASSESSMENT.md: "looks up the per-deployment random flag from the `flags` table and marks capture". w064.md: "The flags table holds a registered flag for oauth:code-leak". PROGRESS.md: "`fix_badges` SQLite table keyed by express `sessionID` (same user identity as the flag system)".
- **Recommendation:** Reword all four to avoid naming the storage mechanism, e.g. "Flags are random per deployment; use `award()` / `flagFor()` and never touch storage directly." The MODULE_CONTRACT one matters most since it is the active contract future contributors read. (Also noted: `app.js` line 98 has a code comment naming storage; internal-only, but the same reword applies.)

### F10. TOOL_SETUP_GUIDE: stale cross-reference in the troubleshooting table
- **Severity:** Low
- **Location:** `docs/TOOL_SETUP_GUIDE.md`, Troubleshooting table, "Certificate errors on every HTTPS page" row
- **Description:** Points the reader to "(see Section B, step 4)". There is no Section B; sections are numbered 1-6, and the CA install is in section 2.
- **Evidence:** "(see Section B, step 4)"
- **Recommendation:** Change to "(see section 2, Installing the Burp CA certificate)".

### F11. TOOL_SETUP_GUIDE recommends Pro-only features while promising Community is enough
- **Severity:** Low
- **Location:** `docs/TOOL_SETUP_GUIDE.md` section 6, "Which tool for which module type" table
- **Description:** The table recommends "Burp Collaborator for out-of-band checks" (SSRF, command injection, XXE rows) and "Turbo Intruder extension for parallel requests" (race conditions row). Collaborator requires Burp Pro, and Turbo Intruder's high-speed engine is Pro-gated, while section 1 and the README both state Community Edition clears all 201 challenges and "you will not need" Pro features here.
- **Evidence:** Rows: "SSRF | Burp Suite (Repeater) | Burp Collaborator for out-of-band checks"; "Race conditions | Burp Suite (Repeater, Intruder) | Turbo Intruder extension for parallel requests".
- **Recommendation:** Either mark these as "(Pro)" with a note that the lab is solvable without them, or replace with Community-compatible alternatives (e.g. the in-lab OOB collector at `/xxe/collector`, which the challenges already provide; time-delay payloads in Repeater).

### F12. Em-dash sweep: clean
- **Severity:** None (informational)
- **Location:** repo-wide
- **Description:** Zero em dashes in prose. The only matches are `lib/certpng.js` line 293 (a unicode-to-ASCII mapping table for certificate PNG rendering, code not prose) and `docs/roadmap/SWARM_BRIEFS.md` lines 47 and 70 (which describe the `grep -rn U+2014` check itself). No en dashes found either.
- **Recommendation:** No action.

### F13. Inconsistent challenge-name capitalization
- **Severity:** Low
- **Location:** `modules/upload/challenges/stored-xss.js` line 87
- **Description:** Name is 'Stored XSS via file upload' while every other challenge name is title-cased.
- **Evidence:** "Stored XSS via file upload" vs siblings like 'GIF/HTML polyglot', 'Path traversal on write'.
- **Recommendation:** "Stored XSS via File Upload".

### F14. SOLUTIONS.md wording: "the node/jwt CLI"
- **Severity:** Low
- **Location:** `modules/jwt/challenges/alg-confusion.js` line 23 (`start` field, rendered on the challenge card and challenge page)
- **Description:** "(the node/jwt CLI is the quickest way)" names a tool that does not exist; the solutions all use `node -e` with the `jsonwebtoken` package.
- **Evidence:** "Mint an HS256 token with role admin signed with those PEM bytes (the node/jwt CLI is the quickest way)"
- **Recommendation:** "a short `node -e` script with the `jsonwebtoken` package is the quickest way".

### F15. SOLUTIONS.md flags/DB-path adjacency (borderline D18)
- **Severity:** Low
- **Location:** `SOLUTIONS.md` line 1689
- **Description:** The closing note says "All flags look like `PENTRIX{...}`. If a payload stops working, reset the lab database by deleting `data/vulnlab.db` and restarting the app". It does not state flags live there, but naming the DB file path in the same breath as flags is needlessly adjacent to the D18 line.
- **Evidence:** as quoted.
- **Recommendation:** Split into two sentences and drop the path: "If a payload stops working, reset the lab (delete the local app data and restart)". The path is already documented in README's project layout for operators.

---

## Tone assessment

Clean. The voice across briefings, hints, and guides is encouraging, precise, and Burp-first. No condescending language ("obviously", "trivially", "even a child", "stupid", "dumb") appears in any student-facing text; the few "trivially" hits are in code comments and SOLUTIONS.md "Why it works" sections describing the vulnerability itself, which is appropriate. The hint ladders genuinely nudge (question first, technique second, explicit last), matching the labeled Nudge/Technique/Explicit pattern in `lib/page.js`. The sqli/lfi/cmdi hint ladders are the best in the repo. Watch items: the all-caps "KEY INSIGHT:" prefix in some upload hints is shouty but consistent enough to read as a brand tic; several `hint` fields repeat the `how` almost verbatim (auth/reset, bizlogic/biz-negative-qty), which is redundant rather than wrong.

## Spelling and grammar

No common misspellings found across all 201 challenge files, SOLUTIONS.md, README.md, or TOOL_SETUP_GUIDE.md. The only grammar defects are F7 ("Burp the SVG extractor form" / "Burp the XInclude importer form").

## SOLUTIONS.md accuracy: 10-solution sample vs code

| # | Solution | Verdict |
|---|---|---|
| 1 | sqli login bypass (`POST /sqli/login`, `admin' OR '1'='1`) | Accurate: route exists, interpolation confirmed in `modules/sqli/challenges/login-bypass.js` |
| 2 | auth brute-force (5+ failed attempts, then alice) | Accurate: `modules/auth/challenges/brute-force.js` awards when `username === 'alice' && attempts >= 5` |
| 3 | cmdi Ping Gadget v7 wildcard payload | Accurate: `GET /cmdi/ping7`, filter regexes confirmed, award on `?` + passwd evidence |
| 4 | ssti basic (`name={{7*7}}` -> 49) | Accurate: `GET /ssti/greet`, award when rendered output contains 49 |
| 5 | upload GIF/HTML polyglot | Accurate: `POST /upload/polyglot`, render at `/upload/poly/:name`, 6-byte magic check confirmed |
| 6 | xss reflected/stored/DOM beacon steps | **Stale (F3):** beacons omit the required `n` nonce; bare requests 400 |
| 7 | jwt alg-confusion (`/jwt/confusion-pubkey`, HS256 with public key bytes) | Accurate: routes and confusion logic confirmed |
| 8 | race double-spend (`POST /race/transfer`, `GET /race/reset`) | Accurate: both routes exist, 150-250ms window confirmed in code comments |
| 9 | ssrf basic (`/ssrf/fetch`, loopback to `/ssrf/internal/secret`) | Accurate: internal routes exist in `modules/ssrf/index.js` |
| 10 | oauth code replay (exchange twice at `/oauth/idp/token`) | Accurate: replay-mints-fresh-token behavior confirmed in challenge prose and the w064 audit note |

All challenge IDs are unique across the 201 files (an early regex pass falsely flagged `jwt/main` twice; it was matching the JWT `kid: 'main'` header in sample-token code, not the vuln `id`. The real IDs are `kid-default` and `kid-sqli`. No duplicate-ID defect exists.)

## Top-10 prioritized list

1. **Delete or archive `solutions/batch-*.md`** (F1): they document non-existent challenges and routes; a student following them will chase ghosts.
2. **Regenerate the README catalog from actual challenge names** (F4): nine rows are wrong, including challenges attributed to the wrong module.
3. **Fix the SOLUTIONS.md XSS beacon steps to include the `n` nonce** (F3): the documented steps fail verbatim against current code.
4. **Strip the generator scaffolding from SOLUTIONS.md** (F2): broken `docs/burp-flows/` references, five wrong counts, inconsistent formatting.
5. **Remove `{{secretFlag}}` from the SSTI module briefing** (F5): it hands over the rce challenge's answer.
6. **De-spoil the `how` card summaries** (F6): exact payloads for cmdi-wildcard, ssrf-file, ssti-rce, cbc-bitflip, and the misconfig filename/credential giveaways belong in SOLUTIONS.md, not on the index cards.
7. **Reword the four internal D18 hits** (F9): MODULE_CONTRACT.md first, since it is the active contributor contract.
8. **Fix the two "Burp the ..." verb drops** (F7) and the billion-laughs hint box (F8).
9. **Fix the TOOL_SETUP_GUIDE "Section B" reference** (F10) and the Pro-only tool recommendations (F11).
10. **Minor polish:** title-case "Stored XSS via File Upload" (F13), fix "the node/jwt CLI" (F14), de-adjacent the flags/DB-path note (F15).
