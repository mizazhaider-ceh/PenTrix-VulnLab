# EXPERT IMPROVEMENT AUDIT: PenTrix-VulnLab

**Date:** 2026-10-20
**Method:** Six independent expert auditors (offensive-security, lab instructor, Burp workflow specialist, UX reviewer, content/briefing editor, code-quality reviewer) audited the repo at `~/workspace/pentrix-vulnlab/` (commit 2ae7e9f) plus live test instances. Read-only; no code changed.
**Per-expert reports:** `docs/audit/expert-audit/` (offensive-security.md, lab-instructor.md, burp-workflow.md, ux-reviewer.md, content-editor.md, code-quality.md)
**Doctrines honored:** no flag-storage details disclosed anywhere; zero em dashes.

---

## Top 10 cross-cutting improvements (ranked by severity x impact)

1. **XXE flags awarded for echoing a literal marker, no entity required (Critical).** Six XXE challenges award when a marker string merely appears in output. One request with the literal marker earns the flag; one variant is fully black-box because the module page prints the marker. Require proof of entity resolution: marker in output AND absent from raw input, plus an `<!ENTITY ... SYSTEM ...>` declaration. Add adversarial negative tests. (offensive-security F1)
2. **Beacon nonces forgeable with plain curl across ~21 challenges (High).** XSS, CSTI, JSONP, and postMessage challenges award on a beacon carrying a nonce scraped from page HTML. Zero JavaScript executes. Move stored XSS to a victim-bot model; make tokens derivable only via JS execution elsewhere; stop rendering raw tokens in HTML. (offensive-security F2)
3. **Race module state is global across all students; `GET /race/reset` wipes everyone (High).** One module-global state object means one student's redeem blocks everyone else's, and an unauthenticated CSRF-able GET link resets all 30 students at once. Scope state per session; make reset a POST. (code-quality P1)
4. **Fix-mode runner has no memory cap and blocks the event loop ~6s per submission (High).** Student code can OOM-kill the whole Node process; each submission re-runs validation 3x plus student code 3x. Isolate in `worker_threads` with `resourceLimits`; cache `validateBlock()` per block; rate-limit the endpoint. (code-quality X1, X2)
5. **No `unhandledRejection` handler; async handlers can crash the lab (High).** Node 24's default is `throw`. All seven race async handlers have zero `try/catch`; one throw after an `await` kills the lab for all students. Add an async-handler wrapper plus a process-level log. (code-quality E1)
6. **CSRF challenges award for self-requests (High).** Three challenges grant the flag for changing your own email in your own session, with a clickable "Load the forged request" shortcut. Require cross-site evidence (Referer/Origin like `referer-bypass` does) or a victim-bot; remove the shortcut. (offensive-security F3)
7. **Upload stored-XSS awards the flag at upload time (High).** A one-byte `.html` file earns the flag; nothing ever executes. Award on proven execution (beacon after serving inline), not on file receipt. (offensive-security F4)
8. **Race guidance prescribes throttled Community Intruder for a 150-250ms window (High).** The documented 20-concurrent-request Intruder workflow cannot work on Burp Community, breaking the "Community edition sufficient" promise for all 8 race challenges. Teach Repeater's "Send group in parallel" (single-packet attack) first. (burp-workflow F1)
9. **crypto-rand-pin needs 1,000,000 Intruder payloads on Community (High).** Days of throttled fuzzing, contradicting the docs' "guessable spaces are small". Shrink the space, teach `Math.random()` prediction honestly, or sanction Turbo Intruder. (burp-workflow F2)
10. **Burp setup cliff: nothing in the web UI links the setup guide (High).** The lab is Burp-first, but the first challenge's Starting point assumes Burp Proxy is configured and `/about` never mentions Burp. Add a "Set up Burp first" card to `/about` and the Start-here page. (lab-instructor F1)

---

## A. Flag integrity and FLAG BAR

- **A1 (Critical):** XXE echo-marker awards, see top-10 #1. (offensive-security F1)
- **A2 (High):** Beacon-nonce forgery, see top-10 #2. (offensive-security F2)
- **A3 (High):** CSRF self-request awards, see top-10 #6. (offensive-security F3)
- **A4 (High):** Upload award-on-store, see top-10 #7. (offensive-security F4)
- **A5 (Medium):** proto-client claim endpoint awards on `GET /proto/client/claim?theme=dark` with no page load and no actual pollution, contradicting the page's own "genuinely polluted" statement. Bind the claim to evidence of a real polluted render (server-issued one-time token echoed by page script). (burp-workflow F3)
- **A6 (Medium):** upload-case and upload-double-ext cross-award each other's flags; one endpoint captures both challenges. Each challenge file should award only its own id. (offensive-security F5)
- **A7 (Low):** ~10 misconfig flags are single-GET discovery, at the edge of the FLAG BAR. Keep discovery but require using what is found (e.g. the `/.env` password must authenticate somewhere; the backup hash must be cracked). (offensive-security F9)
- **A8 (Low):** Test suite has a cheat-shaped blind spot: negative tests use benign input, never adversarial input (marker literals, beacon-without-load, self-CSRF, trivial uploads). The XXE cheat passes the full suite today. Add adversarial negative tests per module. (offensive-security F10)

**What held up:** per-install random flags with no literals in source; scenario stage gating; sqli union/second-order/blind; idor; auth brute-force/reset/OTP; jwt none/weak-secret; crypto ecb-oracle/cbc-bitflip/hash-ext/md5; lfi traversal/log-poison; ssrf bypasses; race TOCTOU; bizlogic; proto pollution; cmdi output check; csrf referer-bypass; hostheader evil-collect; cache-deception; formula export. All 155 `award()` call sites target registered challenges; every flag display is capture-gated; awarding is idempotent. (offensive-security, code-quality)

## B. Classroom robustness (shared-instance safety)

- **B1 (High):** Race global state + CSRF-able reset, see top-10 #3. (code-quality P1)
- **B2 (High):** Fix-mode memory/CPU DoS, see top-10 #4. (code-quality X1, X2)
- **B3 (High):** No `unhandledRejection` handler, see top-10 #5. (code-quality E1)
- **B4 (Medium):** `docker-compose.yml` ships with `SESSION_SECRET` commented out, so real deployments use the public fallback secret; combined with deliberately non-httpOnly cookies, cross-student session hijack is trivial. Generate and persist a random secret on first boot. (code-quality S1)
- **B5 (Medium):** `saveUninitialized: true` with purge-only-at-boot grows the session store unboundedly. Set `saveUninitialized: false`; purge on a timer. (code-quality S2)
- **B6 (Medium):** No concurrency tests despite a race-condition module and shared global state; zero tests assert 500 paths and only 7/43 files check 4xx. Add `platform-errors.test.js` and parallel-burst/two-client race tests. (code-quality T1, T2)
- **B7 (Medium):** hostheader internal agent binds fixed port 13919 at require time; silent degradation on conflict. Bind port 0 or make configurable. (code-quality P2)
- **B8 (Medium):** Six modules implement award-adjacent verifier routes in `index.js` against the thin-aggregator contract (notably 399-line `oauth/index.js`). Move to `shared.js`; lint `index.js` for `award(`. (code-quality A1)
- **B9 (Low):** 20/201 challenge files lack the required `// VULN:` marker. Add a static test asserting the marker. (code-quality A2)
- **B10 (Low):** Oversized bodies return 500 instead of 413. Branch `entity.too.large` to a 413 response. (code-quality E2)
- **B11 (Low):** Uploads accumulate with no quota/cleanup; committed test artifacts `sb-escape.txt`/`trav-escape.txt` at repo root. Sweep old files; gitignore the artifacts; make tests clean up. (code-quality P3, P4)

## C. Teaching, curriculum, and onboarding

- **C1 (High):** Burp setup cliff, see top-10 #10. (lab-instructor F1)
- **C2 (High):** Homepage module grid is alphabetical, ignoring the curriculum track order; Beginner CSRF ("Start here") is card 07 while Intermediate API is card 01. Order by track (Foundations first) with track tags on cards. (lab-instructor F2)
- **C3 (High):** Within-module difficulty cliff jumps in 26/29 modules (crypto, ssrf, xxe, hostheader put a Hard challenge at #2). Reorder easy-to-hard or add recommended-order numbering. (lab-instructor F3)
- **C4 (High):** No classroom tooling: no progress export, no per-student reset, progress is a browser cookie, event mode does not exist. Ship the minimum: scoreboard CSV export, documented reset procedure, `docs/CLASSROOM.md` with isolation notes. (lab-instructor F4)
- **C5 (High):** Certificates are per-install, not per-student: the PTX code derives from install identity + path id only, so all classmates get identical codes. Bind the code to a student identifier or document that it is not identity-bound. (lab-instructor F5)
- **C6 (Medium):** Challenge titles + hint 1 announce the bug class, contradicting the README's "discover, not announce" promise. Decide the doctrine: neutral titles with the reveal in hint 2, or own the technique-practice framing in the README. (lab-instructor F6)
- **C7 (Medium):** Briefing depth is uneven: ~20 modules open with a tagline while csrf/xss/proto/crypto have full "What is X?" explainers. Add 3-5 sentence explainers following the csrf/proto pattern. (lab-instructor F7)
- **C8 (Medium):** Four hint ladders are front-loaded (key primitive in hint 2): jwt/none-admin, race/race-coupon, csti/constructor, proto/proto-constructor. Move the primitive to hint 3. (lab-instructor F8)
- **C9 (Medium):** Three different "first steps" (home says csrf, paths say xss, curriculum says misconfig), and the csrf track banner declares "Prerequisites: xss". Pick one canonical entry module and align all three. (lab-instructor F9)
- **C10 (Medium):** Crypto secrets rotate per boot with no UI recovery warning; a restart silently invalidates in-progress crypto work. Add a dismissible notice when the boot id changed. (lab-instructor F10)
- **C11 (Medium):** Difficulty taxonomy is split (modules: Beginner/Intermediate/Advanced; challenges: Easy/Medium/Hard) and `DIFF_DOTS` has no `advanced` key, so the 4 Advanced modules render a grey "unknown" dot. Unify on one taxonomy; map `advanced` at minimum. (ux-reviewer F4, lab-instructor F13, offensive-security F7)
- **C12 (Medium):** SSTI module has zero Easy challenges; only 7 Beginner labels across 201 challenges; path step 1 teaches `alert()` but the flag needs a beacon. Add an Easy SSTI entry and fix the step-1 mismatch. (offensive-security F7)
- **C13 (Low):** Break-then-fix piloted on only sqli+xss; expand to the Foundations track next (misconfig, idor, csrf). (lab-instructor F12)
- **C14 (Low):** No time estimates per challenge; students cannot plan a session. Add rough 10/30/60+ min estimates to cards. (lab-instructor F13)

**Strengths to protect:** uniform 3-level hint ladders on 200/201 challenges; Burp-first voice in hints and SOLUTIONS.md; real narrative kill-chain scenarios with hard stage unlocking; paths with teaching notes and honest soft gating; break-then-fix pilot is the right defensive half. (lab-instructor)

## D. Burp-first fidelity (D17)

- **D1 (High):** Race Intruder guidance broken on Community, see top-10 #8. (burp-workflow F1)
- **D2 (High):** crypto-rand-pin not Community-feasible, see top-10 #9. (burp-workflow F2)
- **D3 (Medium):** otp-bruteforce (10k codes) has no honest time estimate and no Grep-Match guidance though the challenge depends on it. Add the walkthrough + expected Community runtime. (burp-workflow F4)
- **D4 (Medium):** No documented Repeater "Send group in parallel" (single-packet attack) anywhere, though it is the Community answer to the race module. Add to the setup guide; rewrite race payload blocks. (burp-workflow F5)
- **D5 (Medium):** No Intruder Grep-Match/Grep-Extract walkthrough though otp-bruteforce and sqli/blind depend on it. Add a "Reading Intruder results" section; link from both challenges. (burp-workflow F6)
- **D6 (Medium):** CSRF module omits Burp's "Generate CSRF PoC" workflow (only email.js hint 3 mentions it). Add to each CSRF challenge + guide. (burp-workflow F7)
- **D7 (Low):** Proxy Match and Replace used by session/predictable but documented nowhere. Add a subsection; cross-link. (burp-workflow F8)
- **D8 (Low):** JWT module offers Node as the forge tool with no Burp-native alternative (Decoder base64url, JWT Editor extension). Add alongside the Node fallback. (burp-workflow F10)
- **D9 (Low):** Stale curl-framed code comment in misconfig/trace.js ("curl can") contradicts the Burp-first page copy. Reword. (burp-workflow F9)

**Verified:** all 29 modules Burp-solvable with plain HTTP; no global rate limiter or 429/IP-block logic; zero curl one-liners in challenge metadata; TOOL_SETUP_GUIDE.md accurate on Proxy/Repeater/Intruder/Decoder/Comparer/Logger. (burp-workflow)

## E. Content accuracy (docs, SOLUTIONS.md, README)

- **E1 (High):** `solutions/batch-01..12.md` are stale pre-dedupe drafts describing non-existent challenges/routes. Delete or archive with a clear header. (content-editor F1)
- **E2 (High):** SOLUTIONS.md has generator scaffolding in 15/29 module sections ("File written: docs/burp-flows/x.md"; that dir does not exist) with five wrong challenge counts. Strip all scaffolding. (content-editor F2)
- **E3 (High):** SOLUTIONS.md XSS beacon steps are stale: they omit the page-bound `n` nonce, so following them verbatim returns 400 and no flag. Update every XSS solution with `&n=<window.__px value>`. (content-editor F3)
- **E4 (High):** README "lab catalog" rows are stale in nine rows (challenges attributed to the wrong module, non-existent challenges listed, real ones omitted). Regenerate from actual challenge `name` fields; add a drift check. (content-editor F4)
- **E5 (Medium):** SSTI module briefing names the exact flag variable `{{secretFlag}}`, removing the rce challenge's scope-probing exercise. Drop the literal. (content-editor F5)
- **E6 (Medium):** `how` card summaries hand over exact payloads (cmdi-wildcard glob, `file:///etc/passwd`, SSTI RCE expression, CBC bit-flip recipe, misconfig filenames/credentials, upload bypass filenames). Rewrite as concept teasers; keep exact payloads in SOLUTIONS.md. (content-editor F6)
- **E7 (Medium):** Billion-laughs hint box prints the exact entity shape (names, nesting depth). Keep the concept, remove specifics. (content-editor F8)
- **E8 (Medium):** Four internal D18 hits name flag storage (MODULE_CONTRACT.md:66, ARCHITECTURE_ASSESSMENT.md:425, burp/w064.md:78, PROGRESS.md:99). No student-facing violations found. Reword all four; MODULE_CONTRACT.md first. (content-editor F9)
- **E9 (Low):** TOOL_SETUP_GUIDE points to nonexistent "Section B, step 4"; recommends Pro-only Collaborator/Turbo Intruder while promising Community suffices. Fix reference; mark Pro-only or give Community alternatives. (content-editor F10, F11)
- **E10 (Low):** "Burp the SVG/XInclude form" verb drops; "Stored XSS via file upload" capitalization; "the node/jwt CLI" phrasing; flags/DB-path adjacency in SOLUTIONS.md:1689. (content-editor F7, F13, F14, F15)

**Verified clean:** zero em dashes in prose; no misspellings in student-facing text; tone encouraging and Burp-first throughout; 9/10 sampled SOLUTIONS.md walkthroughs accurate; all 201 challenge IDs unique. (content-editor)

## F. UX consistency

- **F1 (High):** Progress chip (`0/201`) missing on every module page; module routers never pass `scoreChip` to `page()`. Move chip rendering into `page()` itself. (ux-reviewer F1)
- **F2 (High):** No breadcrumbs; challenge sub-pages strand scenario/path users (`/sqli/login` has zero back-links). Add `Modules / <Module> / <Challenge>` breadcrumbs plus back-to-scenario/path links. (ux-reviewer F3)
- **F3 (Medium):** No `aria-current` on nav for module pages. Pass `activeNav` from module routers. (ux-reviewer F2)
- **F4 (Medium):** Home difficulty filter cannot select Advanced modules (select lacks the option; 4 modules silently hidden). Generate options from actual values. (ux-reviewer F5)
- **F5 (Medium):** "Break then fix" repeats an identical "not available" paragraph per challenge (5x on `/api`). Render the module-level note once; skip per-challenge lines when a module has zero fix blocks. (ux-reviewer F6)
- **F6 (Medium):** Scoreboard challenge rows are not links. Deep-link each to `/<module>#<challenge-id>`. (ux-reviewer F7)
- **F7 (Medium):** Flag banner's "Next challenge" button is implemented but never wired by any caller. Pass `nextHref` to the next uncaptured challenge in the module. (ux-reviewer F8)
- **F8 (Medium):** 28/29 module pages have no `<h1>`. Render the module name as `<h1>`. (ux-reviewer F9)
- **F9 (Medium):** Beacon rejections fail silently ("No valid beacon received yet" with no reason). Surface the rejection reason near the claim widget or auto-expand the matching "Why beacons fail" bullet. (ux-reviewer F14)
- **F10 (Medium):** White text on the light end of the primary button gradient fails contrast (2.72:1). Darken the light stop (e.g. `#8B5CF6`). (ux-reviewer F12)
- **F11 (Medium):** Topbar nav crowds at phone widths (5 links + chip, no wrap strategy). Allow wrap or shorten labels on mobile. (ux-reviewer F11)
- **F12 (Low):** Primary buttons go full-width on mobile while secondaries do not; inconsistent action rows. Scope the rule or apply to both variants. (ux-reviewer F10)
- **F13 (Low):** Copy buttons are 36px tall, below the 44px touch guideline. Raise to 44px. (ux-reviewer F13)
- **F14 (Low):** Challenge sub-pages drop shared chrome (no chip, no nav highlight, no breadcrumb). Give them a slim consistent lab-chrome strip. (ux-reviewer F15)
- **F15 (Low):** `.reveal` animation has no safety net if the observer never fires (CSS hides content under `.js` with no `setTimeout` fallback). Add a 2s force-reveal and fix the comment. (ux-reviewer F16)
- **F16 (Low):** Google Fonts loaded externally on a "run locally only" lab; self-host the two font files in `public/`. (ux-reviewer F17)
- **F17 (Low):** Path step label `sqli`/`login-bypass` links to `/sqli/login`; labels should match routes. (ux-reviewer F18)
- **F18 (Low):** Scoreboard "fixes" pill is cryptic for new users ("0 fixes" reads as broken). Add a tooltip/explainer or hide until the first fix. (ux-reviewer F20)

**What is already good:** hint ladders (best UX in the app), flag banner, error pages, failed-login states, scenario/path deep links, table scroll containers, reduced-motion support, body-text contrast 11.7:1. (ux-reviewer)

## G. Vulnerability diversity and scope

- **G1 (Medium):** cmdi is 9x the same ping gadget with different blacklist evasions; injection dominates (56/201). Collapse cmdi variants to 3 and add a deserialization module and an XPath/LDAP module, the conspicuous absences. (offensive-security F8)
- **G2 (Low):** `http` (3), `formula` (4), `redos` (4) modules are thin relative to the catalog. (offensive-security F8)

---

## Consolidated top 20 (all themes, for backlog prioritization)

1. XXE echo-marker FLAG BAR failure (Critical) - A1
2. Beacon-nonce forgery, ~21 challenges (High) - A2
3. Race global state + CSRF-able reset (High) - B1
4. Fix-mode memory/CPU DoS (High) - B2
5. Missing unhandledRejection handler (High) - B3
6. CSRF self-request awards (High) - A3
7. Upload award-on-store (High) - A4
8. Race Intruder guidance vs Community (High) - D1
9. crypto-rand-pin Community feasibility (High) - D2
10. Burp setup cliff, no in-app guide link (High) - C1
11. Stale `solutions/batch-*.md` drafts (High) - E1
12. Stale SOLUTIONS.md XSS beacon steps (High) - E3
13. Stale README catalog, nine rows wrong (High) - E4
14. SOLUTIONS.md generator scaffolding (High) - E2
15. Progress chip missing on module pages (High) - F1
16. No breadcrumbs, stranded challenge pages (High) - F2
17. Homepage ignores curriculum track order (High) - C2
18. Within-module difficulty cliffs, 26/29 modules (High) - C3
19. No classroom tooling (export/reset/isolation) (High) - C4
20. Per-install (not per-student) certificates (High) - C5
