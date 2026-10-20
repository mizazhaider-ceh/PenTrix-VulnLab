# Lab Instructor Audit: PenTrix-VulnLab (Teaching Quality)

**Auditor role:** Lab instructor (teaching expert)
**Date:** 2026-10-20
**Scope:** Read-only audit against the live test instance at `http://127.0.0.1:18402/` plus repo source at `~/workspace/pentrix-vulnlab/`. No code changed, nothing pushed.
**Method:** Simulated a beginner's first 15 minutes from the homepage; read `/`, `/about`, `/scoreboard`, `/scenarios`, `/paths`, and 12 module pages end to end; sampled 16 challenge hint ladders from rendered module pages; extracted the difficulty sequence of every challenge in all 29 modules from `index.js` require order (verified against rendered pages); read 8 SOLUTIONS.md sections in full; checked classroom-relevant mechanics (sessions, certificates, reset, export).

## What is already excellent (do not break)

- **Uniform 3-level hint ladders.** 200 of 201 challenges ship exactly the Nudge / Technique / Explicit ladder (the one outlier, `xxe/ssrf`, has a fourth step). This is the single best-implemented teaching system in the lab.
- **Burp-first voice is real, not a slogan.** Hints, Starting points, and every SOLUTIONS.md walkthrough name the Burp step (Proxy, Repeater, Intruder, Decoder). The SOLUTIONS.md Burp setup section is genuinely good.
- **Module pages teach before they ask**, at least in the best modules: csrf, xss, proto, and crypto explain the vulnerability class, the fictional app, login state, and the exact claim mechanism before any challenge card.
- **Scenarios are real kill chains**, not challenge lists: each has a written story, per-stage briefings, and hard stage unlocking (verified on `/scenarios/shop-takeover`).
- **Paths are well built:** ordered steps with per-step teaching notes, soft prerequisite gating ("guidance, not a lock"), and certificates.
- **Honest limitations in the UI:** "Fix mode is not available for this challenge yet" and certificate verify pages that state plainly they only validate on the issuing install.
- **Break-then-fix pilot** (sqli + xss) is the right defensive half of the pedagogy.

---

## Findings

### F1. Burp setup cliff in the first 15 minutes
- **Severity:** High
- **Location:** `/about` ("How to use"), every module page's challenge cards ("Starting point" boxes), `docs/TOOL_SETUP_GUIDE.md` (exists but unlinked)
- **Description:** The lab is Burp-first, but nothing in the web UI tells a beginner how to install and configure Burp. The very first challenge's Starting point says "Route your browser through Burp Proxy, log in as alice, and open the Email settings page," which assumes setup is done. The step-by-step setup guide (`docs/TOOL_SETUP_GUIDE.md`) is linked only from README.md and SOLUTIONS.md, neither of which a browser-only beginner will open. `/about`'s "How to use" section never mentions Burp at all.
- **Evidence:** `grep -rln "TOOL_SETUP_GUIDE" lib/ modules/*/index.js app.js` returns nothing. `/about` text: "Pick a module on the home page... Read the briefing... Exploit the vulnerability the way a real attacker would." No tool mention.
- **Recommendation:** Add a "Set up Burp first (2 minutes)" card to `/about` and to the Start-here module page, linking the setup guide. One line in each Starting point is not enough; the guide link must be one click from the UI.

### F2. Homepage module grid ignores the curriculum's track order
- **Severity:** High
- **Location:** `/` (home route in `app.js`), contrast with `docs/curriculum/LEARNING_PATHS.md`
- **Description:** The 29 module cards render in alphabetical order: 01 API Security (Intermediate), 02 Broken Authentication (Intermediate), 03 Business Logic (Intermediate), 04 Command Injection, 05 CORS, 06 Cryptographic Failures (Advanced)... The Beginner CSRF module, the designated "Start here," is card 07. The curriculum doc defines a Foundations track that starts with misconfig, but the UI never shows it. A beginner scrolling the grid meets six Intermediate/Advanced modules before the entry point.
- **Evidence:** Extracted card order from the live homepage; `LEARNING_PATHS.md` lists Foundations first (misconfig, idor, xss, csrf, redirect, http, formula).
- **Recommendation:** Order the homepage grid by track (Foundations first, then Injection, Auth and Sessions, Advanced topics), keeping search and difficulty filters. Add a small track tag to each card so the curriculum structure is visible from home.

### F3. Within-module difficulty ordering has cliff jumps in 26 of 29 modules
- **Severity:** High
- **Location:** Challenge card order on module pages (driven by `require` order in each `modules/<id>/index.js`)
- **Description:** A student working top-to-bottom through a module hits Hard challenges far too early, then drops back to Easy ones later. Only csrf, redirect, and ssti are monotonically ordered. Worst cases:
  - **crypto:** Easy (PIN brute force) then **Hard ECB byte-at-a-time oracle as challenge #2**, then two more Hards, then Easies.
  - **ssrf:** Medium, then **Hard blocklist bypass as #2**; the two Easy challenges (userinfo #4, zero-ip #7) are buried.
  - **xxe:** Medium, then **Hard as #2**.
  - **hostheader:** Medium, then **Hard cache poisoning as #2**, then Easies at #4-5.
  - **jwt:** Easy, Medium, Medium, **Hard, Hard**, then Easy (no-expiry) at #6.
  - **sqli:** second-order SQLi (Hard) sits at #6 of 11, ahead of Easy limit-offset at #8 and easier UNION work at #10.
- **Evidence:** Difficulty sequence extracted from every module's `index.js` require order and cross-checked against rendered module pages (e.g. `/crypto` shows PIN then ECB oracle).
- **Recommendation:** Reorder challenges within each module from easy to hard (fix at least the "Hard as challenge #2" cases in crypto, ssrf, xxe, hostheader), or add explicit "recommended order" numbering on the cards. This is the cheapest high-impact teaching fix in the lab.

### F4. No classroom tooling: no export, no reset, no student isolation
- **Severity:** High
- **Location:** `/scoreboard`, `lib/flags.js` (progress in `req.session.flags`), README.md line 37 ("event mode is on the way")
- **Description:** An instructor cannot run a class on this today: there is no progress export (no CSV/JSON download from the scoreboard), no per-student or per-class progress reset (the "Reset" links on `/` and `/scoreboard` only clear search filters), no student accounts or isolation (progress is a browser session cookie; two students on one machine share or clobber state), and the promised event mode does not exist. Sessions do persist in `sessions.db` across restarts, which is good, but nothing is documented for the instructor.
- **Evidence:** `award()`/`captured()` in `lib/flags.js` key progress off `req.session`; no export route exists in `app.js`; README explicitly defers event mode.
- **Recommendation:** Ship the minimum classroom kit: (1) a "Download progress (CSV)" button on the scoreboard, (2) a documented reset procedure (which file/rows to clear), (3) a short `docs/CLASSROOM.md` covering one-instance-per-student vs shared-instance trade-offs, the `SESSION_SECRET` requirement for any shared use, and student isolation notes.

### F5. Certificates are per-install, not per-student
- **Severity:** High
- **Location:** `paths/index.js` (`verifyCodeFor`, `/paths/:id/certificate`, `/paths/:id/verify`)
- **Description:** The certificate verification code (`PTX-XXXXXXXX`) is derived from the install identity plus the path id only. Every student who completes a path on the same install gets the identical code, and the verify page only works on the issuing machine. A certificate therefore proves "someone finished this path on this install," not "this person finished it." Classmates can copy each other's codes and all verify as valid.
- **Evidence:** `verifyCodeFor` hashes `installId() + ':' + pathId`; code comment: "a certificate minted on another machine cannot verify here."
- **Recommendation:** Bind the code to a student identifier (name or email entered when the certificate is minted) or, at minimum, document on the certificate and verify page that the code is not identity-bound and is unsuitable as a credential.

### F6. The "discover the bug" promise contradicts the challenge naming
- **Severity:** Medium
- **Location:** README.md ("The bug is there to be discovered, not announced"), challenge names in `modules/*/challenges/*.js`, hint 1 text
- **Description:** The README promises discovery, but challenge titles announce the vulnerability class outright: "alg=none Accepted," "Unprotected Admin Panel," "Ping Gadget v2 (weak blacklist)," "Exposed .git Directory," "Change Email with No CSRF Token." Hint 1 then frequently restates the same fact ("The email change is a GET request with no token," "The verifier trusts alg:none"). The lab therefore trains technique execution, not vulnerability discovery, which is a fine pedagogy but not the advertised one.
- **Evidence:** Challenge name list plus first-hint text sampled from rendered module pages.
- **Recommendation:** Make a doctrine decision and align the copy: either rename challenges to neutral titles ("Token Service," "Admin Panel," "Ping Gadget v2") and push the bug-class reveal to hint 2, or change the README line to own the technique-practice framing ("each challenge names its flaw; your job is the exploit").

### F7. Briefing depth is uneven across modules
- **Severity:** Medium
- **Location:** Module index pages (`modules/<id>/index.js` intro copy), e.g. `/sqli`, `/jwt`, `/ssrf`, `/xxe`, `/lfi`, `/upload`, `/auth`, `/session` vs `/csrf`, `/xss`, `/proto`, `/crypto`
- **Description:** csrf, xss, proto, crypto, csti, and cmdi open with a full "What is X?" concept explainer, the fictional app's story, and the exact flag-claim mechanics. Most other modules open with a one-to-two sentence tagline (e.g. sqli: "Eleven challenges walk you from a trivial login bypass through second-order injection..."). A beginner who starts at the top of the Injection track gets a roadmap but no conceptual grounding in what SQL injection is.
- **Evidence:** Full-text extraction of 12 module pages; only 6 of the 12 sampled had concept explainers.
- **Recommendation:** Add a 3-5 sentence "What is X?" explainer to the ~20 modules missing one, following the csrf/proto pattern: what the flaw is, why it matters in one concrete sentence, what the fictional app is, and how flags are claimed in this module.

### F8. Hint ladders are excellent but sometimes front-loaded
- **Severity:** Medium
- **Location:** `hintLadder()` in `lib/page.js`; `hints` arrays in `modules/*/challenges/*.js`
- **Description:** The infrastructure deserves praise: 200/201 challenges carry the full Nudge / Technique / Explicit ladder, written Burp-first. Rating the 16 sampled ladders: 10 helpful, 6 spoilery-or-front-loaded. The recurring pattern is that hint 1 or hint 2 hands over the key primitive instead of reserving it for hint 3: `jwt/none-admin` hint 1 ("The verifier trusts alg:none") plus a title that already says it; `idor/profile` hint 3 ("the admin's id is worth trying first"); `csti/constructor` hint 2 ("constructor.constructor is the Function constructor"); `proto/proto-constructor` hint 2 spells out the full constructor/prototype path. Best-in-class ladders: `misconfig/git` (HEAD to ref to commit to object store, pure method), `cmdi/bypass` (teaches separator semantics and URL-encoding), `sqli/blind` (teaches the oracle concept), `upload/upload-polyglot` ("KEY INSIGHT" teaches the polyglot principle).
- **Evidence:** Hint text from rendered module pages for csrf/email, sqli/blind, xss/reflected, xss/stored, crypto/ecb-oracle, ssrf/basic, jwt/none-admin, race/race-coupon, misconfig/git, idor/profile, lfi/log-poison, ssti/rce, xxe/file, csti/constructor, upload/upload-polyglot, cmdi/bypass, proto/proto-constructor, bizlogic/biz-refund.
- **Recommendation:** Keep the ladder system exactly as is. Do one pass over Medium/Hard ladders moving the key primitive from hint 2 into hint 3 (the four named above are the priority). For Easy onboarding challenges the current explicitness is fine and should stay.

### F9. Three different "first steps" across home, paths, and curriculum
- **Severity:** Medium
- **Location:** `/` ("Start here" points to csrf), `/paths` (Zero to Web Pentester starts with xss/reflected), `docs/curriculum/LEARNING_PATHS.md` (Foundations starts with misconfig)
- **Description:** The homepage tells beginners to start with CSRF, the career path tells them to start with reflected XSS, and the curriculum doc starts Foundations with misconfig. Worse, the CSRF module's own track banner declares "Prerequisites: xss," so the designated start-here module tells a true beginner they are missing a prerequisite.
- **Evidence:** Homepage banner text, path step 1, curriculum table, `/csrf` track banner.
- **Recommendation:** Pick one canonical first module (misconfig is the curriculum's choice and is genuinely the gentlest: read a debug page), point the homepage "Start here" card, the about page, and the path's step 1 at it, and remove the prerequisite line from whichever module is the designated entry.

### F10. Crypto progress is silently invalidated by a server restart
- **Severity:** Medium
- **Location:** `modules/crypto/*` ("Keys and secrets are random per server boot"), session persistence in `sessions.db`
- **Description:** The crypto module correctly warns that keys are random per boot, but a student mid-way through the 8-challenge module who restarts the server (or whose instructor restarts it) loses all in-progress work with no UI recovery path, while their scoreboard progress from other modules survives. In a classroom where the instructor restarts the instance between sessions, this will generate confusion and support load.
- **Evidence:** Crypto module page text; `sessions.db` persists flags but crypto secrets do not.
- **Recommendation:** Add a dismissible notice on the crypto module page when the boot id has changed since the student's last crypto flag ("the lab restarted; crypto challenges use fresh secrets, re-do any in-progress ones"). One paragraph, no new infrastructure.

### F11. SOLUTIONS.md is strong but has a rough edge and a mixed voice
- **Severity:** Low
- **Location:** `SOLUTIONS.md` (3,234 lines, all 29 modules covered)
- **Description:** Coverage and teaching quality are high: every module is present, each challenge gets steps, a "Why it works" explanation, and a Burp workflow line. The crypto walkthroughs are technically accurate down to the PKCS#7 pad-block caveat and the IV-flip math. Two blemishes: (1) a stray generator artifact line at the end of the crypto section ("File written: docs/burp-flows/crypto.md"); (2) the steps use curl one-liners while the Burp workflow is appended separately, which slightly undercuts the Burp-first voice, though it is pragmatic for setup steps.
- **Evidence:** `sed -n '2598,2680p' SOLUTIONS.md`; `grep -c "^## " SOLUTIONS.md` = 30 (29 modules + setup).
- **Recommendation:** Delete the artifact line. Keep the curl/Burp split but add one sentence at the top of the setup section explaining the convention (curl for setup beacons, Burp for the attack).

### F12. Break-then-fix is piloted on only 2 of 29 modules
- **Severity:** Low
- **Location:** `lib/fixmode.js`, `docs/curriculum/BREAK_THEN_FIX_GUIDE.md`, module pages ("Fix mode is not available for this challenge yet")
- **Description:** The fix mode is the lab's best differentiator for teaching defense, but it only exists for sqli and xss. Every other module page shows the honest "not available yet" notice, which is the right placeholder. Beginners in the Foundations track (misconfig, idor, csrf) get no defensive half at all.
- **Evidence:** `hasFixBlock` resolves block files; roadmap PROGRESS.md records the sqli+xss pilot scope.
- **Recommendation:** Expand fix blocks to the Foundations track next (misconfig, idor, csrf): beginners benefit most from the attack-then-defend loop, and these flaws have the simplest fixes.

### F13. Minor polish items
- **Severity:** Low
- **Location:** various
- **Description:** (a) Module-level difficulty labels (Beginner/Intermediate/Advanced) vs challenge-level labels (Easy/Medium/Hard) with no documented mapping. (b) The one 4-hint challenge (`xxe/ssrf`) renders its fourth hint as "Step 4" via the label fallback; harmless but inconsistent. (c) `/about` "How to use" ends at "Still stuck? Check SOLUTIONS.md" with no mention of the demo cheat sheet or the curriculum docs. (d) No estimated time per challenge anywhere; students cannot plan a session.
- **Recommendation:** Document the difficulty mapping in one line on the homepage; rename the fallback label; add time estimates (even rough: 10/30/60+ min) to challenge cards when the data exists.

---

## Hint ladder ratings (16 sampled)

| Challenge | Rating | Note |
|---|---|---|
| csrf/email (Easy) | Helpful, front-loaded | Hint 1 restates the title; acceptable as the designated first challenge |
| sqli/blind (Medium) | Helpful | Teaches the oracle concept, not the payload |
| xss/reflected (Easy) | Helpful | Nudge to technique to explicit claim flow, Burp-first |
| xss/stored (Easy) | Helpful | Hint 3 gives the beacon shape; justified, the beacon is module ceremony |
| crypto/ecb-oracle (Hard) | Helpful | Genuine cryptanalysis teaching |
| ssrf/basic (Medium) | Helpful | Hint 2 names 127.0.0.1; slightly explicit but fine for the concept intro |
| jwt/none-admin (Easy) | Spoilery | Hint 1 + title hand the whole primitive; fine only because it is Easy |
| race/race-coupon (Medium) | Borderline spoilery | Hint 2 fully explains check-then-act; move the mechanism to hint 3 |
| misconfig/git (Medium) | Helpful, best in class | HEAD to ref to commit to object store, pure method |
| idor/profile (Easy) | Helpful, front-loaded | "The admin's id is worth trying first" belongs in hint 3, not hint 2/3 mix |
| lfi/log-poison (Hard) | Helpful | Good nudge about writable files, then the technique |
| ssti/rce (Medium) | Helpful | "Most obvious name" is vague but fair |
| xxe/file (Medium) | Helpful | Hint 2 is a mini DOCTYPE syntax tutorial; justified, XXE syntax is not guessable |
| csti/constructor (Medium) | Spoilery | Hint 2 hands `constructor.constructor`; reserve for hint 3 |
| upload/upload-polyglot (Hard) | Helpful | "KEY INSIGHT" teaches the principle |
| cmdi/bypass (Medium) | Helpful | Teaches separator semantics and encoding, genuinely educational |
| proto/proto-constructor (Medium) | Spoilery | Hint 2 spells out the full bypass path; reserve for hint 3 |
| bizlogic/biz-refund (Medium) | Helpful | Clean nudge to technique ladder |

---

## Top 10 prioritized fixes

1. **Reorder challenges easy-to-hard inside each module** (F3). Start with the four "Hard as challenge #2" modules: crypto, ssrf, xxe, hostheader. Biggest teaching ROI in the lab.
2. **Put the Burp setup guide one click from the UI** (F1). Link `docs/TOOL_SETUP_GUIDE.md` from `/about` and the Start-here module page. The Burp-first doctrine fails if setup is not in-app.
3. **Ship the classroom minimum** (F4): scoreboard CSV export, documented reset procedure, `docs/CLASSROOM.md` with isolation notes.
4. **Order the homepage by curriculum track, not alphabetically** (F2). Foundations first; add track tags to cards.
5. **Bind certificates to students or stop calling them verifiable credentials** (F5). Per-install codes cannot distinguish students.
6. **Align the three "first steps"** (F9): one canonical entry module across home, paths, and curriculum; fix the csrf prerequisite contradiction.
7. **Resolve the discovery contradiction** (F6): neutral challenge titles or an honest README line about technique practice.
8. **Even out module briefings** (F7): add "What is X?" explainers to the ~20 modules that only have a tagline, using the csrf/proto pattern.
9. **De-spoil the four named hint ladders** (F8): move the key primitive to hint 3 in jwt/none-admin, race/race-coupon, csti/constructor, proto/proto-constructor.
10. **Warn about crypto secret rotation on restart** (F10) and expand break-then-fix to the Foundations track (F12).

## Bottom line

The teaching engine is genuinely good: uniform hint ladders, Burp-first voice everywhere, concept-first briefings in the best modules, real narrative scenarios, and honest solutions that teach method. The lab's problems are structural, not content: ordering (within modules and on the homepage), onboarding gaps (Burp setup, canonical first step), and missing classroom plumbing (export, reset, identity-bound certificates). Fix the top 10 in order and this becomes the best self-serve web security lab a beginner can open.
