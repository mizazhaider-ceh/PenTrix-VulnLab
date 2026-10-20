# Student Reviews: PenTrix-VulnLab (50-student test wave)

**Date:** 2026-10-20
**Method:** 50 student agents (15 beginners, 12 intermediates, 8 CTF players, 6 Burp-first learners, 5 instructors, 4 impatient clickers) tested a pool of 10 live lab instances with unique cookie jars, exploiting with curl as a Burp Proxy/Repeater/Intruder simulation. All 29 modules were covered 3 to 5 times each, plus all 3 scenarios, all 3 career paths, the scoreboard, hint ladders, and 32 sampled SOLUTIONS.md solutions.
**Environment note:** the test VM rebooted twice during the wave (about 01:37 UTC and about 02:47 UTC). Each reboot reset per-boot state and scoreboard progress; every affected student re-ran their exploits and re-verified results on the live instance afterwards, and reviews note this.
**Ratings:** average 3.9 of 5, median 4, range 3 to 4.5. No review scored below 3.
**Compliance:** all 50 files verified present and non-empty, zero em dashes, and no review discloses where or how flags are stored (the only flag-shaped string quoted anywhere is the decoy the lab itself serves publicly, labeled DECOY_DO_NOT_USE by the lab).

---

## Top 20 issues (ranked by frequency x severity)

1. **Beacon awards need no JavaScript execution (High, FLAG BAR).** Across XSS, CSTI, JSONP, and postMessage, the award fires on a beacon carrying a token scraped from the page HTML. Students cleared whole modules with curl alone: CSTI 5/5 at about 30 seconds per lab with zero template evaluation (ctf-03), JSONP 5/5 by token echo (intermediate-07, beginner-05), constructor beacons accepting any non-empty data value (intermediate-03). The token proves a page load, not an exploit. Reported or confirmed in 26 reviews; matches the expert audit (A2).
2. **XXE echo-marker awards (Critical, FLAG BAR).** Typing the marker strings straight into the import box awards file and SSRF flags with zero entities, and the shared out-of-band collector log publicly exposes other students' marker text, so a fresh session went from 0 to 2 of 201 with no exploit (intermediate-05). Matches the expert audit's Critical A1.
3. **Shared global state breaks other students (High).** Prototype pollution is process-global and leaks across challenges and sessions; race state is global; one student's mass-assignment promotion blocks IDOR path steps; the formula export awards from other people's payloads; the cache-poison flag falls to a fresh visitor after anyone poisons the cache (ctf-06); other testers changed shared account passwords mid-run twice, breaking rate-limit and fixation challenges (ctf-03, ctf-01); alice was silently promoted to admin, nullifying six IDOR challenges with no explanation (burp-06); the hosted-DTD slot is a single global value students clobber for each other (intermediate-05). The dominant theme of the wave: mentioned in 44 reviews.
4. **Wrong addresses everywhere: localhost:3000 (High frequency, trivial fix).** Starting points, hint text, payload blocks, and SOLUTIONS.md hardcode localhost:3000 or stale ports while the lab runs elsewhere. Found in 27 reviews across nearly every module (session, JWT, CORS, hostheader, SSRF samples, race commands). Beginners copy the address and hit nothing.
5. **Scoreboard display inconsistencies (High frequency).** Header chip reads 0/201 while module pages show captures (ctf-07); eight flag banners but scoreboard 0/201 (beginner-15); chip 26 vs filter count 27 (intermediate-02); unearned captures displayed (instructor-02, instructor-04); the crypto module index never renders "Flag captured" pills while the XSS index does (beginner-10); the empty-state text "No challenges match your filter" is baked into markup and shows even when results exist (ctf-05); scoreboard rows are not links back to challenges (clicker-04).
6. **Restart wipes all progress, with no warning (High for classroom use).** Two reboots during the wave reset every student's scoreboard to 0/201. The "Saved to your scoreboard" banner never hints that progress is volatile, and nothing tells students to record each flag as they earn it (clicker-02, intermediate-12). The five instructors judged this, combined with issue 19, as the blocker for classroom use.
7. **Burp Community cannot do what the guidance prescribes (High).** Race hint ladders prescribe throttled Community Intruder for a 150 to 250 ms window; crypto-rand-pin needs a million Intruder payloads; the OTP brute force (10k codes) has no honest time estimate; Community Intruder is single-threaded, so it can run neither the race parallel bursts nor the PIN space. SOLUTIONS.md claims the PIN falls in about 72 s at about 2,800 requests per second; measured about 130 to 150 per second with 20 to 24 workers, a 1 to 2 hour grind (intermediate-07). The working paths are curl, xargs, and Python, which the docs treat as fallbacks. Raised in 34 reviews; matches expert audit D1, D2.
8. **Upload awards at upload time (High, FLAG BAR).** A one-byte .html file earns the stored-XSS flag; all 8 upload challenges awarded on shape alone at upload, and one POST awards both upload-case and upload-double-ext (ctf-07, ctf-02). Matches expert audit A4, A6.
9. **CSRF challenges award self-requests (High, FLAG BAR).** The flag fires for changing your own email in your own session; CTF players noted the module is inherently self-targeted by design (ctf-05, beginner-03). Matches expert audit A3.
10. **Demo credentials broken on live instances (Medium-High).** Session fixation advertises admin/admin123 and returns 403 (burp-02); the hostheader login advertises alice/alice123 and returns 401 while bob/bob123 works (intermediate-06); the seeded admin password reads "Invalid" in the sqli module (ctf-06). Students burn real time on step zero. Credential problems appear in 18 reviews.
11. **Command-injection evidence spoof (Medium-High, FLAG BAR).** A quoted echo of the expected output text awards with no real command executed; the scrub removes only the exact raw input string (intermediate-04, ctf-04).
12. **JWT alg-confusion newline trap (Medium, fairness).** The verifier keys on the published key bytes including a trailing newline that the page renders invisibly; signing with the key exactly as displayed fails with a bare 403, and the hint ("copy the PEM text") leads to the failing variant. Hit independently by beginner-03, ctf-05, and beginner-15.
13. **LFI double-encode check tests for a bare percent sign (Medium-High, FLAG BAR).** /lfi/double awards for %73ecret.txt (only the letter s percent-encoded, no traversal at all) because the check looks for a % in the raw input rather than real double-encoded traversal (ctf-03).
14. **Host-header SSRF check is content-only (Medium-High, FLAG BAR).** The award triggers on a marker substring in the fetched body; a stand-in server returning the marker won the flag and the real internal agent was never contacted (ctf-06). Same marker-check pattern as issue 2.
15. **SQLi possession shortcuts (Medium).** Five of eleven sqli challenges fall to a secret obtained elsewhere with no per-challenge technique: groupby-having accepts a quoted literal of the secret, blind and like-wildcard submit boxes accept a secret extracted once by UNION, and order-by plus limit-offset award on pattern rather than on extracting the target (ctf-01, ctf-06, intermediate-01).
16. **Cards, samples, and hint 2 hand over the solve (Medium).** Module card bodies spoil the full exploit for nearly every challenge, making the ladders redundant (beginner-03); /xxe/param and /xxe/xinclude pre-fill the complete working exploit in the sample box, spoiling two Hard challenges (intermediate-05); several ladders front-load the key primitive in hint 2 (expert audit C8, E6).
17. **SOLUTIONS.md: mostly accurate, specifically stale (Medium-High).** Of 32 sampled solutions, most verified accurate verbatim. The stale set: XSS beacon steps omit the page-bound nonce, confirmed twice (burp-02, intermediate-05); mass-assignment's documented body returns 500 while a simpler role body works; the redos email python one-liner is broken; the jsonp array-hijack curl returns 400 without the feed token; session fixation steps are stale; the SSRF fetch uses localhost:3000. Plus generator scaffolding in 15 of 29 sections and the stale solutions/batch-*.md drafts (expert audit E1 to E3).
18. **Session fragility under parallel load (Medium-High).** After parallel bursts, the scoreboard reads 0/201 and the session id has changed, even for one process sharing one jar; reproduced three times (intermediate-07), with capture loss under bursts also reported by beginner-05. A student running the race module, whose whole point is parallel bursts, can silently lose every captured flag.
19. **No classroom tooling (High for adoption).** No accounts, roster, per-student tracking, progress export, per-student reset, or isolation. All five instructors: cannot run a class on it yet.
20. **Front-door UX dead ends (Medium).** Module challenge cards carry no link to the challenge consoles, so clickers must guess URLs (clicker-01, clicker-03, clicker-04, beginner-11, intermediate-11); Copy buttons copy long prose including the wrong address instead of a command or payload; the "Fix mode is not available" line repeats per challenge (up to 8 times on one page); the home difficulty filter offers no Advanced option although 4 modules are Advanced; the progress chip is missing on module pages and there are no breadcrumbs (expert audit F1, F2, F4, F5).

### Also logged (real, lower frequency)

- CORS subdomain prove gate secretly requires the literal string "evil" in the hostname while hint 2 encourages any label, so a correct solve fails silently (burp-06).
- The predictable-sessions page prints the admin session id outright; no pattern analysis is needed (ctf-03). The user-enum probing page prints both oracle phrases, so the taught grep-match matches every response (intermediate-01).
- A successful ReDoS attempt blocks the shared single-threaded server for up to about 57 seconds, looking like a hung Repeater to every other student (burp-02).
- IDOR comment deletion permanently removes shared seed comments with no reseed path (beginner-12).
- The misconfig backup challenge serves a decoy flag-shaped string while awarding silently with no banner, so day-one students copy the decoy as their answer (beginner-06).
- One full Express stack trace served once during a restart window (intermediate-06).
- Dead code: one module file shadows another's import routes (intermediate-05).
- Host-xforwarded falls back to plain Host, so it falls to the previous challenge's technique (ctf-06).
- Difficulty label drift: JSONP labeled Intermediate with three Easy challenges that day-one beginners clear (beginner-05); XXE param-oob rated Hard plays like a form submit (intermediate-05); blind and like-wildcard collapse from Medium to Easy via issue 15.

---

## Top 10 praises

1. **The three-level hint ladders.** Praised in review after review as helpful and well graded: level 1 nudges, level 2 teaches the technique, level 3 gives exact steps, and they are native toggles that work with JavaScript off. Several students called them the best part of the lab.
2. **Core modules genuinely gate on technique.** SQLi (union, blind, second-order), IDOR, JWT, crypto (ECB oracle, CBC bit-flip, hash extension), OAuth, and race TOCTOU all resisted cheats; cheat batteries of bare beacons, replays, wrong tokens, and wrong roles were rejected with 400 and 403 responses across nearly every review.
3. **Scenario design.** All three scenarios were completed end to end with strict stage gating that held under probing; Shop Takeover was fully verified twice, including after a reboot; students singled out the narrative coherence and the unlock order.
4. **Career paths work as a guided curriculum.** All three paths were walked end to end, steps track progress live on the path page and the scoreboard, no step links were broken, and the completion certificate downloads (Authentication Assassin 11 of 11 by ctf-03; API Hacker by instructor-01).
5. **Flag feedback UX.** The capture banner plus scoreboard loop is satisfying and readable; the CORS prove-it pattern was called the best flag UX in the lab by a CTF player, and several beginners cited the first two-minute CSRF win as the hook that kept them going.
6. **Burp-first feasibility in practice.** Burp-persona students confirmed module after module fully solvable in Burp Community with Proxy and Repeater alone (13 of 13 by burp-06; 21 of 21 by intermediate-05), and the guidance names the right tool in most challenges.
7. **Friendly failure states.** Junk input gets friendly 403 and 404 pages, not crashes or blanks; the 404 page points back to modules and scoreboard; denial pages carry back links, so clickers never got stranded.
8. **SOLUTIONS.md is mostly accurate.** Most of the 32 sampled solutions worked verbatim against the live lab and awarded the flag, including the crypto ECB oracle (recovered byte at a time), the JWT alg=none one-liner, the upload polyglot, and the race double-spend.
9. **Briefings that actually teach.** The API module's endpoint table, the OAuth module's "your two hats" framing of its two sessions, full "What is X?" explainers in the csrf, xss, proto, and crypto modules, and quick-login buttons were repeatedly named as what made hard topics approachable on day one.
10. **Awards are idempotent and honest in normal flow.** Replays never double-counted in any review, cross-checks between module pages, chip, and scoreboard usually agreed exactly (beginner-10: 17 of 201 matching everywhere), and honest students could always tell whether a flag had landed.

---

## Full index of the 50 reviews


| Review | Student | Modules tested (short) | Rating |
|---|---|---|---|
| [beginner-01.md](beginner-01.md) | Day-One Dana | API Security Flaws (all 5 challenges: Mass Assignment, Excessive Data Exposure, Missing Rate Limiting, Rate Limit Byp... | 4 |
| [beginner-02.md](beginner-02.md) | Day-One Dev | - Command Injection (cmdi): all 9 challenges, 9 flags awarded. Basic (`;id`), v2 (`;;id`, filter strips only the firs... | 4 |
| [beginner-03.md](beginner-03.md) | Day-One Priya | CSRF & Clickjacking (5/5 challenges: change-email GET, clickjacking, JSON text/plain CSRF, referer bypass, method ove... | 4 |
| [beginner-04.md](beginner-04.md) | Day-One Marco | - Host Header Injection (hostheader): all 5 challenges, flags awarded for all 5. Password Reset Poisoning (rewrote th... | 4 |
| [beginner-05.md](beginner-05.md) | Day-One Aisha | jsonp (5 challenges: Callback XSS, JSONP Data Theft, Callback Filter Bypass, Array Constructor Hijack, JSONP MIME Sni... | 4 |
| [beginner-06.md](beginner-06.md) | Day-One Leo | Security Misconfiguration (10 challenges), Session Management (6 challenges). Tested live at http://127.0.0.1:18406/ ... | 4 |
| [beginner-07.md](beginner-07.md) | Day-One Nina | proto (Prototype Pollution, 6 challenges), ssti (Server-Side Template Injection, 9 challenges) | 4 |
| [beginner-08.md](beginner-08.md) | Day-One Omar | ReDoS (4 challenges) and XXE Injection (8 challenges), all 12 exploited live with curl against the shared pool instan... | 4 |
| [beginner-09.md](beginner-09.md) | Day-One Sara | ssrf (9/9 challenges), bizlogic (5/8 challenges; workflow-skip, otp-client, email-noreauth untested, the instance wen... | 1 |
| [beginner-10.md](beginner-10.md) | Day-One Tom | XSS (9 challenges), Cryptographic Failures (8 challenges). Result: 9/9 XSS, 8/8 crypto, all captured and confirmed on... | 4.5 |
| [beginner-11.md](beginner-11.md) | Day-One Yuki | Broken Authentication (8 challenges: user-enum, brute-force, reset, otp-bruteforce, reset-predictable, security-quest... | 4 |
| [beginner-12.md](beginner-12.md) | Day-One Zara | - CORS Misconfiguration (/cors): all 6 challenges tested (Reflected Origin with Credentials, Null Origin Trusted, Reg... | 4 |
| [beginner-13.md](beginner-13.md) | Day-One Kai | csti (all 5 challenges: basic, filter-bypass, constructor, attr, stored) and lfi (all 9 challenges: traversal, filter... | 4 |
| [beginner-14.md](beginner-14.md) | Day-One Mia | HTTP Layer Flaws (/http: crlf-log, verb-tamper, cache-deception), postMessage Flaws (/postmsg: no-check, wildcard, da... | 4 |
| [beginner-15.md](beginner-15.md) | Day-One Ravi | JWT Attacks (/jwt: none-admin, weak-secret, kid-sqli, jku, alg-confusion, no-expiry, aud-bypass, kid-default), all 8 ... | 4 |
| [burp-01.md](burp-01.md) | Proxy Paula | proto (Prototype Pollution, 6 challenges), ssti (Server-Side Template Injection, 9 challenges) | 4 |
| [burp-02.md](burp-02.md) | Repeater Ron | redos (4 challenges), xxe (8 challenges). All 12 completed and re-verified post-reboot on the live pool instance at h... | 4 |
| [burp-03.md](burp-03.md) | Intruder Ivy | ssrf (9 challenges) and bizlogic (8 challenges). All 17 were exploited end to end with Burp-style flows (curl used as... | 4 |
| [burp-04.md](burp-04.md) | Decoder Dan | xss (9 challenges: reflected, stored, dom, xss-attr-breakout, xss-js-context, xss-backtick, xss-markdown, xss-svg-upl... | 4 |
| [burp-05.md](burp-05.md) | Comparer Cara | Broken Authentication (/auth, 8 challenges) and CSV Formula Injection (/formula, 4 challenges), on the shared pool in... | 4 |
| [burp-06.md](burp-06.md) | Logger Liam | cors (CORS Misconfiguration, 6 challenges), idor (Broken Access Control, 7 challenges) | 4 |
| [clicker-01.md](clicker-01.md) | Clicker Cal | Home page (all 29 module cards, difficulty filter with every option, search box with junk and real queries); Session ... | 3 |
| [clicker-02.md](clicker-02.md) | Clicker Dot | ssti (assigned), xss (my choice) | 4 |
| [clicker-03.md](clicker-03.md) | Clicker Eli | XXE Injection (all 8 challenge pages: /xxe/import, /xxe/soap, /xxe/billion, /xxe/dtd, /xxe/collector, /xxe/svg, /xxe/... | 4 |
| [clicker-04.md](clicker-04.md) | Clicker Dana | JWT Security, all 8 challenges, this time live (GET /jwt, /jwt/none, /jwt/weak, /jwt/kid, /jwt/jku, /jwt/confusion, /... | 4 |
| [ctf-01.md](ctf-01.md) | Flag Hunter Finn | sqli (11 challenges), auth (8 challenges), formula (4 challenges). Tested only http://127.0.0.1:18408/ with a dedicat... | 4 |
| [ctf-02.md](ctf-02.md) | Pwn Pixie | cors (6 challenges), upload (8 challenges), idor (7 challenges). Tested only http://127.0.0.1:18409/ with a dedicated... | 4 |
| [ctf-03.md](ctf-03.md) | Shellcode Sam | api (5 challenges), csti (5 challenges), lfi (9 challenges), plus the full "Authentication Assassin" career path (11 ... | 4 |
| [ctf-04.md](ctf-04.md) | Exploit Eve | cmdi (9 challenges), http (3 challenges), postmsg (5 challenges). All flags captured: cmdi 9/9, http 3/3, postmsg 5/5... | 4 |
| [ctf-05.md](ctf-05.md) | Buffer Bea | CSRF & Clickjacking (5/5 captured), JWT Attacks (8/8 captured), Open Redirect (5/5 captured). 18 of 18 assigned chall... | 4 |
| [ctf-06.md](ctf-06.md) | Rootkit Ray | hostheader (5/5 captured), oauth (8/8 captured), sqli (11/11 captured). All 24 flags re-verified live on the shared p... | 4 |
| [ctf-07.md](ctf-07.md) | Payload Pam | JSONP Injection (5/5 flags captured), Race Conditions (8/8 flags captured), Unrestricted File Upload (8/8 flags captu... | 3 |
| [ctf-08.md](ctf-08.md) | Zero-Day Zoe | misconfig (10/10), session (6/6), api (5/5). All captures re-verified on the live instance after the ~01:37 UTC pool ... | 4 |
| [instructor-01.md](instructor-01.md) | Prof. Ada | LFI (all 9 challenges), CSTI (all 5 challenges), and the API Hacker career path walked end to end (all 10 steps, path... | 4 |
| [instructor-02.md](instructor-02.md) | Prof. Ben | HTTP Layer Flaws (all 3 challenges: CRLF Log Injection, Verb Tampering, Cache Deception), postMessage Flaws (all 5 ch... | 3 |
| [instructor-03.md](instructor-03.md) | Prof. Cleo | JWT Attacks (jwt, all 8 challenges: none-admin, weak-secret, kid-sqli, jku, alg-confusion, no-expiry, aud-bypass, kid... | 4 |
| [instructor-04.md](instructor-04.md) | Prof. Dov | oauth (all 8 challenge briefings and hint ladders reviewed; hands-on with curl: Redirect URI Prefix Bypass, Scope Tam... | 4 |
| [instructor-05.md](instructor-05.md) | Prof. Elif | race (Race Conditions, 8 challenges), upload (Unrestricted File Upload, 8 challenges), on the shared pool instance at... | 4 |
| [intermediate-01.md](intermediate-01.md) | Grinder Gus | sqli (11 challenges attempted, 11 flags awarded), auth (8 attempted, 7 flags awarded; the 4-digit OTP challenge had i... | 4 |
| [intermediate-02.md](intermediate-02.md) | Grinder Hana | see review | 4 |
| [intermediate-03.md](intermediate-03.md) | Grinder Ivan | Session Management (6 challenges), API Security Flaws (5), Client-Side Template Injection (5). 16 total, all exploite... | 4 |
| [intermediate-04.md](intermediate-04.md) | Grinder Jade | ssti (all 9 challenges, live), cmdi (all 9 challenges, live), http (code-reviewed only, NOT live tested). Career path... | 4 |
| [intermediate-05.md](intermediate-05.md) | Grinder Ken | xxe (XXE Injection, 8 challenges: file read, SSRF via XXE, billion laughs, external DTD OOB, SVG, XInclude, parameter... | 4 |
| [intermediate-06.md](intermediate-06.md) | Grinder Lena | Business Logic Flaws (bizlogic, 8 of 8 captured), Host Header Injection (hostheader, 5 of 5 captured), OAuth Flaws (o... | 4 |
| [intermediate-07.md](intermediate-07.md) | Grinder Mo | crypto (8/8 challenges), jsonp (5/5), race (8/8). Plus SOLUTIONS.md verification duty: ssti RCE, xxe file import, aut... | 4 |
| [intermediate-08.md](intermediate-08.md) | Grinder Nadia | formula (4/4 flags: Classic Formula Injection, DDE Command Execution, HYPERLINK Exfiltration, Pipe Prefix), misconfig... | 4 |
| [intermediate-09.md](intermediate-09.md) | Grinder Owen | IDOR (7 challenges), Prototype Pollution / proto (6 challenges), SSTI (9 challenges). All tested on the shared pool i... | 3 |
| [intermediate-10.md](intermediate-10.md) | Grinder Pia | lfi (9 challenges), redos (4 challenges), xxe (8 challenges). All 21 exploited with curl (Burp simulation), unique co... | 4 |
| [intermediate-11.md](intermediate-11.md) | Grinder Quinn | - postMessage Flaws (postmsg): 5 challenges reviewed. The lab awarded the flag for 4 of 5 (no-check, data-xss, substr... | 4 |
| [intermediate-12.md](intermediate-12.md) | Grinder Rosa | Open Redirect (5/5 exploited, the lab awarded the flag each time), Cross-Site Scripting (9/9 exploited, the lab award... | 4 |

---

## Coverage map

- **Beginners (15):** api, cmdi, csrf, hostheader, jsonp, misconfig, session, proto, ssti, redos, xxe, ssrf, bizlogic, xss, crypto, auth, cors, csti, lfi, http, postmsg, jwt, redirect (redirect partially, instance down during beginner-15's slot; covered fully by five other students).
- **Intermediates (12):** sqli, auth, oauth, scenario shop-takeover (twice), redirect, xss, crypto, api, csti, lfi, ssti, cmdi, xxe, csrf, jwt, bizlogic, hostheader, jsonp, race, formula, misconfig, idor, proto, redos, postmsg, scenario api paths.
- **CTF players (8):** cors, upload, idor, jsonp, race, cmdi, http, postmsg, csrf, jwt, redirect, api, csti, lfi, hostheader, oauth, sqli, misconfig, session, formula; career path authentication-assassin end to end.
- **Burp-first (6):** proto, ssti, redos, xxe, ssrf, bizlogic, xss, auth, formula, cors, idor, session (fixation deep-dive).
- **Instructors (5):** lfi, csti, career path api-hacker, http, postmsg, jwt, oauth, race, upload, classroom and teachability evaluation in every review.
- **Clickers (4):** home page, search, filter, scoreboard, scenarios, paths, session, xxe, ssti, xss, jwt (clicker-04 in two passes: outage code review, then full live re-run at 8 of 8).

## Files

- Expert audit: ../EXPERT_IMPROVEMENT_AUDIT.md (plus per-expert reports in ../expert-audit/)
- This index: REVIEWS.md
- Merged backlog: ../../roadmap/STUDENT_REVIEW_BACKLOG.md
