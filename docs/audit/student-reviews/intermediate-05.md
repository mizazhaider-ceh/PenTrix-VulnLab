# Student Review: Grinder Ken (intermediate-05)

Post-reboot verification note: All live testing in this review was performed AFTER the second reboot (~02:47 UTC 2026-10-20). The pool instance at 127.0.0.1:18410 was verified HTTP 200 before testing; baseline scoreboard was 0/201. My dedicated cookie jar (/tmp/cookies-intermediate-05b.txt) finished at 24/201: all 21 challenges in the three assigned modules, plus the SOLUTIONS.md verification flags for xss reflected, sqli login-bypass, and misconfig git. Every flag outcome below was earned on the post-reboot instance. A second fresh jar used only for cheat testing finished at 2/201.

- Modules tested: xxe (XXE Injection, 8 challenges: file read, SSRF via XXE, billion laughs, external DTD OOB, SVG, XInclude, parameter-entity OOB, SOAP), csrf (CSRF and Clickjacking, 5 challenges: email change, clickjacking, JSON API CSRF, referer bypass, method-override), jwt (JWT Attacks, 8 challenges: none-alg, weak secret, kid SQLi, jku, alg confusion, no expiry, audience bypass, kid default). Plus SOLUTIONS.md accuracy checks for (1) xss reflected beacon, (2) sqli login-bypass, (3) csrf email change, (4) misconfig git.

- What worked well:
  - Every one of the 21 assigned challenges has a genuinely working exploit chain. All awards fired exactly where the briefings said they would, with no broken routes.
  - Anti-cheat design is mostly strong: clickjacking requires the one-time frame token to be both loaded in the framed page and posted back (bare POST earns nothing, tested); json-csrf only awards on the text/plain path, so the legitimate JSON path changes the email but earns no flag (tested, email flipped, no award); method-override only awards on _method=DELETE (plain POST does nothing); the referer bypass only awards on a forged non-same-origin referer (a same-origin POST would not award); billion laughs requires ENTITY declarations plus an entity reference and the size/time threshold (junk input earns nothing); the jwt none/weak panels require role admin, so unsigned or validly-signed role=user tokens are denied (tested).
  - The xss module's page-bound nonce for beacons is a proper fix against bare-curl cheating: the undocumented OLD beacon (no n parameter) now returns 400 "No flag", the documented new flow (load page, read window.__px, beacon with n) awards, and the nonce is single-use so replays fail. Verified all three states live.
  - Hint ladders generally follow the promised pattern (level 1 nudge, level 2 technique, level 3 payload shape) and are honest about the tools needed.
  - The jku challenge page builds its JWKS URL from the server's own PORT, so it works on the pool without port guessing. This is the right pattern; other challenges hardcode localhost:3000 in their start lines.
  - The param-oob challenge explains the quoting trick on the page itself (outer value double-quoted, inner URL must use single quotes), which is the exact gotcha students would burn time on.

- Bugs found (with reproduction):
  1. XXE import awards flags for marker text typed directly into the box, no entity needed. Repro with a FRESH cookie jar: POST /xxe/import with xml=<data> containing only the in-output marker the SSRF module's internal endpoint returns (the string the xxe module briefing itself tells students to look for) awarded the SSRF flag; posting the module secret marker awarded the file-read flag. Scoreboard on the fresh jar went 0 to 2/201 with zero XML entities parsed. Award logic measures the expanded output for marker substrings, not whether an exploit path was used. Impact is worse on the shared pool: the OOB collector log page (/xxe/collector) renders every pingback's d= value in the open, and it contained the marker text from earlier exfils (4 rows), so any student can read the marker there and then type it into the import box. Suggested fix: for the file/ssrf challenges, award only when the marker arrived via entity expansion (e.g. track whether the marker string was present in the submitted xml before expansion), or check the collector-based flow like the OOB challenges do.
  2. The parameter-entity OOB page (GET /xxe/param) pre-fills the textarea with the COMPLETE working exploit (parameter entities reading the secret file plus the smuggled exfil entity with the quoting trick done correctly). Submitting the form as-is wins a Hard challenge with zero work. Same for xinclude: the sample on GET /xxe/xinclude already points at the module secret file, so it is the solution, not a starting point.
  3. The shared hosted-DTD slot (POST /xxe/collector/dtd) is a single global variable for the whole pool instance. If another tester hosts their DTD between my hosting step and my /xxe/dtd submission, my import pulls their DTD instead of mine and my attempt silently fails. Worked solo, but on a busy pool this is a real flaky race. Suggested fix: per-session hosted DTDs (keyed by session, chosen by a query parameter).
  4. Dead route code: both file.js and ssrf.js register GET/POST /xxe/import; since file.js mounts first, ssrf.js's handlers never run. Harmless today (the award checks for both flags live in file.js's handler), but it means the ssrf.js router code is never exercised and could silently rot.
  5. (Docs) SOLUTIONS.md documents a stale beacon URL for xss reflected (see accuracy subsection).

- Friction/confusion points:
  - Port mismatch: the ssrf-via-xxe briefings say to point an entity at e.g. http://127.0.0.1:PORT/ssrf/internal/secret. Students must substitute the pool port (18410); the example only works verbatim on the default 3000 setup. Minor, but it hits at the start of the Hard challenge.
  - The challenge start lines and many start payloads hardcode http://localhost:3000 (jwt start lines especially), which fails literally on the pool. Students adapt fast, but the very first thing they try should work.
  - The external-DTD flow requires the hosted DTD to reference the absolute path of the module secret file and the collector base URL. Both are shown on the collector/dtd pages, but a student who skips reading the collector page will fight the file path for a while. The starter template covers this if they read it.
  - The billion laughs page warns about URL-encoding & in Burp Repeater, which is genuinely the most common failure mode there. Good call.

- Hint quality (helpful? spoilery? useless?):
  - Mostly good. Level 3 hints in xxe (file, ssrf, param-oob) and jwt (kid-sqli, jku, alg-confusion) teach the technique without handing the answer, and the clickjacking ladder explains the token chain well.
  - Spoilery: the hintBox on the SVG page gives the exact entity declaration; the hintBox on the external-DTD page gives both DTD declarations; the billion laughs page's hintBox gives the full classic lol...lol7 shape. These are meant to be level-3 rescue hints, so it is by design, but combined with the pre-filled samples (bug 2) the DTD/SVG/XInclude challenges barely need thinking.
  - The json-csrf hintBox basically hands the answer ("Simple requests (plain forms) skip CORS preflight, so the missing token is the only thing that had to fail, and it did"), plus the page already renders the forged form. Fine for the module's Beginner rating, but there is no mystery left.

- Difficulty fairness:
  - XXE: SOAP Easy (fair), file/svg/xinclude/billion Medium (fair as mechanics, but see spoilery notes), ssrf Hard (fair: needs port substitution plus SSRF module knowledge), external-dtd Medium (fair), param-oob marked Hard but the pre-filled sample makes it a submit-the-form exercise (unfair to the rating).
  - CSRF: email Easy (fair), clickjacking Easy (fair, the token chain is well explained), json-csrf/referer/method-override Medium (all fair; the referer one teaches a real substring-check lesson cleanly).
  - JWT: none/no-expiry Easy (fair), weak/kid-sqli/kid-default/aud Medium (fair; the weak-secret ladder explicitly teaches the wordlist approach and the aud challenge ships a token vending machine), jku/alg-confusion Hard (fair; alg-confusion publishes the key on its own page as designed).
  - No challenge demanded paid Burp features or unrealistic guessing; everything is solvable from the pages plus the ladders.

- Burp-first feasibility:
  - Fully doable on Burp Community. Every challenge is Proxy capture -> Repeater replay; the weak-secret wordlist is a small manual list (Community Intruder's throttling is tolerable for a dozen candidates, or you can paste one at a time into Repeater). Token minting for jwt uses the module's own suggested node/jwt one-liners, which is realistic for an intermediate student. No race windows, no timing attacks, no Pro-only features in these three modules.

- Suggestions (concrete):
  1. Fix the XXE marker-typing cheat (bug 1): gate the file/ssrf awards on the marker entering through entity expansion, not on the output containing it. At minimum, exclude the submitted xml's literal text from matching, so typed-in markers cannot award.
  2. Stop pre-filling complete exploits in GET /xxe/param and GET /xxe/xinclude; give benign samples and move the payload shapes into the level-3 hints.
  3. Scope the hosted DTD to the session (or add a per-student slot parameter) so parallel pool users cannot clobber each other's external-DTD attempts.
  4. Add a one-line port note to the ssrf-via-xxe briefing (use the port in your browser's address bar).
  5. Replace hardcoded localhost:3000 in jwt/csrf start lines with the actual Host or the PORT pattern the jku page already uses.

  - SOLUTIONS.md accuracy:
    1. xss reflected beacon: STALE. The reflection step works verbatim (raw <script>alert(1)</script> appears in the response). But the documented beacon `GET /xss/collect?c=abc&v=reflected` now returns 400 "No flag"; the collector requires the page-bound token (`n`, rendered as window.__px on the challenge page). The working flow is: load /xss/search (which issues the nonce for this session), read window.__px from the page, then beacon /xss/collect?c=abc&v=reflected&n=<token>. Verified live: award fired with the token, and replaying the same token failed (single-use). The doc must be updated to the nonce flow; as written it cannot award.
    2. sqli login-bypass: ACCURATE. POST /sqli/login with username=admin' OR '1'='1 and any password logs in as admin and the lab awarded the flag. Routes, steps, and the Burp workflow all match.
    3. csrf email change: ACCURATE. GET /csrf/login/alice then GET /csrf/change-email?email=... changes alice's email and the lab awarded the flag. Works verbatim after adapting the host/port to the pool.
    4. misconfig git: ACCURATE. The full chain works verbatim: GET /misconfig/.git/HEAD returns ref: refs/heads/main; GET /misconfig/.git/refs/heads/main returns the commit hash; GET /misconfig/.git/objects/ lists directories; fetching the object file prints the commit whose diff leaks the token and the lab awarded the flag.

- Rating: 4
