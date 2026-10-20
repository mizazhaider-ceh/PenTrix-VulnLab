# Student Review: Prof. Dov (instructor-04)

- Modules tested: oauth (all 8 challenge briefings and hint ladders reviewed; hands-on with curl: Redirect URI Prefix Bypass, Scope Tampering, plus an incidental Authorization Code Leaked in Server Log capture), sqli (all 11 challenge briefings and hint ladders reviewed; hands-on: Login Bypass, UNION-based Injection, Boolean Blind Injection oracle plus character-by-character extraction via subquery). Extra duty: verified 4 SOLUTIONS.md solutions against the live lab (http verb tampering, redirect javascript-URI, api exposure, cors prove). All results below marked post-reboot were re-verified after the ~01:37 UTC VM reboot; the transient scoreboard anomaly was observed pre-reboot.

- What worked well:
  - Scoreboard is genuinely classroom-usable for individual tracking: per-challenge Captured/Not captured status, status filter, per-module progress bars, and a global n/201 banner. After the reboot my 8 solves were captured exactly, no more, no less.
  - Hint ladders are consistent and pedagogically shaped: Nudge (conceptual), Technique (method), Explicit (near-answer), all click-to-reveal, so a teacher can set a "no Explicit hints" classroom rule.
  - sqli fix mode is excellent for teaching: every one of the 11 challenges has a "Fix this challenge" panel with a sandboxed runner that checks the exploit is blocked while legitimate use still works. Break-then-fix is the right classroom loop.
  - The OAuth module's miniature IdP (login, consent screen, token endpoint, world-readable log) is a strong teaching setup; students see the full authorization code flow instead of an abstract description.
  - Burp-first throughout: starting points name the exact request to intercept, payload blocks give Repeater-ready templates, hints name Repeater/Intruder steps. Everything I did with curl maps 1:1 onto Burp actions, so a Burp-first classroom works.
  - Anti-cheat thoughtfulness: the login-bypass award only fires when the match came from query breakage, not from submitting real admin credentials, so knowing the seeded password earns nothing.
  - The blind injection oracle genuinely discriminates (true returns the exists div, false returns Not found), and subquery character extraction works end to end.

- Bugs found (with reproduction):
  1. Transient scoreboard contamination (pre-reboot, shared pool instance): one scoreboard fetch showed 3 captured Command Injection challenges (Ping Gadget v1, v2, v8) that I never attempted, while 5 challenges I had completed showed Not captured. A later fetch of the same session showed only my own solves. Cause unknown; concurrent testers share this pool instance. Reproduction: fetch /scoreboard repeatedly during active multi-tester use. Classroom impact: verify per-student session isolation on a shared deployment before grading from the scoreboard.
  2. Stale ports everywhere. SOLUTIONS.md declares base URL localhost:3000 in its header but its curl commands use ports 3000, 3109, and 3112 inconsistently; challenge pages embed http://localhost:3000 links (oauth code-leak starting point points at /oauth/idp/log on port 3000; sqli pages reference /sqli/detail and /sqli/wildcard on port 3000). On the deployed instance (port 18405) verbatim copy-paste fails with connection refused; students must substitute the port. The routes and behaviors themselves are correct.
  3. No per-student progress reset exists. The only "Reset" I found in app.js/lib/page.js is the scoreboard filter reset. A teacher cannot reset a student's progress for a re-run without a fresh session.

- Friction/confusion points:
  - The exfiltrated admin secret is itself flag-formatted, so a UNION dump renders two flag-shaped values in one response: the stolen secret in the table rows and the awarded challenge flag in the flag box. Students may submit the wrong one.
  - The blind challenge page's brief text contains the phrase "product exists", which pollutes naive grep-based oracle scripting; students automating extraction must anchor on the result div, not the substring.
  - OAuth has no fix mode ("Fix mode is not available for this module yet"), while sqli has it for all 11 challenges; the gap is unexplained in the UI.
  - The oauth code-leak award fired incidentally when I re-exchanged a stale code while logged in as a different IdP user (owner != session user). The mechanic is legitimate, but it shows how easily an unrelated action captures a challenge the student was not working on.
  - OAuth challenge pages hand the answer: the redirect-bypass page prints the exact attacker URI with a "Start authorization with this redirect_uri" button, and scope-upgrade has an "Authorize with scope=admin" button plus Repeater payload blocks. Fine for onboarding, but it removes the discovery step.

- Hint quality (helpful? spoilery? useless?): Mostly helpful and well-graded. sqli hints genuinely teach: the blind ladder explains the one-bit oracle concept (Nudge), then the boolean probing method (Technique), then the Intruder character sweep (Explicit). OAuth hints are strong and Burp-specific. Spoilery at the Explicit level by design, which is acceptable, but two spots overshoot: the code-replay Hint 3 states the vulnerability outright ("never marks the code as spent... the flag rides in the second response"), and the redirect-bypass challenge page gives the payload before hints are even needed. For Medium-labeled challenges, that turns discovery into clicking. Useless: none found; every ladder I read was accurate.

- Difficulty fairness: sqli's curve is fair and well ordered: Easy login bypass, Medium union/error/order-by/like/limit/group-by/filter/insert, Hard second-order. Labels feel honest. OAuth is mostly fair, with one mislabel: Lab 1 Redirect URI Prefix Bypass is Medium but is a click-through since the page supplies the exact URI; it plays like an Easy. Scope Tampering (Easy) is fair: the student must still modify scope, exchange the code, and present the token. Overall fair, with the noted exception.

- Burp-first feasibility: Fully feasible. Every tested challenge names the request to intercept and the Repeater/Intruder workflow; I simulated all of them with curl and each maps directly to a Burp action. The sqli blind challenge explicitly suggests Intruder for character sweeps, and the union challenge's 4-column structure is discovered naturally in Repeater. A class could run Burp-only with no curl at all.

- Suggestions (concrete):
  1. Unify the base URL: replace hardcoded localhost:3000/3109/3112 in SOLUTIONS.md and challenge pages with one documented placeholder (or relative links), so copy-paste works on any deployment port.
  2. Add a per-student progress reset (scoreboard or module page button) so teachers can re-run a challenge in class without fresh sessions.
  3. Bring OAuth fix mode to parity with sqli, or label clearly which modules have it and which do not.
  4. Gate the oauth challenge-page reveals: put the exact attacker URI and payload buttons behind a click-to-reveal like the hints, preserving the Medium discovery step; or relabel Lab 1 as Easy.
  5. Visually distinguish the admin-secret token from awarded challenge flags (different format or a "this is data, not your flag" label) to stop wrong submissions.
  6. Investigate the transient scoreboard contamination under concurrent use on shared instances before any graded classroom use.
  7. Add an instructor export (e.g., per-student progress CSV) to make the scoreboard genuinely classroom-ready.

- Rating: 4/5

## SOLUTIONS.md accuracy

All four checked live on http://127.0.0.1:18405/ post-reboot. Route exists, steps work, and the lab awarded the flag in each case. Verdict for each: accurate, with one shared caveat: every documented curl uses a stale port (3000/3109/3112, inconsistent even with the doc's own "base URL localhost:3000" header), so the commands only work verbatim after substituting the live port.

1. http verb tampering: accurate. GET /http/feedback?msg=hello records the feedback and the lab awarded the flag, exactly as documented (doc shows port 3112).
2. redirect javascript-URI: accurate. /redirect/js?next=javascript:alert(1) returns 302 with Location: javascript:alert(1) honored verbatim, and the lab awarded the flag in the response body (doc shows port 3109).
3. api exposure (Excessive Data Exposure): accurate. GET /api/users returns whole rows (passwords, secrets) and the X-Pentrix-Flag header carries the flag; the lab awarded the flag (doc shows port 3000).
4. cors prove (Reflected Origin with Credentials): accurate. /cors/prove?vuln=cors-reflect&origin=https%3A%2F%2Fevil.com awarded the flag verbatim via the documented grep pipeline (doc shows port 3109).
