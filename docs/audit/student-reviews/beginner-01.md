# Student Review: Day-One Dana (beginner-01)

- Modules tested: API Security Flaws (all 5 challenges: Mass Assignment, Excessive Data Exposure, Missing Rate Limiting, Rate Limit Bypass via X-Forwarded-For, API Version AuthZ Bypass) and Client-Side Template Injection (all 5 challenges: Basic, Filter Bypass, Constructor Breakout, Attribute, Stored). Plus the first 3 steps of the Zero to Web Pentester career path (Reflected XSS, SQLi Login Bypass, Profile IDOR). All results below were verified on the live pool instance at 127.0.0.1:18401 AFTER the VM reboot of 2026-10-20 (~01:37 UTC), on a fresh instance state; final scoreboard for my session: 13/201. A first pass before the reboot had reached 10/201 with identical outcomes; the reboot wiped all session progress and I re-ran every exploit.

- What worked well:
  - Every challenge awards its flag after a genuine exploit, and the scoreboard count rises immediately, so success is unambiguous. All 10 module flags and all 3 path flags were captured this way.
  - The API module briefing is genuinely good for a beginner: the endpoint table tells me the whole attack surface, the "Quick login" button gets me into authenticated flows fast, and the note that flags arrive in the response body or the X-Pentrix-Flag header (use curl -i) taught me where to look without spoiling anything.
  - The CSTI briefing explains the engine in plain language: what the two delimiters are, that the browser does the evaluating, and exactly what the beacon needs (lab name, result data, one-time page token). I understood the goal before touching any lab.
  - Anti-cheat held up everywhere I probed. A bare beacon hit with no page load got HTTP 400 and no flag; replaying a consumed one-time token got HTTP 400; a wrong token got HTTP 400; wrong result data got HTTP 400; PATCH /api/me with no login got HTTP 401 and no flag. The token is single-use per page load and cannot be replayed.
  - The path step pages explain the claim flow well. The Reflected XSS step has a "Not getting the flag? Why beacons fail" section that answered exactly the questions I had (token needed, single-use, data required).
  - The SQLi success page shows a short fix explanation (use parameterized queries) right after the attack, which taught me the defense at the moment I was most interested.

- Bugs found (with reproduction):
  1. One challenge's persistent change silently breaks other challenges. Reproduction: (a) complete the API Mass Assignment challenge (PATCH /api/me promoting my own account to admin); (b) log into the IDOR module as alice (GET /idor/login/alice); (c) GET /idor/users/3. Result: bob's secret note is shown (the access-control flaw itself works), but the lab did NOT award the flag, because my session role is now admin and the award requires a non-admin viewer. A beginner following the path in order hits a step that silently refuses to work with no explanation. I only finished the step by logging in as bob instead and viewing another profile, after which the lab awarded the flag. The same pollution leaks into the API Version Bypass challenge: after Mass Assignment, password logins hand out an admin session, and only the demo quick-login link (which forces role user) saved me. Fix: isolate per-challenge state or warn on the Mass Assignment card that the change persists and affects later challenges.
  2. A server restart wipes all student progress with no warning. Mid-test the instance stopped responding (connection refused) for several minutes; when it came back I was logged out everywhere and the scoreboard showed 0/201, down from 10 captured flags. All progress had to be redone. (This was the VM reboot at ~01:37 UTC, not something I caused; per the infra notice, per-boot state was reset.) Losing everything to a reboot with no warning was the worst moment in the lab. Suggestion: persist captured flags across restarts, or warn on the home page that a restart wipes progress.
  3. Transient connection failures on a healthy instance: individual requests occasionally returned HTTP 000 (connection failed), once on the XSS collector call and once mid IDOR test; retrying a few seconds later worked. Minor, but on a shared instance it makes a beginner doubt their exploit.

- Friction/confusion points:
  - Every challenge card's starting point says "http://localhost:3000/...", but the lab is served on a different address and port in this setup (127.0.0.1:18401). A day-one student copying those URLs literally lands nowhere; I had to remap every starting point by hand.
  - The Rate Limit card says "brute force alice's password", but nothing on the API page tells a beginner what alice's password is. I only knew it because the earlier Excessive Data Exposure challenge leaks the user list including passwords. Doing the challenges out of order leaves you stuck with no clue where the password comes from.
  - Related: the attempt counter is global per username and never resets while the server runs. After my legitimate run, a single plain correct login (attempt 16) was awarded the flag again with zero brute forcing, verified after the reboot. On a shared instance, another student can inherit a primed counter and skip the lesson entirely.
  - CSTI Basic and Filter Bypass print the payload right on the lab page (claim box shows {{7*7}} and [[7*7]]), so these are copy-paste rather than problem solving. Fine for a first hour, but it undercuts the "Easy" label's teaching value.
  - As a guest (not logged in) I could open /idor/users/1 and read the admin's profile fields (username, role) with no login at all; only the secret note was hidden. I could not tell whether that counted as the vulnerability or whether I still needed to log in, because the boundary is unclear.
  - The path page gives no time estimates and no "what you need" (browser vs curl), even though the module pages do ("Bring: curl, python" / "Bring: browser").
  - My first SQLi attempt, the classic ' OR '1'='1 with a wrong password, failed with the same "Invalid username or password" message as a wrong password. Nothing on the step page hints that the password half of the query still needs neutralizing; I only got in with a comment payload after reading the module hint ladder. The step page does not link to that ladder.

- Hint quality (helpful? spoilery? useless?):
  - API Mass Assignment: helpful. Rung 2 explains the mechanism (keys become columns), rung 3 points at the role column without writing the JSON. Solved at rung 2.
  - API Exposure: helpful, rung 3 slightly spoilery (tells you the header outright). Rung 1 plus the module intro's curl -i note was enough for me.
  - API Rate Limit: helpful and honest; rung 3 states the exact recipe (14 wrong, then correct). Spoilery but fair for a Medium.
  - API XFF Bypass: helpful. Rung 2 ("it trusts a client-controlled header") is the key insight; rung 3 spells out the full sequence.
  - API Version Bypass: helpful; rung 3 gives away the root cause (the check never made it to v2) but not the request itself. Fair.
  - CSTI Basic: helpful, but the lab page's claim box already shows the payload, so the ladder is redundant.
  - CSTI Filter Bypass: helpful. Rung 1 says there is a second delimiter, rung 2 suggests fuzzing, rung 3 confirms it evaluates like the first. The delimiter is also in the module briefing. Good ladder.
  - CSTI Constructor: rung 2 names the exact property chain (constructor.constructor). Rung 3 plus the lab page's example payload is nearly the complete solution; only the inner beacon code string is left to write. As a day-one student I still had to assemble and understand the token part, but it felt spoilery for a Medium.
  - CSTI Attribute: helpful; the three rungs walk from "watch the POST" to "reload and check the beacon". Solved at rung 1 plus the briefing.
  - CSTI Stored: helpful; rung 3 (the manual Repeater path) is the most useful hint in the module because it explains the token is single-use per page load.
  - Path steps: the XSS step's payload pattern box and "Why beacons fail" section are excellent. The SQLi step page itself gives almost no guidance beyond "the query is vulnerable"; the real help is on the module page's hint ladder, which the path never links to. That gap is the biggest beginner trap I hit.

- Difficulty fairness:
  - Labels felt right overall. Exposure and the two Easy CSTI labs are genuinely easy; the Mediums each add exactly one idea (a trusted header, an attempt count, a second delimiter, attribute decoding).
  - Constructor Breakout is labeled Medium but is the hardest thing in the two modules for a true beginner: it needs JavaScript function-constructor knowledge that none of the earlier steps teach. For day one it plays like a Hard.
  - The path order is fair (XSS, then SQLi, then IDOR), but step 2 is a bigger jump than the "gentlest to trickiest" ramp promises, because the naive injection payload fails silently with the same message as a wrong password. Nothing distinguishes "wrong password" from "your injection broke the query".

- Burp-first feasibility:
  - I tested with curl (the module pages list curl as a tool), hand-simulating Repeater and Intruder. Every API step maps 1:1 onto Burp Community: login and /api/me in Repeater, the 14 guesses in Intruder Sniper (14 requests is well within Community's throttled speed), the XFF edit is one header line in Repeater, the v1 to v2 flip is one path edit.
  - CSTI is browser-first by design: the evaluation happens in the browser, and the module briefing says so up front. Burp's embedded browser or a proxied browser handles all five labs; Repeater alone cannot evaluate the templates. The beacon-replay path in Repeater works with a fresh token copied from a real page load, exactly as the stored lab's rung 3 describes.
  - Nothing I tried needs Burp Pro. Community edition is enough.

- Suggestions (concrete):
  1. Fix the starting-point URLs: they all point at http://localhost:3000/ while the lab is served elsewhere; generate them from the actual host and port or make them relative paths.
  2. Isolate per-challenge state (reset the demo account's role, or scope changes per session) so finishing Mass Assignment cannot silently block the Version Bypass award, the IDOR path step, or other students on a shared instance. At minimum, warn on the Mass Assignment card: "this change persists and affects later challenges".
  3. Make the rate-limit attempt counter per session (or reset it on a successful login), so a primed counter cannot hand the flag to the next student who simply logs in.
  4. Persist captured flags across server restarts, or warn students on the home page that a restart wipes progress.
  5. On the SQLi path step page, link the module hint ladder and add one line distinguishing the failure modes (a broken query and a wrong password currently look identical).
  6. Tell beginners where alice's password comes from on the Rate Limit card ("you already saw it in the Exposure challenge"), or say the challenges assume Exposure first.
  7. Constructor lab: soften the on-page example payload (it is most of the solution) or raise the difficulty label to Hard.
  8. IDOR module: decide whether guests should read member profiles at all; if login is part of the lesson, return 401 to guests so the boundary is clear.

- Rating: 4
