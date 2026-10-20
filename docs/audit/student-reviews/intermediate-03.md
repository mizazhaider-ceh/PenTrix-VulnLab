# Student Review: Grinder Ivan (intermediate-03)

- Modules tested: Session Management (6 challenges), API Security Flaws (5), Client-Side Template Injection (5). 16 total, all exploited with curl simulating Burp (Proxy/Repeater flow) against http://127.0.0.1:18408/. All 16 flags captured; scoreboard confirmed 6/6, 5/5, 5/5 and the nav chip read 16/201.

- What worked well:
  - Every challenge's intended exploit path works end to end and awards the flag on genuine exploitation: fixation (preset sid kept across admin login), logout (old cookie replays after logout), predictable (sequential sid swap), url (admin sid replayed from proxy log), never-expires (decade-old archived sid still accepted), log-leak (admin sid from debug log), exposure (flag in X-Pentrix-Flag header plus leaked password field in raw JSON), mass-assignment (PATCH role to admin), rate-limit (14 wrong guesses then correct login on attempt 15), ratelimit-xff (lockout then correct login with spoofed X-Forwarded-For), api-version-bypass (v1 403 vs v2 200 on another user's record), and all five CSTI labs (template saved, page reloaded, page-bound token echoed to the beacon).
  - Anti-cheat checks are solid in session and api: login without preset fixation awards nothing; live (not logged out) session on the secret page awards nothing; guest sid on the predictable admin panel is 403; wrong sid on leak-admin is 403; the /api/users/view viewer page never awards the flag; benign PATCH with role=user returns flag null; unauthenticated PATCH is 401; correct v1 login under XFF lockout without the header is 429 with no flag; own record via v2 returns flag null; unauthenticated v2 read is 401.
  - CSTI beacon hygiene is half good: bare beacon with no nonce is 400, garbage nonce is 400, and the page-bound token is single use (replay fails). Unknown vuln ids on /beacon and /claim-status are rejected cleanly.
  - Scoreboard is accurate: module names, per-module counts (6/6, 5/5, 5/5), progress bars, per-challenge captured states, and the 16/201 chip all matched my actual captures.

- Bugs found (with reproduction):
  1. CSTI beacon forge bypass (all 5 CSTI labs). Repro: fresh cookie jar, GET /csti/basic (never submit any template), extract the CSTI_NONCE token from the page, then GET /csti/beacon?v=basic&d=49&n=<token>. The lab awarded the flag. The token proves only that a page was loaded, not that any template was injected or evaluated. The module briefing documents the beacon parameters, so this bypass is trivially discoverable, and the stored lab's hint 3 explicitly teaches the manual beacon recipe.
  2. Stored CSTI cross-student contamination. Repro: with jar A I saved display name {{7*7}}; with a fresh jar B I only loaded /csti/stored and forged the beacon with B's own token. The lab awarded the flag to jar B, which never submitted anything. In the shared pool, one student's payload auto-awards every later visitor.
  3. GET /api/v2/users/:id leaks the unmasked secret field for any user (verified as alice reading user 3's row), while GET /api/users deliberately masks it and its page states the secret is the SQLi track's exfiltration target. The API module therefore hands out what the SQLi labs are meant to teach stealing. Suggest masking secret in the v2 row like the exposure endpoint does.
  4. Scoreboard transient misrender. One fetch rendered 0/6, 0/5, 0/5 for my modules while a fetch minutes before and a fetch minutes after (same unchanged session cookie) rendered the correct 6/6, 5/5, 5/5. Could not reproduce afterward; possibly a mid-restart read. Worth one look by whoever owns the scoreboard.
  5. Stale port in hints: 8 "start" fields reference http://localhost:3000 (session: never-expires, logout, url, predictable; api: version-bypass, mass-assignment; csti: basic, attr) while the pool instance runs on 18408. A student following the hint literally hits a dead port.

- Friction/confusion points:
  - Hint ladders render on the module index cards and on the fixation and logout lab pages only. The other 14 lab pages show no hint ladder, so a stuck student must navigate back to the module index.
  - rate-limit and ratelimit-xff require alice's real password, which is only discoverable in-lab via the exposure challenge (leaked password field). The hints never mention this chain, so a student starting at rate-limit has no pointer.
  - Predictable prints the admin's sid outright on the demo page ("Their session id: 1001"), so the challenge is read-and-paste despite the hint saying "do the math".
  - Mass-assignment mutates shared state: alice's role stayed admin in the shared store for later testers until I reset it, and every subsequent PATCH then re-awarded. Shared-pool artifact, confusing for the next student.
  - The url lab's proxy log is global, capped at 50 entries, and the admin URL is seeded once per boot. In a busy pool it can scroll out and soft-brick the lab until restart.
  - The rate-limit attempt counter is per-username and global, so another tester's guesses inflate your count and can award the flag early.
  - The session module brief says "Each challenge gives you a login", but log-leak, never-expires, predictable, and url have no login form.
  - Environment note: the pool instance went down mid-session (connection refused, ~03:15 CEST). Per instructions I did not restart it. All testing was complete before the outage.

- Hint quality (helpful? spoilery? useless?):
  - Session hints: helpful, good nudge to technique to payload-shape progression, Burp specific. Fixation and logout ladders are the best written.
  - API hints: helpful. Exposure hint 3 (check response headers) is exactly the right nudge. Missing only the password-chain pointer for the two rate-limit labs.
  - CSTI hints: helpful but spoilery. The claim boxes print exact payloads ({{7*7}}, [[7*7]]), the constructor page prints the full breakout fetch payload verbatim (contradicting its own hint that says the beacon code "is the one part you must write yourself"), and stored hint 3 teaches the beacon forge bypass. Constructor is effectively answer-on-the-page.

- Difficulty fairness:
  - Session: fixation Medium fair; logout Easy fair; predictable should be Easy not Medium (admin sid is printed); url, never-expires, log-leak Easy fair.
  - API: exposure Easy fair; mass-assignment Medium fair; rate-limit Medium fair only if the password chain is hinted; ratelimit-xff Medium fair; version-bypass Medium fair (arguably Easy-Medium).
  - CSTI: basic Easy fair; filter-bypass Medium fair; attr Medium fair; stored Easy fair; constructor is labeled Medium but the page hands over the exact payload, so it plays as Easy.

- Burp-first feasibility:
  - All 16 are doable with Burp Community (Proxy plus Repeater). The rate-limit lab's 14-request Intruder run is fine under Community throttling. No Pro-only features needed. The CSTI labs need a real browser (Burp's embedded browser works) for the intended auto-beacon path; Repeater alone covers the manual beacon path. curl reproduced every flow, so nothing depends on exotic tooling. One curl-side footnote, not a lab bug: combining -b jar with -H "Cookie:" sends two Cookie headers and Express reads the first, so curl users should edit the jar value instead; in Burp you just edit the header.

- Suggestions (concrete):
  1. Bind the CSTI beacon to a real submission: issue the token at template POST time (or require the beacon data to match the stored template's evaluated result) instead of at page-load time, and remove the forge recipe from the stored hints.
  2. Mask the secret field in /api/v2/users/:id responses, matching the exposure endpoint, to stop cross-module leakage into the SQLi track.
  3. Render hint ladders on all 16 lab pages, not just the index cards and two session pages.
  4. Replace the 8 hardcoded :3000 URLs in start fields with relative links or the deployment's actual base.
  5. Add a password-chain pointer to the rate-limit and ratelimit-xff hints ("where have you already seen full user rows?").
  6. Stop printing the admin's sid on the predictable demo page; show only that the admin signed in right after you, so the +1 computation is real (keeps Medium honest).
  7. Remove the verbatim breakout payload from the constructor page note, or relabel the lab Easy.
  8. Give the stored lab per-student profile rows or a reset button, and raise or scope the proxy-log cap, so shared-pool students do not inherit each other's solves.
  9. Fix the session brief's "each challenge gives you a login" line.
  10. Investigate the one transient all-zero scoreboard render.

- Rating: 4
