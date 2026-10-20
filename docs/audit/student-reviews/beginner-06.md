# Student Review: Day-One Leo (beginner-06)

- Modules tested: Security Misconfiguration (10 challenges), Session Management (6 challenges). Tested live at http://127.0.0.1:18406/ with curl as a Burp Proxy/Repeater stand-in, one unique cookie jar (/tmp/cookies-beginner-06.txt), sequential requests.

- What worked well:
  - Every exploit in both modules works. Final scoreboard after the post-reboot re-test: misconfig 10/10, session 6/6, all showing "Captured" with correct names, difficulty pills, counts, and progress bars. No scoreboard display bugs.
  - The flag banners on most challenge pages (debug, git, swp, trace, manager, robots, and all six session challenge pages) made success obvious: exploit, see the flag, done.
  - Hint ladders are present on every challenge card (Nudge / Technique / Explicit as click-to-reveal details). They teach without hand-holding too early.
  - Cheat resistance is good: direct requests to protected endpoints without the exploit step all failed correctly (predictable/admin, leak-admin, and logoutdemo/secret returned "Access denied" with a wrong or missing session id; manager returned 401 with wrong credentials; the debug page without ?err=1 showed no flag). Replaying an exploit request re-displays the flag once, with no double counting on the scoreboard.
  - The session module brief teaches the concept well ("break that trust... end up holding a session the server believes belongs to admin") and names the cookie (lab_sid) plus the curl jar habit up front.

- Bugs found (with reproduction):
  1. Exposed .env File: hint 3 is wrong. It says "The URL is /misconfig/.env. Read the ADMIN_API_TOKEN line in the response, that value is the flag." But the served response shows `ADMIN_API_TOKEN=<redacted>` and `SESSION_SECRET=<redacted>`. No flag string ever appears in the response. The lab awarded the flag silently (scoreboard count rose), but a beginner following the hints to the letter will stare at a redacted line forever and conclude the lab is broken. Repro: GET /misconfig/.env, read the response.
  2. Exposed Database Backup: the served backup.sql contains a flag-shaped decoy string (reads PENTRIX{DECOY_DO_NOT_USE}) as the only flag-like text. The lab awarded the flag silently with no banner in the response, so a day-one student will copy the decoy as their answer. Either show the real award visibly or remove the decoy text. Repro: GET /misconfig/backup.sql.
  3. Inconsistent success feedback: Directory Listing Leak (secret.txt) and Unauthenticated HTTP PUT (readback) also award silently with no visible flag banner, while debug/trace/manager/git/swp/robots show one. Four challenges where "did it work?" is answered only by checking the scoreboard.
  4. Shared-pool environment flakiness (not a code bug, but it blocked testing twice): the documented login (admin / admin123, shown in the login form placeholders) was rejected with 403 on the pool instance twice during my session, once before the first reboot and again about 30 minutes after the second reboot. Each time it blocked the fixation and logout challenges completely, since no credentials are documented anywhere else. After each reboot the credentials worked again. If other students or automated tracks share the pool, a day-one student will hit "Bad username or password" with the documented pair and assume they are doing something wrong.

- Friction/confusion points:
  - Git challenge: after walking HEAD to the ref to the commit object, the flag string in the commit diff is glued directly onto a `<redacted>` tag (the line reads like the token is redacted, with the flag characters appended). I only found it with find-in-page. A beginner will read "redacted" and give up. Make the flag visually distinct from the redaction tag.
  - Predictable challenge: I broke my own flow by combining a stale lab_sid cookie in the jar with a manual Cookie header; once I replaced the cookie value cleanly (like editing it in browser devtools), the admin panel opened. The page could say explicitly: "replace your lab_sid cookie value with the admin's id (devtools > Application > Cookies, or edit the Cookie header in Repeater)."
  - URL challenge: visiting the proxy log directly shows "empty" until you first visit the login page (that visit seeds the admin's logged URL). A student who jumps straight to the proxy log link will think the lab is broken. Seed the admin entry on first proxy-log visit too, or add a note.
  - The session module brief says "Each challenge gives you a login" but the credentials exist only in the login form placeholder text ("try admin", "try admin123"). Hint 1 of fixation and logout should name the pair explicitly; placeholders are easy to miss.
  - My own testing artifact, not a lab bug: running two curls in parallel against the same cookie jar raced on the session cookies and three awards temporarily showed "missing" on the scoreboard. Sequential requests (what a student does) were fine. Not reporting this as a lab bug.
  - Mid-test, the instance restarted and all 13 of my captured flags reset to 0/10 and 0/6. I re-earned everything after. A student mid-lab would lose all progress with no explanation.

- Hint quality (helpful? spoilery? useless?):
  - debug: Hint 1 unlocked it (points at the "Simulate an error" link and the query parameter it sets). Helpful, not spoilery.
  - backup: Hint 2 names backup.sql outright, which is the whole puzzle; acceptable for Easy, borderline spoilery. A beginner needs rung 2.
  - listing: Hint 1 unlocked it. Helpful.
  - git: a genuinely good three-rung walkthrough (HEAD, follow the ref, walk the object store). Needed rung 3 for the object path shape. Helpful, appropriately explicit for Medium.
  - swp: Hint 3 gives the exact swap-name construction rule. A day-one student who has never used vim cannot get it from hints 1-2 alone, so rung 3 does the heavy lifting. Helpful.
  - trace: Hint 1 tells you to change the method verb in Repeater. Helpful, not spoilery.
  - env: Hints 1-2 are fine; hint 3 is misleading (see bugs). No rung leads to a visible flag; the scoreboard was the only confirmation. Useless as written.
  - manager: Hint 1 ("the most common pair") plus hint 3 (Basic auth in Repeater). Helpful. Rung 1-2.
  - robots: Hint 2 names backup.zip outright. Spoilery but fine for Easy.
  - put: Hint 1 gives the full recipe (PUT, Content-Type: text/plain, GET back). Spoilery-ish but crystal clear for a beginner.
  - fixation: the preset link makes it nearly mechanical; hints teach the fixation concept around it. Helpful.
  - logout: hint ladder is clear (log in, capture cookie, log out, replay). Helpful. Rung 1.
  - predictable: "Do the math" with both ids shown on the page. Helpful; arguably easy for Medium but the lesson is the concept.
  - url: Hint 1 points at the proxy log. Helpful. Rung 1.
  - never-expires: Hint 1 points at the archive. Helpful. Rung 1.
  - log-leak: Hint 1 points at the debug log viewer. Helpful. Rung 1.
  - Overall: high quality. The single broken one is env hint 3. Most challenges fall at rung 1-2, which is right for a beginner-facing module pair.

- Difficulty fairness:
  - Misconfig (Beginner): fair. Ten challenges, seven Easy, three Medium (git, env, put). The Mediums earn it: git needs the object-store walk, put needs composing a raw PUT.
  - Session (Intermediate): mechanically easy (read a leaked value, set a cookie), but the Intermediate label fits because you must understand what a session id is and how the server trusts it. The module prerequisites line names "auth" but does not link or describe it; a true day-one student may not know where to find it.
  - The .env redaction issue aside, nothing felt unfair or required knowledge outside the briefs and hints.

- Burp-first feasibility:
  - All 16 challenges are fully doable in Burp Community. Proxy for browsing and spotting the Set-Cookie / query params, Repeater for replaying with edited Cookie headers and changed methods (TRACE, PUT), browser devtools for editing lab_sid. Intruder is not needed anywhere (manager is a single known default pair, not a brute-force). No challenge needs Burp Pro features.

- Suggestions (concrete):
  1. Fix env hint 3: rewrite it to say the request itself earns the flag and to confirm on the scoreboard, or make the flag visible in the response instead of redacted. As written it promises something the page cannot deliver.
  2. backup.sql: remove the flag-shaped decoy text or add a visible flag banner to the response so students are not misled into submitting it.
  3. Add visible flag banners to the silent-award responses (backup, listing secret.txt, PUT readback, .env) for consistent success feedback.
  4. Seed the URL challenge's proxy log on first visit to the proxy-log page, not only on the login page visit, so "empty" never greets a student who jumps ahead.
  5. State the lab credentials (admin / admin123) in the session module brief and in hint 1 of fixation and logout, not only in form placeholders.
  6. On the predictable page, add one line telling the student to replace (not just add) their lab_sid cookie value with the admin's id.
  7. Make the flag in the git commit diff visually distinct from the surrounding redaction tag so find-in-page is not required.

- Rating: 4
  - Strong, teachable pair of modules with working exploits, good cheat resistance, and mostly excellent hints. Loses a point for the broken .env hint 3, the backup.sql decoy, and the silent awards, plus the shared-pool credential flakiness I hit twice.

- Reboot verification note: the parent reported a VM reboot at ~01:37 UTC. All results above were re-verified after it: the full session module (6/6) and misconfig module (10/10) were re-exploited on the live instance and the scoreboard confirmed both totals. The fixation and logout flags shown to me were identical strings before and after the reboot. The log-leak challenge, which was interrupted by the first outage, was completed for the first time in the post-reboot pass. Cheat tests (no-cookie access, wrong credentials, missing exploit parameters, replay idempotency) were all run post-reboot.
