# PenTrix-VulnLab: Fresh-Eyes Retest Report (Post Fix-Wave)

**Date:** 2026-10-20
**Scope:** The seven modules already fixed in the improvement wave (xxe, upload, race, oauth, cmdi, auth, misconfig). Modules still being edited were deliberately excluded.
**Method:** 12 fresh student testers (4 beginners, 4 intermediate, 2 CTF players, 2 Burp learners), each on their own throwaway instance booted from the current working tree (ports 19501-19512, fresh DB, private cookie jars, curl as Burp Repeater stand-in). Per challenge: (1) honest solve the intended way and confirm the flag awards, (2) attempt the old cheat the reviews exposed and confirm it fails, (3) rate fun, fairness, clarity, hint accuracy.
**Result: 52 of 52 challenges FIXED AND FAIR. Zero broken genuine paths. Zero working cheats.**

## Verdict summary by module

### XXE (8 challenges, 3 testers)
- file, ssrf (beginner): honest solves worked (external entity with a resolvable path for file; SYSTEM identifier aimed at the internal endpoint for ssrf). Old cheats dead: exact markers typed with zero entities, a byte-exact echo of the endpoint body, combined markers, and an internal entity holding the marker value all echo visibly but award nothing on fresh sessions.
- xxe-svg, xxe-soap, xxe-xinclude (intermediate): honest solves worked first try. Old cheats blocked: marker typing with no declarations, entities pointing at nonexistent files (clear ENOENT errors, no award), internal entities holding the marker literal, external entities to unrelated real files. Testing was rigorous: honest solves ran first, then a fresh DB before any cheat test, so no cheat award could hide behind an honest one.
- xxe-external-dtd, xxe-param-oob, xxe-billion-laughs (CTF): genuine out-of-band exfiltration to the student's own listener (server called back with the resolved secret), a fully self-hosted DTD solve, and a real billion-laughs cascade (554-byte payload, 4278 ms busy, 12.67 MB expansion) where a sub-threshold nested payload correctly earns nothing. Cross-session OOB isolation confirmed: another session's exfil never leaked into this student's collector view.

### Upload (8 challenges, 2 testers)
The beacon model is confirmed end to end. Storing a file never awards anything; the flag fires only when the served file's script phones home through the beacon, and the beacon validates token, challenge pattern for the named file, and that the stored file actually contains an executable script.
- stored-xss: uploaded an .html carrying the briefing beacon snippet, simulated execution with the beacon POST, flag captured. One-byte .html with no beacon: stored and served, zero award. A hand-sent beacon for a payload-less file is rejected ("no executable script").
- upload-case, upload-double-ext, upload-ctype: honest bypasses worked (case variant served as image/svg+xml; svg.jpg served as image/svg+xml; header spoof with Content-Type: image/png). The old one-POST-double-award cheat is dead: a dual-snippet file awarded exactly one challenge each (verified both directions), never two from one POST.
- upload-polyglot, upload-strip-once, upload-overwrite, upload-traversal: honest solves worked. Bypass attempts with no executable content were rejected with specific, instructive messages. Traversal pays only on the byte-identical prove read-back; escaped uploads and plain reads earn nothing.

### CMDI (5 sampled challenges, 1 tester)
- basic, bypass, cmdi-pipe, cmdi-newline, cmdi-tab: genuine command execution awards (id output with uid=NNN(name) gid=... shape, real passwd lines). 20+ quoted-echo spoof attempts (double-quote, single-quote, backtick-nested, challenge-adapted variants like pipe-shaped and tab-separated passwd-shaped) all blocked: the spoofed string appears in the output but no flag banner renders. Cheat attempts ran after honest solves in the same session, so a missing banner proves that request's evidence check failed, not a session-state issue.

### Race (6 challenges, 2 testers)
- race-coupon, race-vote, race-balance, race-stock, race-ratelimit, race-referral: all won on first parallel bursts (20/20 redeemed, 20/20 votes, $-1900.00 balance, -95 items left, rate limit exceeded in one window, 20 claims on a 50-point code). Sequential single requests behave correctly, so the bug is the race itself, exactly as taught.
- GET /race/reset now returns 404 (PUT also 404) and changes nothing; reset is POST-only and per-session. Verified with two cookie jars: student A won and reset, student B's state and captures were completely untouched. Earned flags persist across the owner's own resets, so reset cannot farm flags or wipe another student.

### OAuth (8 challenges, 2 testers)
- no-state, code-replay, pkce-skip, code-leak, redirect-bypass, scope-upgrade, secret-in-js, implicit: all honest flows worked first try (login CSRF with a swapped code; replaying an own code twice; exchanging with no code_verifier; exchanging the seeded code from the IdP log; approving an evil-host redirect URI; scope=admin exchange; CLIENT_SECRET read from the public app.js; fragment token recorded through history-log then userinfo from a different session). A dedicated cheat session tried bare requests, fake codes, own-token replays, empty submits, wrong secrets, read-scope tokens on admin endpoints, unknown tickets, wrong git objects, and finished at 0/201: no shortcut awards anywhere.

### Auth (7 challenges, 2 testers)
- user-enum: oracle-phrase giveaway confirmed gone from the login page and module index (grep counts zero); candidates sweep found alice, bob, admin through real POST response differences; hint 3 now tells students to copy the grep phrase from their own probe.
- brute-force: 23-word curl loop, success on attempt 15, no lockout or CAPTCHA, per-session attempt counter visible.
- security-question: public bio states the answer; reset worked; new password signs in, old rejected, in that session.
- reset, reset-predictable, change-pass-noverify, support-impersonate: genuine paths worked (forged admin token, locally computed sha256 recipe verified against alice first, single-field POST, ticket walk 1001-1005). Per-session password isolation confirmed twice: after a session reset alice's password, a fresh jar still signed in with the seeded credentials and could not use the changed one. One student cannot break another's brute-force lab.

### Misconfig (10 challenges, 2 testers)
- backup: GET /misconfig/backup.sql now returns a VISIBLE "FLAG CAPTURED" banner at the very top with the real flag; exactly one flag-shaped string in the whole response; the decoy line is gone from the dump. Award landed on that single request.
- debug, env, robots, listing, git, manager, put, trace, swp: all honest paths worked (traceback plus config dump; .env token; robots.txt to backup.zip; /misconfig/files/ listing; HEAD/ref/object walk; Basic admin:admin; PUT 201 then read-back; TRACE reflecting the Cookie header; dot-prefixed swap filename).
- Port-agnostic copy confirmed: zero occurrences of localhost:3000 across /misconfig, all challenge responses, home, and /scoreboard.

## New friction the fixes introduced (recommendations, non-blocking)

1. **xxe/file Hint 3 (absolute path):** the hint says the file path must be absolute, but the working beginner path is a CWD-relative module path and no absolute path is shown anywhere in the UI. Soften the hint wording.
2. **Upload beacon rejection wording:** two pattern-mismatch rejection messages name the wrong cause (one claims the beacon named a different file when it named the uploaded one; another claims no upload through the endpoint when both challenges share it). The checks behave correctly; only the wording misleads.
3. **misconfig/listing:** secret.txt awards on download but the file itself has no in-file capture banner and still carries a self-labelled DECOY line. Give it the backup banner treatment so beginners get in-file confirmation.
4. **oauth code-replay bleed:** any code exchanged a second time earns the code-replay flag, even mid-flow in another challenge (verified with a PKCE code). Not a shortcut, but a flag can pop up in a lab the student was not aiming at. Also code-leak hint 3 is only true for a fresh own code on first use.
5. **race:** a fresh session starts at balance $0.00, which clashes with the briefing's $100 framing and makes a first test transfer fail; a hint line on the transfer page would fix the confusion. The ratelimit page shows no visible accepted counter after a burst.
6. **cmdi-newline:** the evidence gate only accepts passwd-shaped output while hint 3 says only "a command that prints recognizable output", so a student trying newline plus `id` first sees genuine execution with no award. Tab avoids this by hinting "a recognizable file".
7. **misconfig/put:** capture is silent in the plain-text response; students must check the scoreboard.
8. **xxe minor:** the pingback counter reads 2 for a single solve (entity resolves twice); the external-DTD outer SYSTEM identifier needs double quotes or it fails silently. The absolute secret path is spelled out only on the SVG page; SOAP and XInclude assume cross-challenge discovery.

## Method notes
- Lab progress lives in the session cookie, so every curl request in a session must use the same jar (-c and -b). Without it, the page shows "Flag captured" but the scoreboard stays at 0. Browser users are unaffected.
- A pure curl tester must replay the beacon by hand since curl cannot run the served JavaScript; in the intended Burp plus browser flow this step is automatic.
- Instances needed a few seconds after boot before answering 200.

## Appendix
- Per-student findings: /tmp/retest-findings-01.md through /tmp/retest-findings-12.md (12 files, all zero em dashes).
- Coverage: 52 challenges tested (xxe 8, upload 8, cmdi 5 sampled, race 6, oauth 8, auth 7, misconfig 10), each with at least one honest solve and at least one cheat attempt.
- No product code was edited during this retest. Nothing was pushed. This report contains no flag literals and no flag-storage details (D18 clean).
