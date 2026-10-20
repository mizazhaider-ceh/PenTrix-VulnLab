# Student Review: Day-One Yuki (beginner-11)

- Modules tested: Broken Authentication (8 challenges: user-enum, brute-force, reset, otp-bruteforce, reset-predictable, security-question, change-pass-noverify, support-impersonate) and CSV Formula Injection (4 challenges: formula-csv, formula-dde, formula-hyperlink, formula-pipe). Tested against the shared pool instance at http://127.0.0.1:18401 with curl, simulating Burp Proxy/Repeater/Intruder flows, one cookie jar per test thread.
- Post-reboot verification: the VM hosting the pool rebooted mid-testing (around 01:37 UTC) and per-boot state was reset. After the reboot I re-ran user-enum and brute-force with a fresh jar: both awarded their flags again (fresh flag values) and the scoreboard read 2/201 for that jar. I also re-confirmed formula-csv post-reboot with a separate fresh jar (X-Flags header present, scoreboard 1/201). All other results above were confirmed live before the reboot.

- What worked well:

- Every challenge is genuinely solvable by hand and the lab awarded the flag each time I completed the real exploit: all 8 auth challenges and all 4 formula challenges. I saw all 12 flag banners in responses.
- The module briefing pages are excellent for a day-one student. The auth page explains the product fiction (Northwind Accounts), lists every challenge with difficulty, entry page, a copyable starting point, and a 3-rung hint ladder. The formula page's "Module briefing" actually teaches the concept first (cells starting with = + - @ become live formulas, quoting is not sanitization) before asking me to attack.
- Small touches that saved me as a beginner: the brute-force login page shows "Failed sign-ins this session: N" so I could see the counter climbing; the SHA reset page prints the exact token recipe on the page; the base64 reset page shows the token on screen; the security-question page links straight to the community profiles; the support page tells me the ticket range (1001-1005) up front; the OTP page hands me the token and only hides the code.
- All cheat tests behaved correctly: bare claims were rejected everywhere (enum-submit without probing, login with fewer than 5 failures, forged reset tokens after requesting a legit one, wrong security answer, change-password with no session, unknown ticket number, wrong OTP, and a clean CSV export with no payload all awarded nothing).
- The scoreboard tracks per-challenge Captured/Not captured state per module, which is motivating and clear.

- Bugs found (with reproduction):

1. **Parallel requests sharing one session cookie silently lose captured flags.** Repro: with one cookie jar I verifiably earned 7 auth flags (flag banners in responses), then ran the OTP brute force as 6 parallel request streams sharing that same jar (exactly what Burp Intruder does with one session cookie, which the lab's own hints prescribe: "Keep one session cookie across every attempt"). Afterwards the scoreboard showed only 5 of my 12 earned flags; the 7 auth captures were gone from the session. Concurrent writers also corrupted the shared cookie jar file itself (it ended up deleted). For a real student this means: run a big Intruder attack in the same browser session where you keep your progress, and you can lose scoreboard progress with no error message.
2. **Formula module page never shows captured state.** Repro: capture the formula-csv flag (X-Flags header present, scoreboard counts 1/201), then reload /formula. No "flag captured" indicator appears on any challenge card. The auth module page does render captured flags on its cards; the formula module page has no equivalent, so a student gets zero on-page confirmation. (The per-challenge card code with a captured pill exists but is never reached by the served routes.)
3. **Support impersonation awarded the flag for ticket 1001 (alice), not just the admin ticket.** Repro: fresh session, GET /auth/support/login?ticket=1001. The response said "You are now signed in as alice (role admin)" and the lab awarded the flag. The intended solve is walking the sequential tickets to the admin one (1005), but on the shared instance alice's role read as admin, so the very first ticket tried completed the challenge. This is confusing for a beginner ("wait, was alice the target?") and may be cross-tester data contamination on the shared instance.
4. **Starting points reference the wrong port.** Every "Starting point" block says to open http://localhost:3000/auth/... but the lab serves on port 18401. A day-one student following the instructions literally gets connection refused and may think the lab is broken.

- Friction/confusion points:

- The brute-force challenge says to "load a small weak-password wordlist" but the lab provides no wordlist and no link to one. A true beginner has no wordlist (Burp does not ship one) and will stall here. The password is guessable, but the student is never told where a wordlist comes from.
- Formula flags are returned ONLY in the X-Flags response header. In a plain browser the export is a file download, so the header is invisible; a beginner without a proxy sees a CSV download and no flag, and may conclude the exploit failed. The briefing should say "check the scoreboard too" or show an on-page confirmation.
- The OTP challenge needs up to 10,000 requests with no lockout. That is the lesson, but Burp Community's Intruder is throttled, so a beginner following the Burp-first path faces a very long grind. A note about this (or fewer digits) would help.
- The DDE hint ladder never shows the payload shape. Hint 3 says "packaging the DDE() call so the exported cell still opens as a live formula" but a beginner has never seen DDE() syntax; I had to guess the quoting and separators. One rung showing the function shape (without a working copy-paste payload) would teach more.
- The security-question Hint 1 names the exact bio URL (/auth/bio/alice). It is rung 1 of 3, so it felt slightly spoilery that early, though it is kind to beginners.
- The shared instance restarted mid-test (connection refused for ~20s, then back). After the restart, lab data I had created (my formula contact rows) was gone. On a shared pool instance this can wipe a student's in-progress work without warning.
- Minor UI noise: the "Break then fix" section repeats "Fix mode is not available for this challenge yet." once per challenge (8 identical lines on the auth page). One line would do.

- Hint quality (helpful? spoilery? useless?):

- user-enum: helpful. Rung 1 ("log in once with a made-up username, then once with a real-sounding one, compare responses") taught me the oracle idea; rung 3 gave the exact Intruder setup. Not spoilery.
- brute-force: helpful. Rung 3 telling me the 5-failure session rule was necessary, not spoilery, since it is a lab mechanic I could never guess.
- reset (base64): helpful. Rung 1 (paste the token into Decoder) is the perfect nudge; rung 3 gives the forge-and-replay shape.
- otp-bruteforce: helpful, but none of the rungs warn about the 10k-request grind on throttled Community Intruder.
- reset-predictable (SHA-256): helpful. Rung 2 ("Burp Decoder can hash text for you") genuinely taught me a tool feature.
- security-question: helpful but rung 1 borders on spoilery (hands me the exact bio URL).
- change-pass-noverify: helpful. Rung 2 ("the server checks your session cookie, never the old password") states the vulnerability plainly at the right rung.
- support-impersonate: helpful. Rung 1 asks the right question ("which Burp step turns the ticket number into a variable"), rung 3 gives the Intruder numbers setup.
- formula-csv: helpful; rung 3 names the "cmd pipe cell" shape.
- formula-dde: partially useful. Rungs 1-2 are good, but rung 3 never shows the DDE() shape, so I stalled on syntax longer than on any other Easy challenge.
- formula-hyperlink: helpful; rung 2 explains the exfiltration idea (glue cell data into the URL).
- formula-pipe: helpful; rung 1 names the | trigger, rung 3 describes the payload shape.

- Difficulty fairness:

- Auth Easy challenges (user-enum, reset, security-question, change-pass-noverify) are fair and well scaffolded; each took me minutes once I read the page.
- Auth Mediums (brute-force, reset-predictable, support-impersonate) are fair; the hints carry a beginner through.
- otp-bruteforce as Medium is conceptually fair but practically harsh for Burp Community users because of the 10,000-request throttle grind; with curl and parallel requests it took about 3.5 minutes to find code 7814.
- Formula Easies (csv, dde, pipe) are fair except DDE's missing payload shape (above). HYPERLINK as Medium is fair.

- Burp-first feasibility:

- user-enum: yes, Repeater to spot the two error messages, Intruder sniper on the username field.
- brute-force: yes, Intruder sniper on the password field; Community throttling is tolerable for a tiny wordlist.
- reset: yes, Decoder to spot base64, Repeater to replay the confirm POST (also doable in a plain browser via the confirm form, which prefills the token from the query string).
- otp-bruteforce: technically yes, but 10,000 requests through throttled Community Intruder is the one challenge where the Burp-first path hurts.
- reset-predictable: yes, Decoder hash plus Repeater.
- security-question: yes, browser plus Repeater.
- change-pass-noverify: yes, Proxy to capture the session, Repeater to replay with only newPassword.
- support-impersonate: yes, Repeater stepping 1001-1005 or Intruder numbers on the ticket query param.
- formula x4: yes with Repeater, with one caveat: the flag only appears in the X-Flags response header, so the student must know to inspect response headers in the proxy; a plain browser download shows nothing.

- Suggestions (concrete):

1. Replace all http://localhost:3000 URLs in starting points with relative paths (or the actual host:port) so copy-paste works.
2. Add captured-state indicators to the formula module's challenge cards, matching what the auth module page already does.
3. After a CSV export that earns flags, show an on-page confirmation (or point to the scoreboard), since the X-Flags header is invisible on a plain browser download.
4. Ship a tiny starter password wordlist with the lab (or link one) for the brute-force challenge; day-one students do not have one.
5. On the OTP challenge, warn that 10,000 requests on Burp Community Intruder is slow, or reduce the code to 3 digits for the lab.
6. Give the DDE hint ladder one rung showing the DDE() function shape (arguments and separators) without a working payload.
7. Collapse the repeated "Fix mode is not available for this challenge yet." lines into a single note.
8. Make same-session concurrent requests safe to run (the exact pattern the hints prescribe), or warn students to run Intruder attacks in a session where they do not mind losing progress; at minimum, do not silently drop previously captured flags.
9. For support-impersonate, make the intended target unambiguous even if shared-instance data drifts (e.g., the brief could say the flag needs the staff/admin ticket rather than "a session that matters").

- Rating: 4/5
