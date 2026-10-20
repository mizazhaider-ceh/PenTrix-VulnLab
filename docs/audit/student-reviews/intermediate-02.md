# Student Review: Grinder Hana (intermediate-02)

Tester persona: intermediate student, knows XSS/SQLi basics and Burp fundamentals, grinding efficiently. Tested with curl as Burp simulation on a unique cookie jar, sleep 1 between bursts.

Note on verification: the VM hosting the pool rebooted at ~01:37 UTC mid-test and per-boot state reset, which wiped my captures once. I re-ran every exploit on the live post-reboot instance and re-verified. Everything below was confirmed on the live instance; scoreboard ended at 26/201.

## Modules tested

- race: all 8 challenges (race-coupon, race-balance, race-vote, race-referral, race-register, race-upload-scan, race-ratelimit, race-stock). Each exploited with parallel curl bursts (20 parallel for coupon/balance/ratelimit, 10 for referral, 2 for vote/register/stock, POST+fast-GET for upload-scan). The lab awarded the flag in every case.
- upload: all 8 challenges (stored-xss, upload-ctype, upload-case, upload-double-ext, upload-strip-once, upload-traversal, upload-overwrite, upload-polyglot). The lab awarded the flag in every case.
- cors: all 6 challenges (cors-reflect, cors-null, cors-regex, cors-wildcard-data, cors-subdomain, cors-expose-headers), proven through /cors/prove with hand-crafted Origin headers. The lab awarded the flag in every case.
- Scenario "API Heist" end to end: all 4 stages (leak, escalate, forge, take-all) completed in order, scenario flag shown on the scenario page, progress 4/4.

Cheat testing performed and all failed correctly: sequential (non-parallel) coupon redeem earned nothing; plain .svg filename on the strip-once filter was stripped with no flag; Content-Type text/html on mime-check was blocked; /jwt/none rejected an HS256-signed admin token; /cors/prove rejected Origin https://evil.com for cors-null and a legit Origin https://app.pentrix.lab for cors-regex; /api/v1/users/3 returned 403 as alice. No claim/beacon endpoint exists anywhere, flags are only awarded inside challenge handlers on genuine exploitation, and replays of the same exploit do not double-count on the scoreboard.

## What worked well

- Every challenge's vulnerability works exactly as its briefing describes, and every flag is earned by real exploitation. Controls behave correctly.
- The TOCTOU race (upload-scan) is honest: fetching /race/files/<name> within the 2s window shows the file and awards the flag; fetching after the scan returns 404.
- The CORS /prove design is genuinely good for learning: it makes a real server-side request with your Origin, prints the exact response headers, and awards only on the correct header combination. Raw curl header checks matched what prove showed every time.
- The API Heist kill chain is coherent and the unlock logic is strict: stages unlock exactly one at a time in order, the progress bar and Captured badges track correctly, and the scenario flag appears on the scenario page only after all four. Story coherence is solid: the leaked rows (stage 1) feed the privilege column you abuse (stage 2), then you stop asking for permission entirely (stage 3), then you hit the forgotten v2 endpoint (stage 4).
- Race invariants hold under sequential use: single coupon redeem, single transfer, single order all behave correctly and earn nothing.

## Bugs found (with reproduction)

1. **CORS subdomain prove grader false negative.** `https://cdn.trusted.pentrix.lab` genuinely passes the endpoint's suffix check (the endpoint returns `Access-Control-Allow-Origin: https://cdn.trusted.pentrix.lab` plus `Access-Control-Allow-Credentials: true`, confirmed by raw curl on /cors/api/partner), but `/cors/prove?vuln=cors-subdomain&origin=https://cdn.trusted.pentrix.lab` answers "Not vulnerable" because the grader requires the hostname to contain the string "evil". The challenge `how` text tells students to use "your own invented subdomain under trusted.pentrix.lab", which directly contradicts the grader. Only the pre-filled suggestion works.

2. **Mass-assignment flag awarded without the attack (shared pool cheat).** The flag condition checks the post-update role, not whether the request set it. Reproduction: after my first legitimate exploit left alice as admin in the shared data, a brand-new session logged in as alice (already admin, confirmed via GET /api/me) and sent `PATCH /api/me` with `{"email":"cheat@test.lab"}` only, never touching `role`, and the lab still awarded the flag. Any student after the first exploiter on this shared instance can collect this flag without doing the attack.

3. **Race flag guard itself races.** In a 20-request burst, 15 to 19 responses each embed a full flag box (identical flag value each time, scoreboard still counts 1, so the store dedupes). The `captured` guard races the same way the challenge vuln does. Scoring stays correct, but seeing the flag box in 19 responses looks like the flag was awarded 19 times, which is confusing teaching.

4. **Module index example command uses a dead port.** The race module index shows `curl -s -X POST http://localhost:3000/race/coupon/redeem`, which is connection-refused on this pool (port 18407). Students copying it literally fail with no explanation.

5. **Scoreboard off-by-one.** The nav chip shows 26/201 but the scoreboard page's "Captured" filter lists 27 captured entries for the same session.

6. **Shared race state across sessions.** `/race/reset` wipes the race state globally, so any student's reset clobbers every other student's in-flight attempts on this pool. Similarly, the mass-assignment exploit persisted alice as admin for all sessions (this is what enabled bug 2).

7. **Transient scenario render glitch.** Once, about a second after stage 2's flag was awarded, the scenario page rendered the just-completed stage-2 card as "locked". Re-fetching later and a fresh-jar re-test both rendered correctly (completed stages show full titles, Captured badges on all four at 4/4), so this looks like a render race, flagged in case others see it.

## Friction/confusion points

- **The documented Burp Intruder workflow is not followable in Burp Community.** Every race challenge pushes "send to Intruder, run a parallel attack with concurrent requests / resource pool". Community Intruder is throttled and cannot realistically fire 20 truly parallel requests inside the 150-250ms race window. I used curl background jobs (`curl ... &` x20, wait) instead and won every race on the first attempt. Challenge pages never mention the curl alternative; only the module index does (with the wrong port, see bug 4). The docs should ship a copy-paste parallel curl command per challenge and either mention Turbo Intruder or warn that stock Community Intruder cannot do this.
- The 150-250ms race window is generous, which is fine for learning, but it makes the "Hard" rating on race-upload-scan feel off (it is one POST plus one GET, I finished it in under a second).
- Stage 1's briefing says the viewer page lies and only the raw API earns the flag. The distinction is real (/api/users/view never awards, /api/users does) and it is covered, but it is easy to miss for a fast grinder; the viewer page itself could say "fetch /api/users directly for the flag" more plainly.
- The polyglot challenge works as advertised: a `GIF89a` prefix plus HTML body uploaded to /upload/polyglot is served as `text/html` at /upload/poly/x.gif, and a plain GIF89a body with no HTML earns nothing. Good teaching moment about magic-byte checks.

## Hint quality (helpful? spoilery? useless?)

- Race hint ladders follow a good shape (nudge, then technique, then payload shape) and are genuinely helpful. None are useless.
- Upload hints trend spoilery at level 3: the strip-once "start" box literally gives the exact filename (`evil.s.svgvg`). The level-1 and 2 hints teach well, so this only affects students who read all three before trying.
- CORS hints are fine; the prove page's "need" text is explicit about the required header combination, which is spoilery but necessary since it is the grader.
- The JWT none-admin hints are solid (Burp Decoder suggestion is a nice touch for an intermediate).
- One accuracy issue: the cors-subdomain `how` says "your own invented subdomain" while the grader only accepts names containing "evil" (bug 1). That is a hint/grader mismatch, not just spoiling.

## Difficulty fairness

- Fairly rated: race-vote (Easy), race-stock (Easy), race-coupon/balance/referral/register (Medium), upload-case/ctype/stored-xss (Easy), upload-strip-once/traversal/overwrite (Medium).
- Overrated: race-upload-scan (Hard; it is a POST plus a quick GET, one of the easiest in the set), race-ratelimit (Medium; a single 20-request burst, borderline Easy), upload-polyglot (Hard; the only real skill is knowing the 6 GIF magic bytes and concatenating, Medium at most for an intermediate).
- Nothing felt underrated or unfair; no challenge required guessing, and every flag landed on the first correct attempt.

## Burp-first feasibility

- Proxy + Repeater flows work for everything except the parallel race bursts. All upload challenges are textbook Repeater (raw body with the ?filename= query param), all CORS challenges are Repeater-friendly (Origin header, then /cors/prove), the JWT forge is one hand-crafted token pasted into the form, and the API Heist stages are all single requests. The TOCTOU race is doable in Repeater manually (upload tab, then GET the file URL quickly) but tight at 2 seconds; trivial with curl.
- Race parallel bursts are the one non-Burp-first-feasible part in Community edition. Needed instead: curl background jobs. This is the single biggest gap between the documented workflow and reality.

## Suggestions (concrete)

1. Fix the cors-subdomain grader to accept any attacker-controlled subdomain of trusted.pentrix.lab, not just names containing "evil", to match the `how` text. Or change the `how` text to say the name must contain "evil".
2. Fix the mass-assignment flag condition: award only when the request body included `role: "admin"` (or when the role was not admin before the update), so a student cannot collect it with an email-only PATCH after someone else's exploit.
3. Put a working parallel-curl command block on every race challenge page (e.g. `seq 1 20 | xargs -P20 -I{} curl ...` with the correct host/port), alongside the Intruder steps, and note that Burp Community Intruder is throttled so curl or Turbo Intruder is the realistic path.
4. Fix the module-index curl example to use the pool's actual host/port (or a relative path) instead of localhost:3000.
5. Make race state and the api users table per-session, or add per-challenge reset buttons, so shared-pool students do not clobber each other (and so bug 2's cheat cannot propagate).
6. Re-rate race-upload-scan to Medium and upload-polyglot to Medium; current ratings mislead difficulty expectations.
7. Reconcile the scoreboard chip (26/201) with the captured filter (27 entries).
8. Add a one-line note on /api/users/view that the flag is only awarded from the raw /api/users response, since the viewer is where the stage link points.

## Rating: 4
