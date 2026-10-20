# Student Review: Payload Pam (ctf-07)
- Modules tested: JSONP Injection (5/5 flags captured), Race Conditions (8/8 flags captured), Unrestricted File Upload (8/8 flags captured). 21/21 total. Tested only against http://127.0.0.1:18404/ with a dedicated cookie jar, curl only, no browser, no server restarts.

## Time-to-first-flag
- JSONP: under 1 minute (Callback XSS fell on the first beacon call).
- Race: about 2 minutes (first parallel burst on race-balance).
- Upload: under 1 minute (first upload POST).
- Whole session to 21/21: roughly 25 minutes of active testing. Zero flags required a browser or Burp.

## What worked well
- Race module is the strongest of the three. The 150 to 250ms check-to-use window makes every race genuinely winnable with plain parallel curl, first try, no flakiness. Sequential double-actions are properly refused everywhere: second sequential register says "Username taken", second sequential stock buy says "Out of stock", second coupon/referral/vote calls say "already redeemed/claimed/voted". The intended technique is actually required.
- race-upload-scan is a clean TOCTOU: upload then immediate GET /race/files/<name> earns the flag, and the same file requested 2.5 seconds later returns 404 as the scanner deletes it. Honest window, verifiable.
- Scoreboard per-module sections (names, counts, Captured/Not captured rows) updated correctly for all three modules.

## Bugs found (with reproduction)
1. JSONP beacons cannot tell an executed payload from a bare token echo. All 5 challenges fall to reading the per-session token out of the feed response body and calling the beacon with curl, no JavaScript execution anywhere:
   - callback-xss: `GET /jsonp/user?callback=hello`, copy token, `GET /jsonp/beacon-xss?v=callback-xss&n=<token>` => the lab awarded the flag. This endpoint has no attempt-shape gate at all.
   - csrf-data: `GET /jsonp/data?callback=cb`, copy secret, `POST /jsonp/beacon` with `{"secret":"<secret>"}` => the lab awarded the flag. No cross-origin theft, no browser.
   - filter-bypass: `GET /jsonp/filtered?callback=x%27%2B%27y%28z%29%3B` (decodes to `x'+'y(z);`), copy token, beacon => the lab awarded the flag. The "attempt" gate only checks the callback contains a quote followed by `+` and one of `(` `)` `;`, so no filter-bypass technique is needed.
   - mimetype: `GET /jsonp/snippet?callback=%3C` (a single `<`), copy token, beacon => the lab awarded the flag. No HTML payload needed.
   - array-hijack (labeled Hard): `GET /jsonp/legacy?callback=cb`, copy the feed token from the body, `POST /jsonp/array-beacon` with `{"items":["alice:A1","feed-token:<token>"]}` => the lab awarded the flag. Two requests, no Array override. The pages claim the beacon "proves the payload really executed", but it only proves the caller read the token.
2. One upload awards two flags. `POST /upload/ext-blacklist?filename=evil.svg.HTML` with a 1-byte body returned two flag banners: upload-case (final ext `.HTML` passes the case-sensitive blacklist, lowercases to `.html`) and upload-double-ext (regex matches the earlier `.svg.`). One request captures both challenges, so neither intended technique is really isolated.
3. Every upload flag is awarded at upload time on request shape alone. All 8 fell with trivial bodies: stored-xss with a 1-byte body on `?filename=pam1.html`; upload-ctype with `Content-Type: image/jpeg` and a 1-byte non-image body on `?filename=pam4.html` (body bytes never inspected); strip-once with `?filename=evil.s.svgvg`; overwrite with `?user=bob` and body `PWNED`; polyglot with body `GIF89a<script>alert(1)</script>` (only magic bytes plus a script pattern checked, the file never rendered); traversal with `?filename=../pam8.txt`. No stored file is ever fetched or executed to earn the flag.
4. Scoreboard topbar chip on /scoreboard read `0/201` while my session already had captured flags (the per-module sections correctly showed 5/5, 8/8, 8/8). The chip does not reflect session progress.
5. One fetch transiently rendered the "Unrestricted File Upload" section as 0/8 while its per-challenge rows showed Captured; a refetch showed 8/8. Possible stale render, not reliably reproducible.

## Cheat battery summary
- Bare claim/beacon: CHEAT-WORKS on all 5 JSONP (above) and all 8 upload (flags awarded on upload POST; nothing is fetched, executed, or rendered). BLOCKED on race: sequential double-actions are all refused, and race-upload-scan needs the file fetched inside the 2-second window.
- Replays: beacon tokens are single-use and rotate after award, so replays earn nothing. Upload POSTs are replayable but the flags are idempotent per session.
- Trivial inputs: 1-byte bodies earn upload flags; a single `<` or a 6-character callback satisfies the JSONP attempt gates.
- 13 of 21 flags fall without genuine exploitation (all JSONP, all upload). All 8 race flags required the real technique.

## Friction/confusion points
- The JSONP pages insist the token echo "proves the payload really executed", but the server cannot tell. A curl-only player finishes the module without touching the browser mechanics the module is supposed to teach.
- Race lab state is shared server-wide and `/race/reset` is unauthenticated, so another visitor's reset can wipe your balance/coupon/votes mid-test. The pages mention resetting but not that it is global to the instance.
- The shared `POST /upload/ext-blacklist` route serves two challenges silently; one upload quietly captures both flags with no explanation in the UI.
- Note for lab ops: my traversal test wrote a file outside the uploads area on the shared instance (`../pam8.txt` landed one level up from the uploads folder). That file is still there and should be cleaned up by whoever maintains the pool instance.

## Hint quality
- JSONP hints are spoilery. The filter-bypass claim card prints the full payload pattern, and the array-hijack hints explicitly say replaying the beacon in Repeater works, which hands over the cheat.
- Race hints are fair and technique-focused (parallel burst, Intruder parallel mode).
- Upload hints are mixed: double-ext asks what path.extname returns, a good nudge; polyglot gives away the whole trick (magic bytes plus HTML) despite the Hard label.

## Difficulty fairness
- Array Constructor Hijack is labeled Hard but is two curl calls via token echo, the easiest of the JSONP set.
- race-upload-scan is labeled Hard but needs no racing at all, just a fast GET, making it easier than several Mediums.
- The race Mediums are fair; the 150 to 250ms window makes parallel curl reliable first try, arguably generous for Medium.
- upload-case and upload-double-ext each being worth a flag while one request takes both undervalues both.

## Burp-first feasibility
- Fully feasible, but nothing requires Burp. All 21 challenges are solvable with curl alone. Race maps cleanly to Burp Intruder parallel mode as documented. The JSONP "load in Burp's browser" steps are unnecessary since the beacons accept plain HTTP echoes, and the hints openly admit Repeater replay works.

## Suggestions (concrete)
- JSONP: either make the beacon unclaimable by a bare echo (e.g. require the nonce to be combined by executed script, or gate on headers only a page-context request sends), or drop the "proves execution" wording and frame the labs honestly as token-echo drills.
- Upload: award flags when the stored file is fetched and served as active content (like race-upload-scan does), not at upload time; split case and double-ext onto separate endpoints or make their trigger conditions mutually exclusive so one request cannot take both.
- Race: scope lab state per session or make `/race/reset` per-session; document the shared state on the module index so visitors do not clobber each other.
- Scoreboard: make the topbar score chip reflect the same per-session totals as the module sections.
- Rebalance difficulty labels: array-hijack and race-upload-scan are not Hard as implemented.

## Rating: 3/5
- The race module is excellent (5/5 on its own): real races, honest windows, sequential cheats blocked. But the JSONP and upload flag gates do not enforce the techniques they teach, so 13 of 21 flags fall to pattern matching rather than exploitation. For a CTF-speed player the whole assignment collapses to about 25 minutes of curl.
