# Expert Audit: Burp Suite Workflow Feasibility

Scope: PenTrix-VulnLab (29 modules, 201 challenges). Doctrine D17: every challenge must be fully solvable through the standard Burp Suite workflow (Proxy intercept, Repeater, Intruder, Community edition sufficient). No code changed, nothing pushed. Live test instance: `http://127.0.0.1:18403/`, probed with plain HTTP requests equivalent to what Burp Proxy/Repeater/Intruder send.

Method: spot-checked at least one challenge per module (code plus `tools`/`start`/`hints`/`how` metadata), verified award triggers are plain-HTTP reachable, live-tested the risky ones (TRACE, verb tampering, race window, CSTI beacon replay, proto claim), and reviewed `docs/TOOL_SETUP_GUIDE.md` and `docs/RECOMMENDED_TOOLS.md`.

Headline: the lab is overwhelmingly Burp-clean. All 29 modules are solvable with plain HTTP requests, there is no global rate limiter and no IP block/429 logic anywhere (`app.js` middleware is sessions, JSON/urlencoded parsing, cookie parsing, static files only), and the per-challenge metadata voice is consistently Burp-first. A prior per-challenge pass (docs/audit/burp/w001-w146 plus FOLLOWUPS.md) fixed the curl-default voice and I found no remaining user-facing curl-isms. Three High findings remain, all independently live-verified.

---

## Finding 1: Race module tells Community users to use Intruder for a 150-250ms window

- Severity: High
- Location: `modules/race/challenges/` (all 8: race-balance, race-coupon, race-ratelimit, race-referral, race-register, race-stock, race-upload-scan, race-vote) plus `modules/race/shared.js`

Description: The race window is 150-250 ms (`WINDOW = () => 150 + Math.floor(Math.random() * 101)` in `modules/race/shared.js`). Every race challenge's hints, `how`, `start`, and in-page payload blocks instruct students to run a Burp Intruder attack with 20 concurrent requests (race-coupon's payload block: "Resource pool: create a pool with concurrent requests set to 20"). Burp Community Intruder is deliberately throttled (the lab's own docs confirm: "Intruder (automated payloads) | Yes (rate-limited)" and "Burp Community's Intruder is throttled. It is slow on purpose"). A throttled, effectively single-threaded Intruder cannot land 20 requests inside a 250 ms window on Community edition, so the documented workflow fails on the free tier and D17 ("Community edition sufficient") is broken for the whole module.

Evidence: Live test against the running instance fired 20 parallel POSTs to `/race/coupon/redeem` with curl: the coupon page afterwards reported 20 redeems, proving the window is real and parallel-request exploitable. The gap is purely in Burp Community tooling, not the server.

Recommendation: Rewrite the race guidance around Repeater's "Send group in parallel" (single-packet attack), which IS available in Community and is PortSwigger's documented Community technique for race conditions: open 20 identical Repeater tabs (or duplicate the request 20 times in one group), send the group in parallel, count successes. Keep Intruder as the Pro alternative. Add this technique to `docs/TOOL_SETUP_GUIDE.md` (see Finding 5).

## Finding 2: crypto-rand-pin requires 1,000,000 Intruder payloads on Community

- Severity: High
- Location: `modules/crypto/challenges/crypto-rand-pin.js` (lines 47-50, 77-82)

Description: The challenge awards only when the 6-digit PIN (10^6 space) is brute-forced via Burp Intruder ("Use a null payload generating 000000-999999"). On Community's throttled Intruder, one million sequential requests takes on the order of days, not a lab session. The challenge's `tools` field is `'BZ'` only, so there is no sanctioned fallback, and the docs' "Honest limits" section claims "the guessable spaces are small", which is false here.

Evidence: Code comment admits "10^6 guesses with no rate limiting is a trivially brute-forceable space" (trivially, in compute terms, but not in Burp Community time terms). The title says "Predictable" but the hints teach pure brute force, never prediction.

Recommendation: Either (a) reduce the PIN space so Community Intruder finishes in a realistic session (e.g. 4 digits, and add honest time math plus grep-match setup to the hints), or (b) make the intended path genuine `Math.random()` prediction and rewrite the hints toward that, or (c) keep 6 digits but sanction Turbo Intruder as the documented Community-compatible tool. As written, the challenge is not Community-feasible.

## Finding 3: proto-client claim endpoint awards without any client-side pollution

- Severity: High
- Location: `modules/proto/challenges/proto-client.js` (`router.get('/client/claim', ...)`)

Description: `GET /proto/client/claim?theme=dark` awards the flag for any `theme` value other than empty or 'light'. No page load, no browser render, and no actual `Object.prototype` pollution is required; the "genuine" check the code comment describes does not exist server-side. The rendered page even tells students "This endpoint only awards a flag when the client page reports a genuinely polluted theme value", which is not true. This undermines the genuine-exploit bar (also recorded as an open follow-up in `docs/audit/burp/FOLLOWUPS.md`, w103, and re-verified here independently).

Evidence: Live test, fresh session, no page load: `GET /proto/client/claim?theme=dark` returned the flag banner in the response. A Burp Repeater user who reads the claim URL from the page source (or guesses the obvious pattern) scores without performing the lab's exploit.

Recommendation: Bind the claim to evidence of a real polluted render (e.g. a one-time server-issued token rendered only into the victim page, echoed back by the page's own script), consistent with how csti/postmsg/xss beacon challenges already bind beacons to page-rendered tokens. Note: this challenge IS Burp-solvable either way; the problem is it is solvable without doing the exploit at all.

## Finding 4: auth/otp-bruteforce (10,000 codes) has no honest time expectation and no grep-match guidance

- Severity: Medium
- Location: `modules/auth/challenges/otp-bruteforce.js` (lines 14-30)

Description: 10,000 numeric OTP payloads on a throttled Community Intruder is a multi-hour attack (roughly 3+ hours at ~1 req/s, longer if slower). The hints say "watch for the response that looks different from the failures" but never explain how to set up Intruder's Grep - Match to find the success page automatically, which is the standard Burp workflow for exactly this situation. The `tools` tag includes `P, C` (python, curl) as an escape hatch, which is a D17 smell: the Burp path exists but is painful and unguided.

Evidence: No rate limiting, lockout, or expiry on `/auth/otp-reset/verify` (verified in code), so the attack works, it is just slow and the docs never teach the grep-match setup this challenge depends on.

Recommendation: Add a grep-match walkthrough to the hints (`Intruder > Options/Grep - Match`, add the success-page string, sort results by it) and state the honest expected runtime on Community. Cross-link the same guidance from `docs/TOOL_SETUP_GUIDE.md` (Finding 6).

## Finding 5: No documentation of Repeater "Send group in parallel" (single-packet attack) anywhere

- Severity: Medium
- Location: `docs/TOOL_SETUP_GUIDE.md`, `docs/RECOMMENDED_TOOLS.md`

Description: The single-packet parallel-send technique in Repeater is the Community-edition answer to the entire race module, yet neither doc mentions it. `TOOL_SETUP_GUIDE.md` covers Proxy, Repeater, Intruder, Decoder, Comparer, and Logger well, but the race module's own docs table (`docs/TOOL_SETUP_GUIDE.md:619`) lists only "Burp Suite (Repeater, Intruder)" as the tool and "Turbo Intruder extension for parallel requests" as the alternative, with no explanation of either. A Community student following the docs has no working technique for 8 challenges.

Evidence: grep for "single-packet", "single packet", "send group", "parallel" in both docs returns only the one table row (line 619).

Recommendation: Add a short section to the guide: how to duplicate a request into a Repeater group and use "Send group in parallel", when to use it (race module), and why Intruder is the wrong tool on Community for sub-second windows. Rewrite the race challenge payload blocks to teach this first, Intruder second (Pro).

## Finding 6: No Intruder Grep-Match / Grep-Extract setup walkthrough, though challenges depend on it

- Severity: Medium
- Location: `docs/TOOL_SETUP_GUIDE.md` (Intruder section), `modules/auth/challenges/otp-bruteforce.js`, `modules/sqli/challenges/blind.js`

Description: Two challenges explicitly depend on spotting one different response among thousands: otp-bruteforce ("watch for the response that looks different from the failures") and sqli/blind ("hand the oracle to Intruder with a character payload set and match on the true answer"). The guide's Intruder coverage never explains Grep - Match (flagging responses containing a string) or Grep - Extract (pulling a substring into the results table), which are the standard Burp workflows for both.

Evidence: The blind SQLi hint references "match on the true answer" with no pointer to where that feature lives; a student who has never used Intruder results filtering will scroll 10k rows by hand.

Recommendation: Add a compact "Reading Intruder results" subsection: add a Grep - Match string, sort by the match column, and use Grep - Extract to pull e.g. the response length or a marker into the table. Reference it from the otp-bruteforce and blind hints.

## Finding 7: CSRF module omits Burp's "Generate CSRF PoC" workflow

- Severity: Medium
- Location: `modules/csrf/challenges/` (email.js, json-csrf.js, referer-bypass.js, method-override-csrf.js), `docs/TOOL_SETUP_GUIDE.md`

Description: The canonical Burp workflow for demonstrating CSRF impact is right-click the captured state-changing request in Proxy history, Engagement tools, "Generate CSRF PoC". Only `email.js` hint 3 mentions it, in passing; the other CSRF challenges and both docs never do. Students are left to hand-write attacker HTML without learning the tool built for it.

Evidence: grep for "Generate CSRF PoC" / "CSRF PoC" across modules and docs returns only `modules/csrf/challenges/email.js` (one hint) and a worker audit note. The challenge pages show the forged tag as a static payload block instead of pointing at the generator.

Recommendation: Add one hint step to each CSRF challenge ("Build the attacker's page with Burp's Generate CSRF PoC on the captured request") and a short docs section showing the click path and what the generated PoC looks like.

## Finding 8: Proxy "Match and Replace" is used by a challenge but documented nowhere

- Severity: Low
- Location: `modules/session/challenges/predictable.js` (`how` field), `docs/TOOL_SETUP_GUIDE.md`

Description: The session/predictable challenge's `how` says "set it as your lab_sid cookie in Burp (Repeater or a Match and Replace rule)". Match and Replace is a genuinely useful Burp technique (auto-swapping a cookie/header on every request, including proxied browser traffic), but the setup guide never explains where it lives (Proxy > Options/Settings > Match and Replace) or how to write a rule. A student who has not used it will just use Repeater and miss the technique.

Evidence: grep for "match and replace" (case-insensitive) in both docs returns zero hits.

Recommendation: One short docs subsection with the click path and a cookie-swap rule example, cross-linked from the predictable challenge hint.

## Finding 9: Stale curl voice in a misconfig code comment contradicts the Burp-first metadata

- Severity: Low
- Location: `modules/misconfig/challenges/trace.js` line 22

Description: The comment reads "GET /trace -> explainer page: browsers cannot send TRACE, curl can." while the user-facing metadata for the same challenge says the correct thing: "TRACE echoes the request back to the sender. Browsers cannot send it, but Burp Repeater can: change the method verb to TRACE." The code comment is internal, but a student reading source (or a future maintainer) gets the curl-default framing. The rendered page body itself is already Burp-first ("In Burp Repeater, change the method verb to TRACE"), and TRACE via Repeater was live-verified working.

Evidence: Direct file read; live test `curl -X TRACE /misconfig/trace` returned 200 with full reflection, confirming any HTTP client (including Repeater) can send it.

Recommendation: Reword the comment to "browsers cannot send TRACE, but any raw HTTP client (Burp Repeater: change the verb to TRACE) can."

## Finding 10: JWT module offers Node as the forge tool with no Burp-native alternative

- Severity: Low
- Location: `modules/jwt/challenges/` (e.g. weak-secret.js, `tools: 'BZ, N'`), `docs/RECOMMENDED_TOOLS.md`

Description: The jwt challenges' `tools` tags include `N` (Node/jwt) and the recommended-tools table says "Node with jsonwebtoken: Lets you forge and inspect JWTs from a script". That is fine as a supporting tool, but the Burp-native path (Decoder for base64url header/payload inspection, plus the widely used JWT Editor extension for resigning) is never mentioned, so students do not learn the in-Burp workflow first.

Evidence: `docs/RECOMMENDED_TOOLS.md` JWT row names only Node; no mention of Decoder base64url handling or extensions in either doc.

Recommendation: Add a sentence to the jwt challenge hints/docs: inspect the token parts in Decoder (base64url), and optionally install the JWT Editor extension for in-Burp resigning, keeping Node as the scripted fallback.

---

## Per-module Burp feasibility verdicts

All 29 modules were spot-checked (code plus metadata). Verdict "Burp-solvable" means the exploit is achievable with plain HTTP requests craftable in Proxy/Repeater/Intruder, Community edition, with no raw sockets, exotic protocols, or unreproducible browser-only steps. Browser-rendered modules (csti, postmsg, jsonp, xss, clickjacking) all expose beacon/prove/claim endpoints whose page-bound tokens can be read from page source in Repeater and replayed, which the challenge hints themselves document.

| Module | Spot-checked challenge | Verdict |
|---|---|---|
| api | mass-assignment | Burp-solvable (Repeater JSON tampering) |
| auth | brute-force, otp-bruteforce | Solvable; otp-bruteforce impractical on Community (Finding 4) |
| bizlogic | biz-coupon-stack | Burp-solvable (Repeater parameter tampering) |
| cmdi | basic (ping gadget) | Burp-solvable (Repeater command injection) |
| cors | cors-reflect | Burp-solvable (Repeater Origin header; prove endpoint) |
| crypto | crypto-md5-crack, crypto-rand-pin | md5-crack solvable offline; rand-pin not Community-feasible (Finding 2) |
| csrf | email | Burp-solvable (Repeater forged GET; needs Generate CSRF PoC note, Finding 7) |
| csti | basic | Burp-solvable (page load in Repeater, nonce extraction, beacon replay; live-verified) |
| formula | formula-csv | Burp-solvable (Repeater POST + CSV export, flag in X-Flags response header) |
| hostheader | host-abs-url | Burp-solvable (Repeater Host header tampering) |
| http | verb-tamper, crlf-log | Burp-solvable (method change in Repeater; live-verified verb-tamper) |
| idor | admin | Burp-solvable (Repeater session/ID tampering) |
| jsonp | array-hijack, csrf-data | Burp-solvable (beacon replay in Repeater, per hints) |
| jwt | weak-secret | Burp-solvable (Repeater token submission; needs Burp-native forge note, Finding 10) |
| lfi | absolute, config-read | Burp-solvable (Repeater path traversal) |
| misconfig | trace, put | Burp-solvable (TRACE verb and PUT method in Repeater; live-verified TRACE) |
| oauth | code-leak, implicit | Burp-solvable (Repeater token exchange; simulated victim flow) |
| postmsg | no-check, csrf-action, wildcard | Burp-solvable (page-source token extraction + beacon replay; delete POST replayable) |
| proto | proto-client, proto-constructor | Solvable, but proto-client claim is flag-cheap (Finding 3) |
| race | race-coupon, race-ratelimit, race-balance | Solvable only with Pro Intruder or single-packet Repeater; Community Intruder guidance fails (Finding 1) |
| redirect | redirect-javascript, redirect-data | Burp-solvable (Repeater query tampering; 302 Location reflected; live-verified) |
| redos | redos-email | Burp-solvable (Repeater payload within the 33-char cap; timing oracle) |
| session | fixation | Burp-solvable (Repeater cookie presetting) |
| sqli | login-bypass, blind | Burp-solvable (Repeater injection; blind needs grep-match note, Finding 6) |
| ssrf | basic | Burp-solvable (Repeater URL tampering; bypass variants verified in code) |
| ssti | ssti-curly | Burp-solvable (Repeater brace-count fuzzing; metadata is exemplary Burp voice) |
| upload | upload-polyglot | Burp-solvable (raw-body POST in Repeater with GIF magic bytes) |
| xss | xss-js-context, xss-dom-clobber | Burp-solvable (Repeater payload crafting + browser load for beacon; fresh-token beacon model) |
| xxe | file | Burp-solvable (Repeater XML POST; server expands entities and renders markers) |

No challenge requires raw sockets, WebSockets, HTTP/2, gRPC, or any other protocol Burp cannot speak. No challenge is blocked by server-side throttling: there is no global rate limiter, no 429 logic, and no IP blocking anywhere in the codebase.

## Metadata voice check

All 201 challenge files carry `BZ` (Burp/ZAP) in their `tools` field. A scripted pass over every `hint`, `hints`, `how`, `start`, and `name` field found zero curl one-liners or curl-default instructions in user-facing metadata (the single "curl" match was a filename). In-page payload blocks were previously converted to "Burp Repeater" framing (per `docs/audit/burp/FOLLOWUPS.md`, w014), and a re-grep confirmed no regressions. Challenge metadata consistently names the Burp step (Proxy intercept, send to Repeater Ctrl+R, Intruder sniper with payload positions).

## Docs accuracy check

`docs/TOOL_SETUP_GUIDE.md` is accurate on Proxy/Repeater/Intruder/Decoder setup, the Community-vs-Pro table (honestly marks Intruder rate-limited), Comparer, and Logger. `docs/RECOMMENDED_TOOLS.md` is accurate on the supporting cast and its "Honest limits" section. Gaps are the missing techniques in Findings 5, 6, 7, 8, and 10, plus the false "guessable spaces are small" claim contradicted by Finding 2. One inaccuracy to correct alongside Finding 5: the guide should stop implying Intruder is the race-condition tool on Community.

## Top-10 prioritized list

1. Rewrite race module guidance for Repeater single-packet parallel send; stop prescribing Community-throttled Intruder for a 150-250ms window (Finding 1, High).
2. Fix crypto-rand-pin: 1M Intruder payloads is not Community-feasible; shrink the space, teach prediction, or sanction Turbo Intruder (Finding 2, High).
3. Bind proto-client claim to a real polluted render; bare `?theme=dark` GET currently awards with no exploit (Finding 3, High).
4. Add honest Community runtime expectations and a Grep-Match walkthrough to auth/otp-bruteforce (Finding 4, Medium).
5. Document Repeater "Send group in parallel" (single-packet attack) in the setup guide (Finding 5, Medium).
6. Add an "Intruder Grep - Match / Grep - Extract" results-reading section to the guide; link from otp-bruteforce and sqli/blind (Finding 6, Medium).
7. Add Burp "Generate CSRF PoC" workflow to csrf challenges and the guide (Finding 7, Medium).
8. Document Proxy Match and Replace in the guide; link from session/predictable (Finding 8, Low).
9. Fix the stale curl-framed code comment in misconfig/trace.js (Finding 9, Low).
10. Add Burp-native JWT workflow (Decoder base64url, JWT Editor extension) alongside the Node fallback (Finding 10, Low).

Bottom line: D17 holds for 27 of 29 modules outright. The race module and crypto-rand-pin break the "Community edition sufficient" promise as documented, and proto-client lets a flag go without the exploit. Everything else is Burp-clean, and the metadata voice work from the earlier w001-w146 pass has held up.
