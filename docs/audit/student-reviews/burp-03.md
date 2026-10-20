# Student Review: Intruder Ivy (burp-03)
- Modules tested: ssrf (9 challenges) and bizlogic (8 challenges). All 17 were exploited end to end with Burp-style flows (curl used as the Repeater stand-in, one unique cookie jar /tmp/cookies-burp-03.txt, sleep 1 between bursts, no hammering). Final scoreboard on the live instance: 17/201. NOTE: the pool rebooted at ~01:37 UTC mid-test; per-boot state reset and my scoreboard dropped from 16/201 to 0/201. Every result below was re-run and re-verified on the post-reboot instance. The live port was 18408.
  - SSRF 1 basic: Proxy /ssrf, send GET /ssrf/fetch to Repeater, set url to the loopback internal secret URL, Send. The lab awarded the flag.
  - SSRF 2 bypass: same flow against /ssrf/fetch2 with the loopback spelled as the single decimal number 2130706433. Also spot-checked hex (0x7f.0.0.1) and octal (0177.0.0.1) spellings; all passed the substring blocklist. The lab awarded the flag.
  - SSRF 3 redirect: /ssrf/fetch3 with url set to the app's own /ssrf/jump address aimed at the internal secret. Key detail: the OUTER host must be localhost, an outer host of 127.0.0.1 gets a 403 (see Bugs). The lab awarded the flag.
  - SSRF 4 userinfo: /ssrf/userinfo with the trusted name in the userinfo part (before @) and the loopback target after it. The lab awarded the flag.
  - SSRF 5 hex-ip: /ssrf/hex-ip with host 0x7f.0.0.1. The lab awarded the flag.
  - SSRF 6 octal-ip: /ssrf/octal-ip with host 0177.0.0.1. The lab awarded the flag.
  - SSRF 7 zero-ip: /ssrf/zero-ip with host 0.0.0.0. The lab awarded the flag.
  - SSRF 8 metadata: /ssrf/fetch-meta with the cloud link-local credentials listing URL. The lab awarded the flag on the FIRST fetch (see Bugs, the hinted second step is redundant).
  - SSRF 9 file: /ssrf/fetch-file with url=file:///etc/passwd. The root account line appeared in the response and the lab awarded the flag.
  - Bizlogic 1 coupon-stack: POST /bizlogic/coupon-stack with codes "SAVE50 SAVE40 SAVE30" (120 percent stacked, negative total). The lab awarded the flag.
  - Bizlogic 2 currency: POST /bizlogic/currency/pay with amount=50 currency=JPY. The lab awarded the flag.
  - Bizlogic 3 email-noreauth: POST /bizlogic/account/email new_email=attacker@evil.example, then POST /bizlogic/account/forgot email=attacker@evil.example (demo token shown on the page), then POST /bizlogic/account/reset with the token and a new password. The lab awarded the flag.
  - Bizlogic 4 negative-qty: POST /bizlogic/negative-qty with qty=-5. The lab awarded the flag.
  - Bizlogic 5 otp-client: POST /bizlogic/otp/verify with otp=000000 and otp_ok=1. The wrong OTP was accepted and the lab awarded the flag.
  - Bizlogic 6 price-tamper: POST /bizlogic/price-tamper/buy with price=0.01. The lab awarded the flag.
  - Bizlogic 7 refund: POST /bizlogic/refund/buy, read the new order id from the refund page, then POST /bizlogic/refund with order_id=N and amount=9999. The lab awarded the flag.
  - Bizlogic 8 workflow-skip: POST /bizlogic/workflow/cart with product_id=hoodie (302), then POST /bizlogic/workflow/confirm directly with no pay step. The response showed "Free order" and the lab awarded the flag. (This one was interrupted by the reboot mid-test and completed cleanly after it.)
- What worked well:
  - Every one of the 17 challenges is genuinely Burp-solvable: Proxy to capture the real request, send to Repeater, mutate one parameter, Send. Nothing required Burp Pro features (no scanner, no extensions, no Collaborator).
  - Tool pills are accurate: all 17 carry the BZ (Burp/ZAP) tag, and the extra C/B/DT tags match what the challenge actually needs.
  - Starting points name the exact page and request to proxy and send to Repeater, so a Burp learner never wonders where to begin.
  - Cheat resistance checked out: (a) a direct GET to /ssrf/internal/secret with no fetcher returns the marker text but the scoreboard did not move (stayed 17/201), so reading the marker directly earns nothing; (b) replaying an already-solved exploit re-renders the flag box but the scoreboard stayed at 17/201, no double counting; (c) routing code review found no separate flag-claim HTTP endpoint in either module, awards only fire inside the challenge handlers when the vulnerable condition holds. Beacon-style claim widgets exist only in the xss/csti/jsonp/postmsg modules, not in these two.
- Bugs found (with reproduction):
  1. Redirect challenge hints mislead about the outer host. The ssrf-redirect hint ladder says "point the url parameter at the app's own redirect endpoint; the 302 answer is your proof the redirect works", but if a student builds the outer URL with host 127.0.0.1 (the natural reading of the how line), /ssrf/fetch3 returns 403 "Blocked: URL contains a forbidden host." The blocklist only checks the parsed hostname of the INITIAL url against ['127.0.0.1'], so the outer host must be a non-blocked spelling such as localhost while the redirect target may use the blocked host (redirects are never re-checked). The working pattern (localhost outer) appears in the module index page example payload but NOT in the challenge card hints. Repro: GET /ssrf/fetch3?url=http://127.0.0.1:18408/ssrf/jump?to=http://127.0.0.1:18408/ssrf/internal/secret returns 403; the same request with outer host localhost returns the flag.
  2. Metadata hint ladder describes a redundant second step. Hints say: fetch the credentials listing, then "fetch the credential name it lists to read the secret material." The listing response itself already contains the marker and the flag is awarded on the first fetch, so hint 3 sends the student on a needless extra step. Repro: GET /ssrf/fetch-meta?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ awarded the flag immediately, verified both pre- and post-reboot.
  3. Hardcoded port 3000 in challenge start texts. The bypass, redirect, refund, and workflow-skip start texts tell the student to browse http://localhost:3000/..., but the pool instance runs on port 18408, so the printed URL lands nowhere. The SSRF module index page already builds example payloads with the live port, so the pattern exists; the challenge cards should use it too.
- Friction/confusion points:
  - The redirect 403 message ("Blocked: URL contains a forbidden host") cost me several minutes: the check is on the parsed hostname of the outer URL only, while the inner `to` target is free to use the blocked host. The message gives no hint that the outer host is the problem.
  - One redirect attempt with a double-encoded inner URL made the fetcher hang until the request timed out (~21s) with no useful error about the bad `to` value. Minor, mostly my own encoding slip.
  - basic is labeled Medium but is a trivial one-mutation win; it may mis-set expectations for what "Medium" means elsewhere.
  - email-noreauth hint says "Copy the demo token from the response page" without saying it appears inside the simulated email body on the forgot-password response. Small, but a Burp learner scanning raw HTML could miss it.
- Hint quality (helpful? spoilery? useless?):
  - Mostly helpful and well graded. The bypass ladder is the best of the set: L1 suggests Intruder with a small payload list, L2 teaches the parser-vs-string-check insight and names the spelling families, L3 gives the payload shape.
  - Bizlogic hints are crisp: each names the exact parameter to tamper (codes, currency, qty, otp_ok, price, amount), and none spoil at L1.
  - Downgrades: redirect L2 is actively misleading (Bug 1), metadata L3 is redundant (Bug 2). The currency hints are fine (JPY is the only cheap currency in the rate table and the flag needs exactly it, so "try a cheap-currency label" converges without spoiling).
- Difficulty fairness:
  - Fair overall. The Easy ones (userinfo, zero-ip, currency, negative-qty, price-tamper) are genuinely one-mutation Repeater wins. bypass as Hard is fair (needs the substring-check insight plus alternate IP spellings). file and metadata as Medium are fair. The only off label is basic (should be Easy).
- Burp-first feasibility:
  - 17/17 doable in Burp Community with Proxy plus Repeater only. The single Intruder mention (bypass) works fine under Community throttling because the payload list is tiny (3 to 5 spellings). No challenge names a wrong tool, and nothing needs ZAP-specific or Pro-only features. The guidance gaps are the redirect outer-host detail and the hardcoded :3000 URLs, not the tool choice.
- Suggestions (concrete):
  1. Add one sentence to the ssrf-redirect hints/how: the outer URL's host must itself pass the blocklist (localhost works); only the redirect target may use the blocked host, because redirects are never re-checked.
  2. Fix the metadata ladder: either note in L3 that the listing already contains the marker, or change the challenge so the second fetch is actually required for the flag.
  3. Replace the hardcoded http://localhost:3000 URLs in challenge start texts with the live port (reuse the dynamic-port pattern the SSRF index page already uses).
  4. Relabel basic SSRF from Medium to Easy.
  5. In the email-noreauth hints, say the demo token is shown in the simulated email body on the forgot-password response page.
  6. Unverified anomaly, not a confirmed bug: pre-reboot, one refund attempt (order_id=2, amount=9999) advanced the scoreboard to 16/201 while the flag box was absent from the piped response. Post-reboot the identical flow renders the flag box and moves the scoreboard correctly. Could not reproduce after the reboot; possibly a degraded pre-reboot instance artifact.
- Rating: 4
