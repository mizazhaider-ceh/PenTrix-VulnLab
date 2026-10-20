# Student Review: Day-One Sara (beginner-09)

- Modules tested: ssrf (9/9 challenges), bizlogic (5/8 challenges; workflow-skip, otp-client, email-noreauth untested, the instance went down mid-session)

## What worked well

- The 3-rung hint ladders are the best part of the lab. As a beginner, I could read Hint 1 and feel guided, not lectured. Every SSRF challenge had a rung that actually unlocked it for me.
- Every SSRF challenge worked with plain Repeater-style requests (GET with a `url` param, POST with form fields). Nothing needed fancy tooling.
- The flag banner is clear: big "Flag captured", "Saved to your scoreboard", plus a copy button. I always knew when I won.
- The technique-enforcement messages are great teaching. On the redirect challenge I tried to cheat with a direct fetch of the secret (no redirect hop) and the page told me: "Marker found, but no redirect was followed, so the redirect technique was not demonstrated." No flag awarded. Same with plain 127.0.0.1 on the bypass challenge: a clean 403 "Blocked: URL contains a forbidden host." You cannot accidentally earn a flag.
- The fix panels after each flag teach the real fix, which made me feel like I learned something, not just clicked.
- Replaying a solved exploit shows the flag banner again but the scoreboard does not double count (the award is idempotent per session). Replay does not let you skip the exploit; you must still perform the fetch that returns the marker.

## Bugs found (with reproduction)

1. Instance outage mid-test (blocks completion). Around 03:0x CEST, after I had earned flags in ssrf (9/9) and bizlogic price-tamper, negative-qty, coupon-stack, currency and refund, http://127.0.0.1:18409/ stopped responding (curl returned 000, three retries, waits of 8s and 30s). `ss` on the VM showed zero listening TCP ports. I did not restart or boot anything, per the rules, so biz-workflow-skip, biz-otp-client and biz-email-noreauth are NOT live-tested in this review. The one `workflow/cart` POST I fired may have landed before the abort, but I never confirmed the flag, so I claim nothing for it.
2. Stale port in "Starting point" copy. Challenge cards tell the student to "Browse to http://localhost:3000/ssrf/fetch2" / "/ssrf/userinfo" / "/ssrf/fetch3" (verified in the live /ssrf page text), but this pool instance runs on port 18409. As a beginner I would paste that address, get connection refused, and think the lab is broken. The bizlogic cards have the same localhost:3000 text in their code. Suggestion: use relative URLs or inject the real port.
3. Metadata award mismatch. The hints teach a two-step flow ("First fetch the credentials listing path, then fetch the credential name it lists to read the secret material"), but a single fetch of `http://169.254.169.254/latest/meta-data/iam/security-credentials/` already returned the marker and earned the flag. The taught second hop is unnecessary, so the challenge is easier than documented.
4. Order-dependent award on negative-qty. The flag fires only when the final session balance exceeds the $100 start balance. If a beginner spends money on earlier challenges first (e.g. buys the full-price hoodie, balance 50), then `qty=-1` only restores the balance to 100 and earns nothing, with no explanation. I hit this risk myself (my balance was $149 only because price-tamper cost me almost nothing first). Suggestion: award when the order total goes negative, or show the start balance on the receipt so the math is visible.
5. Inconsistent fetch behavior on the redirect challenge. As the initial jump URL host: 127.1, 2130706433 and 0x7f.0.0.1 are all blocked because the WHATWG URL parser normalizes them to 127.0.0.1 before the blocklist parses the hostname (by design), 0.0.0.0 passes the blocklist but the server-side fetch dies with "socket hang up" (reproduced 3 times; even direct fetch3 of internal/secret via 0.0.0.0 fails), and only `localhost` works (`/ssrf/fetch3?url=http://localhost:18409/ssrf/jump?to=/ssrf/internal/secret` earned the flag). A beginner trying the 0.0.0.0 trick from the previous challenge gets an unexplained "socket hang up". Not a blocker since localhost works, but a one-line hint that localhost is allowed here would save real confusion.

## Friction/confusion points

- userinfo challenge never names the trusted domain. The module page says "the trusted string" and "the trusted name" but never prints `pentrix.lab`. My first try used a guessed domain and failed. The 403 message ("Blocked: only pentrix.lab URLs may be fetched") eventually told me, but that feels backwards: I had to fail first to learn the key fact. The page brief could say "our partner network (*.pentrix.lab)".
- currency challenge never names JPY. The dropdown lists only USD and EUR, and the hints say "a currency where 50 units are worth almost nothing in dollars" without ever naming a currency. A day-one student does not carry "JPY = cheap" in their head; I had to guess it. Either add JPY to the dropdown or name it in Hint 2.
- file:// challenge: my first grep of the response missed the flag because the page is long; visually the "Response body" pre block with `root:` lines and the flag banner below it is fine in a browser. No real friction, just long pages. Fine.
- coupon-stack: zero friction. "50 + 40 + 30 = ?" made me laugh and I immediately got it. 120% discount, negative total, flag earned.

## Hint quality (helpful? spoilery? useless?)

- ssrf-basic: helpful. Hint 2 ("127.0.0.1 from the server's point of view") was the exact rung that unlocked it.
- ssrf-bypass: helpful, borderline spoilery in the good way. Hint 2 names "single decimal number, hex octets, leading-zero octal", which is exactly the vocabulary a beginner lacks. Hint 1's Intruder suggestion is overkill (Repeater works), but harmless.
- ssrf-hex-ip: helpful. "127 is 0x7f in hex" taught me something real.
- ssrf-octal-ip: helpful. "127 written in octal is 0177" unlocked it in one try.
- ssrf-zero-ip: helpful. Hint 2 unlocked it.
- ssrf-file: helpful. Hint 2 ("Unix user database") gave the target class, Hint 3 gave the file. Good ladder.
- ssrf-userinfo: helpful once I knew the domain. Hint 3 explaining what @ means in a URL genuinely taught me URL userinfo semantics.
- ssrf-redirect: helpful technique-wise, but the "starting point" still says localhost:3000 (bug 2), and no hint mentions that localhost passes the blocklist while 0.0.0.0 fetch dies (bug 5). I lost time on dead-end host spellings.
- ssrf-metadata: helpful ladder, but spoiled by bug 3 (Hint 3's second hop is unnecessary).
- biz-price-tamper: helpful. The page itself says "View the page source".
- biz-negative-qty: helpful ladder (Hints 2 and 3 unlock it), marred by bug 4 (threshold confusion).
- biz-coupon-stack: helpful and fun. Rung 1 alone nearly solves it.
- biz-currency: weakest of the set. Hint 2 describes the idea but never names a currency, and the dropdown hides the answer. As a beginner this rung felt useless; I solved it by guessing JPY, not by learning.
- biz-refund: helpful. Finding order_id in the form was fine.
- biz-workflow-skip, biz-otp-client, biz-email-noreauth: not live-tested (server outage). The hint text reads fine but I cannot rate it honestly.

## Difficulty fairness

- ssrf module: fair across the board. Basic is a true Medium for a day one (the loopback concept is new), the bypass family teaches one clean idea each, and the anti-cheat rules (no plain 127.0.0.1, redirect must actually redirect) feel strict but honest.
- bizlogic module: fair except two spots. Negative-qty punishes doing challenges in a different order (bug 4), and currency requires knowledge (JPY) the lab never provides (friction above). Coupon-stack, price-tamper and refund are perfectly pitched for day one.
- No challenge required knowledge beyond basic HTTP/HTML plus what the hints teach, except the JPY guess. That is the single unfair moment in the whole review.

## Burp-first feasibility

- All 9 SSRF challenges: doable in Burp Community Repeater. They are all GET requests with a `url` parameter; I simulated each with curl, which is a weaker tool than Repeater. Intruder is mentioned in the bypass hints but never needed.
- All tested bizlogic challenges: doable in Burp Community Repeater. Plain POST form fields (price, qty, codes, currency, order_id, amount). The coupon-stack codes parameter is a single text field, easy to fuzz in Repeater by hand.
- Untested challenges (otp-client, email-noreauth, workflow-skip) look like plain Repeater POSTs from their routes and hint text, but I did not run them live, so this is an expectation, not a finding.

## Suggestions (concrete)

1. Replace every hardcoded `http://localhost:3000` in starting-point copy with relative paths (e.g. "open /ssrf/fetch2 in your proxied browser") or inject the actual lab port.
2. Add JPY to the currency dropdown (or at least name JPY in currency Hint 2) so the challenge is solvable from the page, not from trivia.
3. Name the trusted domain (`pentrix.lab`) in the userinfo page brief or in the "partner URL" example, instead of only revealing it in the 403 message.
4. Either require the metadata second hop for the flag (award only when the role document is fetched) or update the metadata hints to say the listing already contains the secret material.
5. Change the negative-qty award condition to "order total went negative" (or display the start balance on the receipt) so it cannot silently fail depending on earlier spending.
6. Have the platform team investigate the pool instance dying mid-session (no listening ports on the VM after the outage); at minimum, surface a status page so testers know it is an outage and not their exploit.

## Rating: 1-5

3. The hint ladders, flag UX and anti-cheat enforcement are genuinely good for a first-timer, and I solved 14 challenges with real learning. But a day-one student would hit three avoidable walls: localhost:3000 in the instructions, the JPY guess, and (in my session) the server dying before the last three bizlogic challenges. Fix those and this is a 4 or 5.
