# Student Review: Day-One Dev (beginner-02)

- Modules tested:
  - Command Injection (cmdi): all 9 challenges, 9 flags awarded. Basic (`;id`), v2 (`;;id`, filter strips only the first semicolon), v3 (`;cat${IFS}/etc/passwd`), v4 (braced `${IFS}`), v5 (`%0a` newline), v6 (backtick substitution), v7 (`;/???/bin/?at /???/p?sswd` glob), v8 (`|id` pipe), v9 (`%09` tab).
  - HTTP Layer Flaws (http): all 3 challenges, flags awarded. Verb Tampering (replay over GET), CRLF Log Injection (forge a line, confirm in the viewer), Cache Deception (poison as alice, steal from a fresh cookie-less session, flag arrived in the X-Flag response header).
  - Every exploit was done with curl standing in for Burp Repeater (edit-and-resend), one fresh cookie jar per "browser session" (/tmp/cookies-beginner-02.txt, plus /tmp/cookies-attacker-02.txt for the cache attacker), with 1s sleeps between bursts.

- What worked well:
  - The "Sanitized value sent to the shell" box on the ping gadgets is a fantastic teaching aid. When my naive `;id` got mangled into `127.0.0.1id`, I could SEE the filter at work instead of guessing. This single box turned black-box fuzzing into something learnable.
  - The CRLF flow is honest: the track page tells you to go open the viewer, the viewer confirms "Forged log line confirmed" with a line count, and the flag only lands when the forged line is really there. I tested opening the viewer without injecting first: no flag. Cheats correctly fail.
  - Cheats all failed cleanly: benign host (no flag), echo-marker tricks like `uid=0(root)` with no real command (no flag), POST to verb-tamper (no flag), same-user and guest cache HITs (no flag). The evidence checks are solid.
  - The cache dashboard shows live cache state, a purge button, and the capture status. The module briefing warns up front that the flag comes in an X-Flag header, which saved me a lot of staring at CSS.
  - Hint ladders render as three labeled rungs (Nudge, Technique, Explicit). Clear, opt-in, and the rung that unlocked each challenge for me is noted below.
  - Scoreboard is correct for both modules: cmdi 9/9, http 2/3 on my main session plus 1/3 on the attacker session, totals 11/201 and 1/201. Every challenge flips to a "captured" pill with the right name, difficulty pill, and per-module counts. No display bugs found.

- Bugs found (with reproduction):
  - BUG 1 (wrong hint text, cmdi v2, Ping Gadget v2 weak blacklist): Hint 2 says "Try the separator in its URL-encoded form so the raw filter never sees it." This is wrong: the filter runs on the decoded value, so `%3B` fails just like `;`. Reproduction: request `GET /cmdi/ping2?host=127.0.0.1%3Bid` (curl equivalent of the Repeater edit the hint suggests). The page's own "Sanitized value sent to the shell" box shows `127.0.0.1id`, and no flag is awarded. A beginner following the hint wastes time re-encoding separators. The part of the same hint about other separators (newline, &&, ||) works fine.
  - BUG 2 (silent no-flag after genuine command output, cmdi v3/v5): the pages and Hint 3 say "the flag is awarded only when the second command's real output shows up in the response." I did exactly that and got no flag, twice. Reproduction A: `GET /cmdi/ping3?host=127.0.0.1;id` shows `uid=0(root)` in the output, no flag. Reproduction B: `GET /cmdi/ping5?host=127.0.0.1%0Aid` shows `uid=0(root)` in the output, no flag. These challenges quietly require the technique marker ($IFS / newline) AND password-file output; the stated rule on the page does not match the behavior. As a beginner, "my command ran, where is my flag?" was the most confusing moment in the whole module.
  - BUG 3 (spoiler on the catalog page, cmdi v7 wildcard): the /cmdi/ module index card for Ping Gadget v7 prints the full working payload `host=127.0.0.1;/???/bin/?at /???/p?sswd` inside its visible "Attack" line. I read the module page before starting and the Hard challenge was effectively solved for me before I opened it. The same text also appears on the challenge page. Compare with other challenges, whose cards only describe the approach.
  - MINOR (replay re-shows the flag): re-sending a winning ping exploit re-displays the flag box. Verified the scoreboard does NOT inflate (stays 9/9), so this is cosmetic and learner-friendly, not a score cheat. Mentioning so nobody flags it as an exploit.

- Friction/confusion points:
  - The no-flag-after-real-output problem above (ping3/ping5, and by code reading also v4/v6/v9) is friction, not just a bug report: a hint or message on the page like "that ran, but this gadget needs the password file read to count" would rescue the student instead of leaving them retrying.
  - My naive `c?t` guess on v7 failed with "not found" because a bare `c?t` command word only glob-expands if a matching file exists in the working directory. Nothing on the page hints that the glob has to be a full path. I only got there because the (spoiling) card told me the full-path shape.
  - Cache Deception dead end: after priming as alice, I fetched the stylesheet again in the SAME session and got a silent HIT with no flag and no message (the response is raw CSS, there is no UI to explain "wrong session, use a fresh one"). A beginner doing everything in one browser tab will sit at 2/3 forever. Related: the Capture card says the flag is "saved to your scoreboard", but the flag lands on the attacker session's scoreboard, not the victim browser session's. That sentence misled me.
  - Cache poisoning order matters and it is easy to get wrong: I visited /http/account.css as a guest BEFORE logging in as alice, which cached the guest copy, and then alice was served the guest's stylesheet (my own mistake, but an exact replica of the attack, and nothing warned me to purge). The walkthrough does say "log in as alice, then open the stylesheet", but a warning like "if you opened the stylesheet first, purge and redo" would save beginners.
  - Slow failed attempts feel like a hang: a ping request with a mangled hostname (e.g. my naive v2 attempt) takes about 8 seconds to come back with no loading indicator. I thought the page had died the first time.
  - The module is labeled "Intermediate" with an sqli prerequisite on the catalog. As a day-one student I did all 9 without any SQL knowledge, so the prerequisite feels copy-pasted rather than real.

- Hint quality (helpful? spoilery? useless?):
  - basic: helpful. Hint 3 gave the payload shape without handing the exact payload. Unlocked at Hint 3.
  - bypass: mixed. Hint 1 helpful (watch what gets stripped). Hint 2 is misleading about URL encoding (see Bug 1) but its second half (other separators) helped. Hint 3 fine. Unlocked at Hint 2 (the separator list part).
  - cmdi-ifs: helpful, but Hint 3 never mentions the password file, which is actually required (see Bug 2). Unlocked at Hint 3.
  - cmdi-braces: helpful. Hint 2's "use Repeater's Decoder tab to check your encoding" confused me as a beginner (I did not need any decoding; the point was just to type `${IFS}`). The tab suggestion feels like filler. Unlocked at Hint 2.
  - cmdi-newline: spoilery. The page one-liner says "In a URL, %0a becomes one of them" and Hint 2 repeats it. I had the answer before reading Hint 3.
  - cmdi-backtick: helpful and fair. Hint 1 nudges, Hint 2 teaches the legacy syntax, Hint 3 gives the shape. Unlocked at Hint 2.
  - cmdi-wildcard: hints themselves helpful (Hint 2's "count the letters" was a great nudge), but the module card spoiled the payload before I needed hints (Bug 3). Unlocked at Hint 0, thanks to the card.
  - cmdi-pipe: helpful, plain, fair for Easy. Unlocked at Hint 2.
  - cmdi-tab: spoilery-ish. The page one-liner hands `%09` directly; the challenge is then mechanical. Acceptable for Easy, but the hint ladder adds nothing after that.
  - crlf-log: helpful but borderline spoilery. The track page's "Try this payload" block shows a complete working example (`/http/track?ref=homepage%0d%0a...FAKE admin login from 10.9.9.9`), so I solved it before touching the hint ladder. For a beginner this is kind, for the challenge it is a giveaway. Suggestion: put that example behind Hint 3 instead of on the page.
  - verb-tamper: helpful. Hint 3 is explicit, which is fine for an Easy challenge. Unlocked at Hint 2.
  - cache-deception: helpful and necessary. The two-session dance is the hard part; Hint 1 (compare two sessions) and Hint 3 (read the response headers) were both needed. Unlocked at Hint 3.

- Difficulty fairness:
  - basic is labeled Medium but is the simplest possible injection; it reads like an Easy that was bumped up. The rest of the labels are fair: bypass/ifs/braces/newline Medium, backtick/pipe/tab Easy, wildcard Hard (would be fair if the card did not spoil it).
  - The hidden evidence requirements (password-file-only on v3/v4/v5/v9, backtick-required on v6) make some Mediums feel harder and quirkier than advertised, because success looks like failure.
  - http: Easy (verb-tamper) and Medium (crlf, cache-deception) are fairly rated. Cache Deception's Medium is earned by the two-session setup, not the concept.

- Burp-first feasibility:
  - All 12 challenges are fully doable in Burp Community with Proxy + Repeater only. Every cmdi challenge is a GET query parameter, edited in Repeater. Verb-tamper is a method flip in Repeater. CRLF is a request-line edit in Repeater plus a browser/viewer visit. Cache Deception needs two sessions, which is a private window or a cookie-less Repeater tab, exactly as the hints suggest.
  - Intruder is never required; the hint ladders mention it as optional. The "BZ, B, C" pills expand to full tool names in the UI, which is beginner-friendly.
  - One caveat for real Burp use: the newline payload (%0a in the query) is fiddly to type by hand in a browser address bar, but Repeater handles it fine, which is what the hints teach.

- Suggestions (concrete):
  - Fix Hint 2 on Ping Gadget v2: replace "Try the separator in its URL-encoded form so the raw filter never sees it" with "Encoding will not help here: the filter sees the decoded value. Which other separators does the shell offer?"
  - On ping gadgets v3/v4/v5/v6/v9, make the real award rule visible: extend Hint 3 (or add a line under the output) to say what evidence counts, e.g. "this gadget only counts it if you read the password file" / "your input must contain a backtick". Never leave a student staring at real command output with no flag and no explanation.
  - Remove the literal payload from the v7 module-index card text; keep the approach description and move the payload shape to Hint 3.
  - Cache Deception: add a "capture" card line saying the flag is awarded to the fresh (attacker) session's scoreboard, not the victim browser session's, and a warning that opening the stylesheet before logging in caches the guest copy (purge and redo).
  - Consider re-rating Ping Gadget (no filtering) to Easy; it is the intended first injection.
  - Move the CRLF "Try this payload" block behind Hint 3 so it is opt-in rather than on the page.
  - Add a tiny loading state to the ping form: slow (~8s) failed attempts currently feel like the page froze.

- Rating: 4
