# Student Review: Day-One Tom (beginner-10)

## Test conditions
- Instance: http://127.0.0.1:18410/ (shared pool), unique jar /tmp/cookies-beginner-10.txt, curl only, no live browser, sleeps between bursts.
- The VM rebooted twice during testing (~01:37 UTC and ~02:47 UTC); per-boot state was reset both times. I re-ran ALL exploits after the second reboot and re-confirmed the scoreboard: 17/17 for my two modules, total 17/201 on the live instance. Results below describe post-reboot verification unless noted.
- Repo reference used read-only for routes, hints, and briefings (~/workspace/pentrix-vulnlab/modules/xss, modules/crypto). Flag values are never written here; the lab awarded each flag or it did not.

- Modules tested: XSS (9 challenges), Cryptographic Failures (8 challenges). Result: 9/9 XSS, 8/8 crypto, all captured and confirmed on /scoreboard.

- What worked well:
  - Every beacon challenge has a claim box with the payload pattern and a live claim-status widget. I always knew exactly what the server expected: non-empty data, valid vuln id, fresh page token as n.
  - The "Why beacons fail" details element explained token-less beacons, expired tokens, and the single-use nonce rule. That saved me from a long dead end.
  - The verification model is honest: bare beacon with no page load got 400, replaying a consumed nonce got 400, wrong token got 400. No free flags.
  - Crypto hints are the best teaching in the lab: H1 gives the concept, H2 the operation, H3 almost the recipe. The ECB byte-at-a-time attack genuinely worked from hints alone.
  - /scoreboard displayed both modules correctly after the reboot: XSS 9/9 (100%), crypto 8/8 (100%), correct challenge names and difficulties, "Captured" status on every row, header total 17/201 matching the topbar chip.

- Bugs found (with reproduction):
  1. Crypto module index shows no "Flag captured" pill, XSS module index does (inconsistent captured-state display). Repro: capture any crypto flag (e.g. crack the MD5 login), reload /crypto, the challenge cards show no captured state at all (the word "captured" appears zero times in the page source). On /xss the same session shows 9 "Flag captured" pills. A student finishing crypto gets no on-page confirmation, only the scoreboard knows. Fix: add the same done-pill to crypto index cards that the XSS index has.
  2. Not a lab bug, but worth flagging: during testing the instance went down twice (VM reboots) and /tmp was wiped both times, deleting my scratch files but not the cookie jar. The lab itself recovered and per-boot secrets rotated cleanly, which is actually good behavior.

- Friction/confusion points:
  - XSS claim boxes hand you the complete payload verbatim. As a beginner I never needed hints H1/H2 on any of the 8 beacon challenges; I copied the pattern, shaped it, fired the beacon. It felt like a recipe, not a discovery. (The clobber challenge was the exception: no payload pattern, and there H1/H2 actually did the teaching. That one felt earned.)
  - On the attribute breakout page, the n parameter reflects TWICE: once escaped in the form input and once raw in the preview input. My first look at the response showed the escaped one and I briefly concluded the challenge was patched. A one-line note on the page about the two reflection points would help.
  - Stored XSS: submitting with curl and following the redirect produced a confusing 400 in my client on one attempt; a plain browser POST/redirect works fine. Minor.
  - SVG challenge: the file link carries the token in ?n= because the SVG is its own document. The claim box explains this, but as a day-one student I had to read it twice before the token flow clicked.
  - Hash length extension: hints H2/H3 openly say Burp Decoder cannot do the glue padding and that I need "a tiny script". For a Hard challenge that is fair, but writing a pure-Python SHA-256 with state injection is a big jump for a beginner. A pointer to the exact primitives (0x80 padding, 64-bit big-endian bit length, restore digest as compression state) would have helped; I worked it out, but it was the hardest hour of the whole test.
  - PIN brute force: the challenge says "script it" and the intended tool is Burp Intruder. Via curl-style requests I measured roughly 200 requests/sec on localhost even with 48 parallel threads, so the full million-guess space is on the order of tens of minutes to an hour. The page says nothing about expected wall time. A beginner will stare at a running attack for a long time with no idea if it is working.
  - Shared-pool hazard (worth a warning on the page): the reset PIN is global to the instance, not per session. If another student clicks "Generate reset PIN" while my brute force is running, my search targets a dead PIN and can never hit. My run found the PIN after about 35 minutes, but a mid-run regenerate would have silently wasted it.

- Hint quality (helpful? spoilery? useless?):
  - XSS hints H1/H2: well written but effectively redundant, because the claim box payload pattern is more specific than H3. Rating: helpful for learning, spoilery by design. The rung that unlocked each challenge was the claim box payload, not the hint ladder.
  - Clobber hints: H1 (what survives the filter, named elements become window properties) and H2 (rebuild truthy window.settings.isAdmin) were the real unlock. Rating: helpful, not spoilery.
  - Crypto b64/MD5/key-in-js hints: accurate and quick. Helpful.
  - Crypto XOR crib: H3 (try key lengths 1-12 with the known header) was the unlock. Helpful.
  - Crypto CBC: H3 (flip IV bytes with guest xor admin, re-encode, POST to /crypto/cbc/check) was the unlock. Helpful, borderline spoilery, but the concept is the lesson.
  - Crypto ECB: H1-H3 taught me the attack I did not know (block equality as oracle, align unknown byte at block end, 256 probes). Helpful, the best hint ladder in the module.
  - Crypto hash-ext: H1-H3 honest about needing a script. Helpful.
  - Crypto PIN: H3 (null payload 000000-999999, watch for a 200 among 401s) is exactly right. Helpful.

- Difficulty fairness:
  - XSS: Easy challenges are genuinely easy (with the claim box, arguably trivial); Medium ones are fair; clobber (Hard) is a fair hard. As a first-timer I never felt lost.
  - Crypto: Easy challenges are easy, XOR (Medium) is fair. The Hard trio (ECB, CBC, hash-ext) are genuinely hard for a beginner even with hints, but all are solvable and the hints carry you. Fair as Hard.
  - PIN is labeled Easy: the concept is easy, but the effort is a 35+ minute brute force with no progress indicator. By effort it feels like Medium. Either relabel it or state the expected wall time on the page.

- Burp-first feasibility:
  - XSS: all 9 doable with Burp Community. Reflected, stored, attr-breakout, js-context, backtick are pure Repeater work; dom needs pasting the fragment URL into the proxied browser address bar; svg needs opening the served file link in the browser; markdown needs clicking the rendered link; clobber needs opening the admin panel in the browser. The beacon itself fires through the Proxy and shows up in HTTP history, which is a nice teaching moment.
  - Crypto: b64 (Decoder + Repeater), MD5 (wordlist hashing is faster offline, login through Proxy), key-in-js (read app.js, decrypt offline, Repeater POST), XOR crib (offline Python, Repeater POST), CBC bit-flip (Decoder XOR/Encode transforms or offline, Repeater POST), ECB oracle (Repeater for single bytes; the full loop wants Intruder or a script), hash-ext (needs an external script; the hints say so themselves), PIN (Intruder with a null payload over 000000-999999, exactly as the hints describe). Community edition is enough for all of it.

- Suggestions (concrete):
  1. Add the "Flag captured" pill to crypto module index cards, matching the XSS index (bug 1 above).
  2. On the PIN page, add one line: expected brute-force wall time at typical Intruder speed, plus a warning that the reset PIN is shared per instance, so regenerating mid-attack restarts everyone's search.
  3. On the attribute breakout page, note that n reflects in two places (escaped form input, raw preview input) so beginners check the right one.
  4. Consider gating the full XSS payload pattern behind a "reveal" click so students who want to discover can try H1/H2 first; keep the current default for those who want the recipe.
  5. For hash-ext, add the two concrete primitives to H2 (0x80 then zeros to 56 mod 64, then the 64-bit big-endian total bit length) so a beginner can build the glue padding without guessing the format.

- Rating: 4.5/5
  - Everything I tested worked, hints taught real technique, cheats were rejected, and the scoreboard was accurate. Deductions: the crypto index missing captured pills, the PIN page giving no time expectation, and XSS claim boxes giving away the payload so the hint ladder rarely matters.
