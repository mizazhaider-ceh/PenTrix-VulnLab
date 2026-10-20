# Student Review: Day-One Kai (beginner-13)

- Modules tested: csti (all 5 challenges: basic, filter-bypass, constructor, attr, stored) and lfi (all 9 challenges: traversal, filter-bypass, absolute, double-encode, nested-deep, lang, log-poison, proc-self, config-read)
- What worked well:
  - Every challenge is genuinely exploitable end to end. I earned all 14 flags by actually doing the exploits (curl flows standing in for Burp Proxy/Repeater/Intruder).
  - The anti-cheat checks held where they exist: a bare beacon with no page load returns 400 "No flag"; replaying a consumed CSTI nonce returns 400; reading docs/secret.txt via /lfi/view with plain file=secret.txt displays the secret marker on screen but the lab does NOT award the flag (verified with a fresh session); the single-pass filters really do strip naive ../ attempts; the double-decode filter really does print "Blocked" on a plain traversal.
  - The lab pages state the goal clearly ("make the preview show 49", "read the secret file"), so I always knew what success looked like.
  - The claim-status endpoint is great feedback: a quick GET tells me unambiguously whether the lab counted my work.
  - The LFI lab pages that name both steps of a chain (log-poison page: poison the log, then read it back through the viewer) saved me from dead ends.

- Bugs found (with reproduction):
  1. CSTI beacon awards the flag with no exploit at all. Fresh session, load /csti/basic only (never save a template), copy the CSTI_NONCE value from the page source, then GET /csti/beacon?v=basic&d=49&n=<nonce>. The lab awarded the flag and the scoreboard marked "Basic Template Evaluation" captured. The nonce proves I loaded the page, not that any template evaluated. This works for every auto-beacon lab (basic, filter-bypass, attr, stored).
  2. Constructor beacon accepts ANY non-empty d. Fresh session, load /csti/constructor, copy CSTI_NONCE, GET /csti/beacon?v=constructor&d=hello&n=<nonce>. The lab awarded the flag; claim-status returned captured:true. Nothing needs to be injected, compiled, or executed.
  3. The constructor lab page prints the entire working payload in its own goal note, including the beacon URL and the nonce usage. Combined with bug 2, the lab needs zero injection skill: read the page, copy two values, done.
  4. The claim box on every CSTI page names the wrong token. It says the one-time token is rendered as window.__px (mentioned 4 to 5 times on the live pages) and tells me to search for it, but the pages actually render the token as CSTI_NONCE. A beginner who follows the numbered steps literally searches the page source for __px and finds nothing. (The stored lab's beacon info adds "not window.__px" as a correction; the basic lab does not correct it clearly.)
  5. The claim box says "a new one-time token is rendered into it on every load" and that tokens are "single-use per page load". I verified with two consecutive GETs of /csti/basic that the token is IDENTICAL across reloads until the beacon consumes it. After a failed attempt, the same token still works, so "reload for a fresh one after each attempt" is misleading.
  6. The LFI error page discloses the server's absolute filesystem path. Reproduction: GET /lfi/download?file=../docs/secret.txt (stripped by the filter), and the error line shows the full path of the attempted file including the deployment directory layout. As a student this actually helped me work out depth, but it is info disclosure in an error message.
  7. Transient failures can silently consume the CSTI nonce. During testing, one beacon request timed out on the network; the nonce had been consumed server-side anyway, so my retry returned 400 and I had to reload the page for a fresh token while the flag was actually already captured. A student in this situation sees an error and believes they failed.

- Friction/confusion points:
  - CSTI labs cannot be finished with curl or Burp Repeater alone: the template evaluates in page JavaScript and the beacon is a fetch() from that same script. Nothing on the module page says plainly "you need a real browser (or Burp's embedded browser) to finish these labs". As a beginner I burned time trying to make the beacon fire from curl before realizing the browser does it.
  - The log-poison page re-displays my previously captured traversal flag at the top (via the "captured" display) right next to the newly awarded log-poison flag. I first thought I had earned the traversal flag twice. The page does not visually distinguish "already captured earlier" from "just awarded now".
  - The stored lab's hint 3 ("copy the session cookie and the CSTI_NONCE token... then forge the beacon GET") teaches exactly the shortcut described in bug 1. The hints legitimize the cheat path for all CSTI labs.
  - The constructor challenge card says tools "BZ, B, DT" and difficulty Medium, but the page note hands over the full payload, so the difficulty label is meaningless in practice.
  - The /proc/self/environ output is raw NUL-separated binary rendered straight into the page. A beginner grepping or copying it needs to know to treat it as text (curl/grep refused it as binary until I forced text mode). Also, the dump shows a lot of process internals on screen, which was unexpected.
  - During testing the pool instance went down for several minutes (connection refused on all requests). When it came back, my whole session was wiped: nonces gone, saved templates gone, and previously captured flags no longer shown as captured. I had to redo the constructor honest path and re-verify several LFI labs. A student working across days would lose their scoreboard progress on every instance restart.

- Hint quality (helpful? spoilery? useless?):
  - lfi/traversal: helpful. Rung 2 ("start with one ../ and add more depth") is what unlocked it.
  - lfi/filter-bypass: helpful. Rung 1 ("what happens to ....// after one removal?") unlocked it directly.
  - lfi/absolute: helpful. The hint names the goal precisely (system user list by full absolute path).
  - lfi/double-encode: helpful. The main hint explains the double decode; rung 3's Burp Decoder tip is practical.
  - lfi/nested-deep: helpful, but rungs 2 and 3 say nearly the same thing (redundant).
  - lfi/lang: helpful. Rung 1 ("Is it validated?") got me to test the parameter.
  - lfi/log-poison: helpful. The lab page itself plus the hints form a clean two-step ladder.
  - lfi/proc-self: spoilery. Rung 1 ("What does /proc/self/environ contain?") just names the file, and rungs 2-3 repeat it. No thinking left to do.
  - lfi/config-read: helpful and short.
  - csti/basic: helpful. The goal line ("The engine evaluates {{ expression }} as JavaScript") plus rung 1 got me there.
  - csti/filter-bypass: helpful. The goal ("the client engine knows more than one syntax") plus rung 1 (check the rejection, then look at how the engine parses) unlocked it.
  - csti/constructor: spoilery. The lab page note prints the complete working payload; the hints then re-explain pieces of it. Copy-paste, not problem solving.
  - csti/attr: helpful. Rung 3 (reload the page, watch for the beacon) is the unlock.
  - csti/stored: helpful. Rung 1 ("Two requests, not one") taught me the stored concept as a beginner.

- Difficulty fairness:
  - LFI progression is fair: traversal (Easy) is truly easy, the filter-bypass variants are a satisfying step up, and log-poison (Hard) is a fair two-step chain. Double-encode (Medium) is the hardest fair one; the "Blocked" feedback makes iteration fast.
  - CSTI: basic/filter-bypass/attr/stored are fairly labeled and solvable from hints. Constructor is labeled Medium but, because the full payload is printed on the page, it is the easiest lab in the module in practice. Without that printed payload it would be a fair Medium/Hard.

- Burp-first feasibility:
  - All 9 LFI challenges: fully doable in Burp Community. Proxy to capture, Repeater to iterate payloads (file/page/lang/f parameters, User-Agent for log poisoning). Intruder is optional for depth fuzzing but never required.
  - All 5 CSTI challenges: NOT doable in Repeater alone. Saving templates via Repeater works, but the evaluation and the auto-beacon happen in page JavaScript, so a real browser (or Burp's embedded browser) must render the page. The stored lab's hint 3 documents a Repeater-only nonce-forging path, but that is the cheat from bug 1, not the intended exploit. A beginner should be told up front that CSTI needs the browser.

- Suggestions (concrete):
  1. Make the CSTI beacon prove evaluation, not just page load: require the beacon data to be a value only derivable from evaluating the saved template, or bind the nonce to the saved template so a template-less beacon cannot award. At minimum, stop printing the full constructor payload on the lab page; hint at the pattern (constructor reaches Function) instead of the finished code.
  2. Fix the claim box copy on CSTI pages: name the real token (CSTI_NONCE), and describe its real lifetime (same across reloads until the beacon consumes it; reload after consuming).
  3. Rewrite or remove the stored lab's hint 3: it currently documents the forge-the-beacon shortcut that bypasses every CSTI lab's intended exploit.
  4. On challenge pages, visually distinguish "flag already captured earlier" from "flag just awarded" so students do not think they earned a duplicate (seen on the log-poison page).
  5. Suppress absolute filesystem paths in LFI error messages (the ENOENT line leaks the deployment directory layout).
  6. Dedupe near-identical hint rungs (nested-deep rungs 2/3, proc-self rungs 2/3) and de-spoiler proc-self rung 1.
  7. Add one line to each CSTI briefing: "Finish this lab in a real browser (or Burp's embedded browser); curl/Repeater alone cannot run the page script that fires the beacon."

- Rating: 4

- Test notes: the pool instance went down mid-test and my session state was wiped on reboot (per the infra notice). Re-verified after the reboot: the constructor honest-path flag, plus traversal, double-encode, and the full log-poison chain, all awarded their flags again on the live instance. The remaining LFI flags were confirmed working before the reboot and their mechanics are unchanged. Cheat findings (bugs 1-3) were verified before the reboot and rest on server code, not session state.
