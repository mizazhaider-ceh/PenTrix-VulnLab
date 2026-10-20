# Student Review: Grinder Pia (intermediate-10)

- Modules tested: lfi (9 challenges), redos (4 challenges), xxe (8 challenges). All 21 exploited with curl (Burp simulation), unique cookie jar per the rules, 1s sleeps between bursts. Every flag below was confirmed as an actual award by the lab (a PENTRIX{...} string rendered in the response), not read from any file. Final scoreboard for my session: LFI 9/9, ReDoS 4/4, XXE 8/8, all rows "Captured", total 21/201.

## What worked well

- LFI is the best-designed module of the three. Nine challenges with genuinely distinct mechanics: plain traversal, single-pass strip, absolute path, double decode, nested strip, an unchecked lang parameter, a log-poisoning chain, /proc/self/environ, and a planted config. The double-encode challenge is the standout: the filter decodes once and checks, the reader decodes twice, and the page shows the final decoded path, so Repeater teaches the bug directly.
- ReDoS pages print the exact regex, the measured milliseconds, and the 1000 ms threshold on every attempt, so tuning is fast and the win condition is unambiguous. Length caps keep the worst case in seconds.
- XXE covers eight distinct parser behaviors (importer, SSRF chain, billion laughs, external DTD, SVG, XInclude, param-entity OOB, SOAP). The in-lab OOB collector is excellent: no external listener needed, the pingback log shows exfiltrated data landing, and both OOB challenges worked end to end on the first correctly-formed attempt.
- Anti-cheat is solid in most places. LFI requires the traversal to survive in the post-filter path (plain `../docs/secret.txt` against /lfi/download: no flag was awarded; single-encoded payload against /lfi/double: "Blocked", no flag was awarded; `file=secret.txt` with no dots: file read, no flag was awarded). ReDoS benign inputs (matching username, benign search, benign URL) return fast with no flag; over-limit input returns 400 with no flag. OOB awards count only pingbacks from the current request, so pre-planting a beacon then submitting harmless XML does not award. Billion laughs requires a real entity declaration plus a reference plus the time/size threshold; a tiny entity does not award.

## Bugs found (with reproduction)

1. BARE-CLAIM HOLE, XXE (5 of 8 challenges affected). The award checks whether the expanded output contains the marker string, with no requirement that any entity was declared. Typing the marker directly into the input, with no DOCTYPE and no entity, gets the flag. Reproduced in a FRESH session (new cookie jar, nothing previously captured):
   - POST /xxe/import with body `xml=<data>XXE-SECRET-4471</data>` → the lab awarded the flag (file challenge).
   - POST /xxe/import with body `xml=<data>SSRF-INTERNAL-9921</data>` → the lab awarded the flag (ssrf challenge).
   - POST /xxe/svg, /xxe/soap, /xxe/xinclude with the marker typed into the input → the lab awarded the flag in each case.
   Impact: anyone who learns the marker string (from another student's writeup, a screenshot, a log) can claim 5 of 8 XXE flags with zero exploitation. This directly contradicts the lab's own doctrine that flags require genuine multi-step exploitation.
2. LOG-POISON CROSS-SESSION CLAIM on the shared pool. The access log is shared across sessions and the award only checks that the marker appears in the log. Session A plants a marker via a custom User-Agent on /lfi/log-demo. Session B (fresh jar, never visited /lfi/log-demo, never poisoned anything) requests /lfi/view?file=../lfi_access.log → the lab awarded the flag to session B. Correct behavior in a solo deployment; on the shared pool instance the challenge is claimable without poisoning.
3. Environment note, not a lab bug: mid-audit the shared instance went down (VM had rebooted, uptime 2 min, nothing listening on 18405). Per my rules I did not restart it. All 21 exploits and all cheat tests were already complete; only a scoreboard re-read was left, and the earlier read (9/9, 4/4, 8/8) stands.

## Friction/confusion points

- Several challenge "start" texts reference http://localhost:3000 (nested-deep, proc-self) while the lab actually runs on 127.0.0.1:18405. A student copy-pasting the host gets connection errors.
- LFI module copy is stale: the briefing says "capture both flags" and the description says "seven more labs", but the module has 9 challenges.
- POSTing to /redos/url (easy to do from a form-encoded curl or a Repeater tab left on POST) returns a bare 404 with no hint that only GET is served.
- ReDoS payloads that win block the event loop for a long time on the shared box (my winning payloads measured 16.2 s username, 17.9 s search, 22.5 s url server-side). Nothing on the page warns that a successful attempt DoSes every other student on the pool.
- ReDoS email needed blind length tuning: 24 chars of payload took 142 ms (fail), 28 chars took 1223 ms (win), cap is 33. The win window is machine-speed dependent and there is no fallback gate like billion-laughs has (5 MB size gate). On a much faster box the 33-char cap could make the threshold unreachable; on a slower box it is trivially overshot.
- Param-entity OOB fails silently: my first payload missed the inner declaration's closing `>` and the result page showed "0 pingbacks" with no diagnostic about what the parser saw (declarations parsed, entities resolved). Some parse diagnostics would cut debugging time a lot.

## Hint quality (helpful? spoilery? useless?)

- LFI hints: good three-level ladders. Level 1 nudges, level 2 teaches the technique, level 3 sketches the payload shape without handing the exact string. The double-encode hints are the best in the set.
- ReDoS hints: helpful but nearly total spoilers. The pages already print the exact regex and threshold, and level-3 hints say things like "Fill the input with the one character the pattern wants, repeated many times, then break the match". The remaining challenge is length tuning, not discovery. Acceptable for Easy/Medium, but there is no "figure it out" left.
- XXE hints: over-spoilery in four places. The module index brief prints a complete working file-read payload including the absolute path of the secret file. The /xxe/svg challenge page shows the full file:// URI with the real path in its hint box. The /xxe/dtd page shows both entity declarations with the real path. The /xxe/param page pre-fills a fully working exploit in the textarea. An intermediate student can copy-paste through file, svg, dtd, and param-oob without discovering anything. The ssrf and billion and xinclude hints are better balanced.

## Difficulty fairness

- Fair across the board, and if anything slightly generous (labeled harder than they play). Nothing required guessing; every needed fact is on the page or in the hints.
- LFI: Easy tags are honest for traversal, absolute, nested-deep, lang, config-read (one step each). filter-bypass Medium is fair (single vs global strip is a genuinely subtle distinction; the "Contents of" line showing the post-filter path teaches it). double-encode Medium is fair. proc-self Medium is fair (hint names /proc/self/environ). log-poison Hard is fair (two-step chain: header injection then traversal).
- ReDoS: username Easy is fair (textbook pattern shown on the page). email/search/url Medium are fair as technique, but the url one needed the most tuning and the win condition depends on machine speed, which is a fairness risk the billion challenge avoids with its size gate.
- XXE: file/ssrf/soap/svg/xinclude play as Easy given how much the pages hand out; their Medium/Easy labels are fine only if the hint spoilers are toned down. billion Medium is fair (classic shape is given, tuning is the work). external-dtd Medium is fair (collector does the hard infrastructure part). param-oob Hard is fair (the quoting trick is genuinely tricky, and the page explains it). ssrf Hard is fair (real XXE to SSRF to internal-endpoint chain).

## Burp-first feasibility

- Fully feasible with Burp Community (no Pro features needed). Every challenge is Proxy to Repeater work: tamper a query param (LFI), grow a string and watch Repeater's response timer (ReDoS), edit a form field (XXE). The traversal hint suggests Intruder for depth fuzzing, but manual depth stepping worked fine and Intruder is not required. No Collaborator needed thanks to the in-lab OOB collector. The billion challenge even includes Repeater-specific URL-encoding instructions. One gap: nothing tells the student that /redos/* are GET-only, so a Repeater tab accidentally left on POST gives a confusing 404.

## Suggestions (concrete)

1. Close the XXE bare-claim hole: require an entity declaration in the submitted XML before awarding file/ssrf/svg/soap/xinclude (e.g. require /<!ENTITY/i or a DOCTYPE in the input, the way the billion challenge already requires both /<!ENTITY/i and /&\w+;/).
2. Scope the log-poison award on shared instances: only count marker lines whose source IP matches the requester's IP (the log already records IP), or keep the access log per session.
3. Replace hardcoded localhost:3000 in challenge start texts with the actual host/port or a relative reference.
4. Redact the absolute secret path from the XXE hint boxes and the module index brief; use a placeholder path and let the student discover the real one (the pages already teach that absolute paths are required).
5. Fix stale LFI module copy ("both flags", "seven more labs") to describe the 9 challenges.
6. Give ReDoS a non-timing fallback gate (billion-laughs style size gate) or document that the threshold is machine-dependent; add a shared-box courtesy note asking students to use the smallest payload that crosses 1000 ms, since winners block the loop for 15+ seconds for everyone.
7. Show parser diagnostics on failed OOB attempts (declarations parsed, entities resolved, pingbacks fired) instead of a bare "0 pingbacks".
8. Return 405 with a message for POST /redos/url instead of a bare 404.

- Rating: 4
