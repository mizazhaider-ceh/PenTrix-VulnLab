# Student Review: Day-One Nina (beginner-07)

- Modules tested: proto (Prototype Pollution, 6 challenges), ssti (Server-Side Template Injection, 9 challenges)
- What worked well:
  - The module briefings are genuinely beginner friendly. The proto page explains Object.prototype inheritance in plain words before any challenge, and the SSTI page lays out the escalation path (prove evaluation with {{7*7}}, then hunt scope, then bypass filters, then RCE). As a day-one student I never felt lost about the goal of a challenge.
  - Every challenge page has a consistent layout: story briefing, an interactive form/console, a hint box, and a hint ladder. I always knew where to look next.
  - The hint ladders (Hint 1 nudge, Hint 2 technique, Hint 3 payload shape) are well written. Rung 1 almost always taught the idea without naming the answer, for example the dotblock rung ("JavaScript has a second syntax for property access that uses no dots at all") and the curly rung about the single strip pass.
  - All 15 challenges were solvable with plain curl GET/POST requests, simulating Burp Repeater. No challenge needed special tooling beyond editing a parameter and reading the response.
  - Error feedback is instructive: the unicode importer returns 400 with "Blocked: raw request text contains __proto__" vs "Send the JSON document as text/plain", so I could tell a blacklist hit apart from a wrong Content-Type.
  - Final tally: 15 of 15 challenges exploited with curl, and the lab awarded the flag for each one. Scoreboard went 0 to 15/201 on my cookie jar.
- Bugs found (with reproduction):
  1. Cross-challenge pollution leakage (proto): I exploited ONLY proto-query (`GET /proto/query?__proto__[role]=admin` with curl -g), then visited the admin checks of proto-json, proto-constructor and proto-unicode WITHOUT doing their exploits. All three passed and the lab awarded the flag for each. Scoreboard read 4/201 after one real exploit. Reproduction: fresh jar, `curl -sg -b jar "http://127.0.0.1:18407/proto/query?__proto__[role]=admin"`, then `curl -sg -b jar "http://127.0.0.1:18407/proto/json/admin"` and the other admin URLs. Root cause visible in the challenge design: every admin check reads the same process-wide property, so one pollution unlocks all four.
  2. Cross-session pollution leakage (proto): with a brand-new cookie jar (never touched any merge console), `GET /proto/query/admin` passed and awarded the flag because my earlier pollution was still live in the shared server process. Reproduction: `rm -f fresh.txt; curl -sg -c fresh.txt -b fresh.txt "http://127.0.0.1:18407/proto/query/admin"` returned the flag page and the fresh scoreboard showed 1/201. On the shared pool instance, any student's exploit unlocks these flags for every other student. The module tip ("restart the lab server for a clean slate") is not actionable for students on the shared instance.
  3. proto-client claim endpoint trusts the client: `GET /proto/client/claim?theme=dark` via plain curl, with no browser and no actual client-side pollution, returned the "Pollution demonstrated" page and the lab awarded the flag. `theme=light` correctly returns 400, but ANY other string is accepted. The page copy claims the endpoint "only awards a flag when the client page reports a genuinely polluted theme value", which is not enforced. The whole browser-based challenge is skippable in Repeater.
  4. Misleading "Keys merged this request" line (proto-constructor): requesting `?__proto__[role]=admin` shows "Keys merged this request: __proto__" even though the blacklist dropped that key before merging (the line lists parsed keys, not actually-merged keys). As a beginner I believed the merge had run and was confused when nothing changed. The line should reflect what the merge accepted, or say which keys were dropped.
- Friction/confusion points:
  - curl URL globbing breaks every bracket payload: `curl "http://127.0.0.1:18407/proto/query?__proto__[role]=admin"` fails with `curl: (3) bad range in URL position 46` unless you add `-g` (--globoff). A day-one student copying the challenge payloads into curl will hit this wall immediately, and nothing on the challenge pages warns about it. (Burp Repeater users are unaffected, which is presumably why it was never noticed.)
  - The challenge pages hand out the full payload, so the hint ladders felt decorative. proto-query has a clickable "Try it" link with the exact exploit query string, proto-json pre-fills the textarea with the exact JSON body and prints a complete Repeater block, proto-constructor links the exact bypass string, proto-dos links `?__proto__[toString]=boom`, proto-client links `?__proto__[theme]=dark`, proto-unicode pre-fills the escaped JSON document, SSTI basic has a "test {{7*7}}" quick link, and the ssti-rce hint box nearly spells the payload (`require("child_process")`, `execSync("id")`). I solved most challenges by clicking/reading the page, not by reasoning. As a beginner this felt great for confidence and terrible for learning; I cannot say I understand prototype pollution, I can say I can click links.
  - The `rce` challenge is titled "Scope Leak (Data Exposure, Not RCE)" but its id is `rce` and there is a separate `ssti-rce` challenge actually about RCE. I spent time confused about which "rce" the module briefing meant.
  - proto-dos page was slow to respond at one point (about 6.6s for the plain widget page). Not sure if load-related, but worth noting on the shared instance.
  - The unicode challenge demands `Content-Type: text/plain`, and the 400 message does explain it, but as a beginner my first instinct was application/json (it is a JSON document). The page does say "Send the body as text/plain" in two places, so this is minor, but an example raw request block like the other challenges have would have saved me a round trip.
- Hint quality (helpful? spoilery? useless?):
  - proto-query: spoilery. Rung 1 is good ("which parameter name could climb from a normal key to the shared prototype"), but the page's own "Try it" link gives the full payload, so I never needed the ladder.
  - proto-json: spoilery. Pre-filled textarea plus a complete Burp Repeater request block; the ladder adds nothing.
  - proto-constructor: helpful ladder (rung 1 teaches the constructor/prototype entrance without naming it), but spoilery page ("Try it" link with the exact bypass string).
  - proto-dos: helpful rung 1 ("What if toString stopped being a function?"), but the page links the exact crashing query string, so spoilery overall.
  - proto-client: useless-to-spoilery. The hints describe a Burp browser workflow, but the page links the exact URL and the claim endpoint accepts a bare curl hit, so neither hints nor browser were needed.
  - proto-unicode-bypass: spoilery. Rung 2 is well phrased ("the forbidden key never appears in the raw bytes"), but the page pre-fills the exact escaped document.
  - ssti basic: appropriately easy; the quick link spoils it, which is fine for challenge 1.
  - ssti rce (scope leak): helpful. Rung 1 ("its name is the most obvious one you would pick for this job") made me guess the variable name myself, and guessing right felt earned.
  - ssti wordfilter: helpful. The page hint box teaches the principle (assemble the name at run time from fragments) without giving the fragments.
  - ssti nounderscore: spoilery. The page hint box literally says `String.fromCharCode(95)` is `_` and "Combine it with eval". That is the whole solution.
  - ssti nobrackets: helpful. "What function turns any object into text?" taught me to reach for JSON.stringify myself.
  - ssti dotblock: helpful. Rung 2 names the bracket syntax without writing it out.
  - ssti curly: helpful. The hint box ("What happens if you send two pairs?") plus rung 2 taught the doubling trick; I still had to count the braces myself.
  - ssti noquotes: helpful. The hint box says "spell it with character codes, then evaluate the result" without listing codes; rung 2's ADMIN example showed the pattern on a different word.
  - ssti-rce (Template to Shell): spoilery. The hint box names `require("child_process")` and `execSync("id")`; I only had to wrap it in {{ }}.
  - Net: the ladders themselves are good pedagogy, but the challenge pages keep giving away the answer above them.
- Difficulty fairness:
  - Mostly fair, with labels that roughly match: proto-dos (Easy) was easy, the filter bypasses (Medium) each taught one idea, unicode and noquotes and template-to-shell (Hard) felt hard in the right way.
  - Exceptions: ssti basic is labeled Medium but is the canonical 30-second first SSTI; Easy would be more honest. The proto module is labeled Advanced with xss and sqli prerequisites, yet four of its six challenges hand you the payload on the page, which undercuts the Advanced billing.
  - The leakage bugs (above) make difficulty ratings moot for proto-json, proto-constructor and proto-unicode on a shared instance: they are free once any one admin-check challenge is solved.
- Burp-first feasibility:
  - proto-query: yes, Repeater GET with the query string.
  - proto-json: yes, Repeater POST with JSON body.
  - proto-constructor: yes, Repeater GET.
  - proto-dos: yes, Repeater GET; crash page renders in the response.
  - proto-client: intended path needs a real browser (Burp built-in browser works per the hints), BUT the claim-endpoint bug means it is currently solvable in Repeater with a single GET, no browser at all.
  - proto-unicode-bypass: yes, Repeater POST with text/plain body. (Beginner note: Burp handles this fine; curl needs the header set explicitly.)
  - ssti basic through noquotes: yes, all Repeater GETs with an edited parameter. The curly and wordfilter challenges even suggest Intruder for fuzzing variants, which is doable in Community edition.
  - ssti-rce (Template to Shell): yes, Repeater GET; command output renders in the response.
- Suggestions (concrete):
  1. Fix the cross-challenge and cross-session leakage: give each proto admin check its own property name (not one shared process-wide property), or scope the pollution per session, so each challenge must be solved with its own vector. This is the highest-value fix; it currently lets one exploit collect four flags and lets strangers collect flags for free.
  2. Harden /proto/client/claim: require proof the value actually came through the page's merge (for example a signed token the page mints at render time), or at least only accept the exact theme values the demo uses, so the bare-curl beacon stops working.
  3. Make "Keys merged this request" truthful on the constructor challenge: list keys the merge accepted and call out keys the blacklist dropped. Beginners use that line as their debugger.
  4. Move the full payloads off the challenge pages: replace "Try it" exploit links and pre-filled answer textareas with a harmless baseline example (for example `?theme=light`, `{"theme": "light"}`), and keep the real payload shapes inside hint rung 3 where they belong. The ladders are good; let the student climb them.
  5. Rename the `rce` challenge id or title so it does not collide with `ssti-rce` ("Scope Leak via Template" would end the confusion).
  6. Add a one-line curl note where bracket payloads appear ("curl users: add -g so [brackets] are not treated as URL ranges"), or show the payloads URL-encoded in the Repeater blocks.
  7. Replace the "restart the lab server" tip with shared-instance-safe guidance (for example a per-session reset link), since pool users cannot restart anything.
- Rating: 4
