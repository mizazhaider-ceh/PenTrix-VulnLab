# Student Review: Clicker Eli (clicker-03)
- Modules tested: XXE Injection (all 8 challenge pages: /xxe/import, /xxe/soap, /xxe/billion, /xxe/dtd, /xxe/collector, /xxe/svg, /xxe/xinclude, /xxe/param), plus a full navigation sweep of /scoreboard, /scenarios, /paths, all 3 scenario detail pages, all 3 path detail pages, all 3 path verify pages, and all 29 module home pages.

- What worked well:
  - Every link I clicked resolved. All 23 deep links from the scenarios and paths pages (e.g. /sqli/login, /jwt#alg-confusion, /oauth#code-replay) returned 200, and all 19 challenge anchors I checked were present on their target pages.
  - Progress tracking works end to end. After capturing the XXE File Read flag the nav chip flipped from 0/201 to 1/201, and after the Billion Laughs flag to 2/201. The scoreboard row changed from "Not captured" to "Captured" for that challenge. Progress bars on module cards, scenario pages (0/4), and path pages (0/10) all render with sensible labels.
  - The flag-capture moment is satisfying: "✓ Flag captured. Saved to your scoreboard" plus a Copy flag button and links to Scoreboard and All modules, plus a "The fix" remediation box with an OWASP cheat sheet reference.
  - The XXE module page is the best briefing I saw: every challenge has a 3-level hint ladder (nudge, technique, explicit), a "Starting point Copy" button, and exact numbers (Billion Laughs states the 3000-char limit, the 1.5s and 5MB thresholds, and even the classic lol..lol7 payload shape).
  - Scenario locked stages are clear: a lock icon with "Complete the previous stage to unlock" and no dead links where locked.
  - The OOB collector explains its own purpose well ("this collector is that 'somewhere else'") and shows the hosted DTD URL plus the pingback log table right below the upload form.

- Bugs found (with reproduction):
  - About page dead end: the About page says "Stuck? Open the hint. Still stuck? Check SOLUTIONS.md." There is no link, and I tried /SOLUTIONS.md, /solutions.md and /solutions: all 404. A stuck student is told to check something that does not exist.
  - Collector accepts junk silently: POSTing an empty or garbage `dtd` value to /xxe/collector/dtd returns 302 and the page then shows "Currently hosted at http://127.0.0.1:18409/xxe/collector/dtd" with the junk stored verbatim. I hosted "not a dtd at all" as a DTD with zero validation feedback.
  - One flaky render (unconfirmed, likely my own script): a single fetch of /jwt did not contain the `weak-secret` anchor, but 6 immediate refetches all contained it with identical byte size. Not a lab bug as far as I can tell, noting it for completeness.
  - The shared instance stopped responding (connection refused on every request) near the end of my sweep, around 03:30 CEST, after hours of healthy 200s. I did not boot, restart, or kill anything; reporting as observed. This also meant I could not review the 404 page copy.

- Friction/confusion points:
  - Scoreboard rows are not clickable. I captured flags, went to the scoreboard, and instinctively tried to jump from the "XXE File Read" row back to the challenge. Nothing to click. You have to go back to Modules, find the module card, then find the challenge card. For a clicker, the scoreboard feels read-only when it should be a launchpad.
  - The "🛠 0 fixes" pill on the scoreboard is never explained anywhere: no tooltip on the pill, no mention on the About page, nothing on the home page. On the XXE module page there is a "Break then fix" section that says "Fix mode is not available for this module yet", and that exact line is repeated once per challenge card (8 times on the page). It reads like a feature that ships "soon" but the pill on the scoreboard counts it as if it exists.
  - Empty submits give no feedback. I submitted empty forms on /xxe/import, /xxe/billion, /xxe/svg, /xxe/soap and /xxe/xinclude: every one returned 200 with an empty result block ("Import result", "Parse result", "Service response") and no message like "you submitted nothing". A clicker mashing buttons learns nothing from the response.
  - Malformed XML fails silently. POSTing `<data><oops></data>` to /xxe/import renders `&lt;oops&gt;` as parsed content with no parse-error message. Typo your payload and the lab just shrugs.
  - Decorative nav that is not nav: the SOAP console shows "Status · Docs · API keys" and the importer shows "Dashboard · Imports · Settings" as plain text that looks exactly like navigation. I checked the markup: no links. A clicker will click these mentally and get nothing.
  - Inconsistent path guidance: the XXE briefing example payload uses the placeholder `file:///absolute/path/to/modules/xxe/secret.txt` (not a real path), while the XInclude challenge page prints the full real absolute path in its example. One page makes you guess, the other hands you the answer.
  - "Starting point Copy" buttons and "Copy flag" buttons need JavaScript; fine in a browser, but worth noting nothing breaks without it.

- Hint quality (helpful? spoilery? useless?): Helpful and well-structured, drifting into spoilery on this module. The 3-level ladder (nudge, technique, explicit) is exactly the right shape. But the Billion Laughs hint gives the exact entity cascade (`lol` through `lol7`, "each level multiplies the work by ten"), and the XInclude page prints the literal absolute secret path. A clicker like me barely needs to think; a student who wants to learn might want the explicit level gated a bit more.

- Difficulty fairness: Fair overall. XXE File Read (Medium) is easy once the XInclude page hands you the path. Billion Laughs (Medium) is fair because the thresholds and payload shape are documented; my payload was awarded the flag via the expansion-size condition even though parsing took only ~0.4s, matching the documented "or blows the expansion past 5 MB" rule. SOAP (Easy) is appropriately easy. SSRF via XXE (Hard) requires discovering the internal endpoint, which feels right for Hard.

- Burp-first feasibility: Fully feasible. Every challenge page's starting point describes the Burp Proxy plus Repeater flow. That said, I completed both exploits I tested with plain curl form POSTs and no Burp at all, so the lab does not punish students who skip the proxy setup. A clicker with only a browser and curl can get flags.

- Suggestions (concrete):
  1. Make scoreboard challenge rows link to their challenge pages (deep link with the challenge anchor), so the scoreboard is a launchpad, not a museum.
  2. Either explain the "fixes" pill (one-line tooltip: "Fix mode: repair the vulnerable code. Not available yet.") or hide it until fix mode ships. Same for the 8 repeated "Fix mode is not available for this challenge yet" lines; one section-level notice is enough.
  3. Add an empty-submit message ("You submitted nothing. Paste some XML and try again.") on all challenge forms and the collector DTD form.
  4. Surface XML parse errors instead of silently echoing escaped input, so payload typos are debuggable.
  5. Fix the About page: either serve SOLUTIONS.md at a real route and link it, or delete the "Check SOLUTIONS.md" sentence.
  6. Validate the collector DTD upload (reject empty or non-DTD-looking input with a message) or label the field honestly if anything goes.
  7. Make the decorative console nav (Status, Docs, API keys, Dashboard, Imports, Settings) real links or visually distinct from real navigation.
  8. Pick one path strategy for the file-read challenges: either always give the absolute path or never; the current split (placeholder in the briefing, real path in XInclude) is uneven.

- Rating: 1-5: 4
