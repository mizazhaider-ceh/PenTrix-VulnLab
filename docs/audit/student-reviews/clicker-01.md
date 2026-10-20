# Student Review: Clicker Cal (clicker-01)

Post-reboot verification note: the pool VM rebooted mid-audit. I re-ran every flag exploit after the reboot and re-verified my scoreboard total on the live instance. All flag outcomes below are post-reboot verified: the lab awarded the flag for fixation, predictable sids, logout bypass, never-expires, and log leak. Scoreboard re-confirmed at 2/201 with my main jar. The url-demo exploit is the exception, see the urldemo finding under Bugs found.

- Modules tested: Home page (all 29 module cards, difficulty filter with every option, search box with junk and real queries); Session Management (all 6 challenges: fixation, logoutdemo, predictable, urldemo, neverexpires, logleak; every hint toggle, every copy button payload, every back link, junk logins, the preset link clicked twice, the admin panels with wrong and right cookies); /about, /scoreboard, /scenarios, /paths, one scenario page and one path page, the 404 page. Everything on the shared instance at http://127.0.0.1:18407/ with a fresh cookie jar per burst.

- What worked well:
  - Every one of the 29 module links on the home page returned 200; no dead module links.
  - The search box finds modules (q=xss and q=session both matched), keeps the query in the box after searching, and junk like `<script>alert(1)</script>` is echoed back HTML-escaped in the value attribute, not raw.
  - Difficulty filter works for Beginner and Intermediate.
  - /scoreboard, /scenarios, /paths, /about all load; every scenario and path detail link I clicked (api-heist, shop-takeover, api-hacker, zero-to-web-pentester) returned 200.
  - Every session challenge console has a "Back to the Session module" link, and the denial pages have one too, so I never got stranded.
  - Junk logins get a friendly 403 page ("Access denied. Bad username or password.") instead of a crash or a blank page.
  - The fixation preset link (/session/fixation/preset) is a clean 302 back to the console with the cookie set, and clicking it twice is harmless (idempotent).
  - Five of the six session challenges are solvable by clicking and copying values exactly as the pages instruct; the lab awarded the flag each time (all re-verified after the reboot), then showed a "The fix" panel with an OWASP link. The url demo is the exception: replaying a leaked admin URL rendered the admin page but awarded no flag. The hint ladders are native details toggles, so they work with JS off.
  - Scoreboard tracked my cookie jar correctly (2/6 on the jar I used for fixation and logout, matching what that jar earned).
  - The 404 page for a bogus URL is friendly ("Lost in the lab? That page does not exist.") with links to All modules and Scoreboard.

- Bugs found (with reproduction):
  1. The difficulty filter has no "Advanced" option, even though 4 modules are labeled Advanced (Cryptographic Failures, Prototype Pollution, Race Conditions, SSRF). Repro: open the home filter dropdown, it offers only All difficulties / Beginner / Intermediate. Typing ?difficulty=Advanced by hand returns the full unfiltered list, so Advanced modules can never be isolated by the filter.
  2. The module page challenge cards have no link or button to the challenge consoles. Repro: open /session. The six cards (Session Fixation, Logout Does Not Destroy the Session, etc.) contain prose, a Copy button, and hint toggles, but zero anchor links to the consoles (the only hrefs on the page are the nav). The cards say "open the fixation console" without saying where; you must guess /session/fixation or read the hint text. An impatient clicker has nothing to click.
  3. Empty search results show a leaked debug line. Repro: search q=asdfghjklzz. The page shows "No modules match your filter. Try clearing the search." AND "∅ No modules found Something went wrong with the build: no modules loaded." Two stacked, contradictory empty states; the second reads like a broken build and made me think the lab was down.
  4. Four of the six "Starting point" texts use the wrong address http://localhost:3000/... (logoutdemo, predictable, urldemo, neverexpires) while the lab here runs on http://127.0.0.1:18407/. Anyone who copies or types that address hits nothing. Worse, the Copy button copies that prose (wrong URL included) rather than a command or payload.
  5. The "Break then fix" section on /session ends with the line "Fix mode is not available for this challenge yet." repeated six times in a row, on top of the section intro saying the same thing. Reads like placeholder spam; I kept clicking expecting a button to appear.
  6. The URL-demo challenge never awarded a flag in my tests (re-checked after the reboot). Repro: log in at /session/urldemo, open /session/urldemo/proxy-log, replay a logged admin home URL (/session/urldemo/home?sid=...) from a fresh identity. Result: 200, "Welcome, admin", but no flag was awarded. Worse, the proxy log contains only real visitor traffic and shows no seeded admin entry, so a solo student following the card ("find the admin's sid in the proxy log") has nothing to find except their own sids. The log rows are also inconsistent: one row reads "GET /session/urldemo/home?sid=..." and another reads "/session/urldemo/home?sid=..." with no verb. By eye you cannot tell which logged sid is the live admin one, because the home page greets every replayed visit "Welcome, admin" whether or not a flag fires.
  7. Minor brand inconsistency: the logleak console brands itself "⌗ Acme Ops" but its shared Access denied page brands itself "! Acme Portal". Verbatim mismatch on the same screen flow.

- Friction/confusion points:
  - Nothing to click on the module cards (bug 2 above) is the single biggest clicker friction: the whole page is instructions about consoles that are not linked.
  - The Copy buttons on the cards copy long prose instructions, so the "Copy" label sets the wrong expectation; you expect a command or a payload and get a paragraph with a broken URL.
  - Paths page says "🔒 Locked: finish Zero to Web Pentester first. This is guidance, not a hard block: you can still browse the steps now." A lock icon plus the word "Locked" next to text saying it is not locked is contradictory; as a clicker I expected a locked page and the detail page just opened.
  - /about says "Still stuck? Check SOLUTIONS.md." with no link and no path, so a web-only student has no idea where that file lives.
  - The session briefing lists "Prerequisites: auth" as plain text with no link to the auth module.
  - The nav label "About" and the hero button "How to use" both go to /about; two labels for one page is mildly confusing.

- Hint quality (helpful? spoilery? useless?): Helpful and well graded. Every card and console carries a 3-level ladder: level 1 nudges, level 2 teaches the technique, level 3 gives the exact steps (fully spoilery, but you choose to open it). I opened all of them and they matched the consoles. Small nit: the hints keep telling you to do everything in Burp Proxy, even steps trivially doable in the browser (like reading the predictable sids off the page), which slows a clicker down for no reason.

- Difficulty fairness: Mostly fair. The Easy challenges are genuinely easy (copy a value, replay a request), the two Mediums (fixation, predictable) need one extra step each (preset cookie before login; swap the cookie). Nothing felt mislabeled; if anything predictable is the easiest of the bunch since the page prints both sids. One unfair case: the Easy URL demo never awarded a flag on replay (bug 6), so its label is moot until that is fixed.

- Burp-first feasibility: Feasible. Every session challenge is shaped for Burp (preset link into Proxy history, Repeater replays, cookie edits) and I completed five of the six with curl and a cookie jar, so a browser-only student is not blocked either (the URL demo never awarded a flag by any route I tried, see bug 6). The one real hit against Burp-first is bug 4: four starting points hand you http://localhost:3000/... addresses, which break the whole Burp flow whenever the lab runs on a different port (like this shared instance).

- Suggestions (concrete):
  1. Add "Advanced" to the difficulty dropdown, and make an unrecognized filter value show an empty state instead of silently returning everything.
  2. Put an "Open challenge" button on every module card linking straight to its console (e.g. /session/fixation). This is the fix for the biggest clicker pain point.
  3. Delete the "Something went wrong with the build: no modules loaded." line from the empty search state; keep one friendly message.
  4. Replace the hardcoded http://localhost:3000 addresses in starting points with relative paths or the actual request origin.
  5. Make the card Copy buttons copy the real first request or payload, or rename the button to "Copy instructions" so it does not promise code.
  6. Collapse the six repeated "Fix mode is not available for this challenge yet." lines into a single line under "Break then fix".
  7. Make proxy log rows consistent (always show the HTTP verb).
  8. Rename the Paths "🔒 Locked" pill to "Suggested order" since it is not a lock.
  9. Link SOLUTIONS.md from /about, or say where in the lab folder it lives.

- Rating: 1-5: 3. The core loop is solid (friendly errors, working hints, flags awarded reliably, scoreboard tracking, good 404), but as an impatient clicker I rate the front door: a module page that tells me to open consoles it never links, and copy buttons that hand me a localhost:3000 address that goes nowhere, cost it two stars. Fix the card links and the port text and this is a 4.
