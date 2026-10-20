# Student Review: Day-One Zara (beginner-12)

- Modules tested:
  - CORS Misconfiguration (/cors): all 6 challenges tested (Reflected Origin with Credentials, Null Origin Trusted, Regex Allowlist Bypass, Wildcard on Sensitive Data, Subdomain Suffix Check, Exposed Admin Token Header). All 6 flags earned via /cors/prove.
  - Broken Access Control / IDOR (/idor): all 7 challenges tested (Profile IDOR, Unprotected Admin Panel, Invoice Download IDOR, Email Change IDOR, API Key Regeneration IDOR, Forced Browsing to Admin Function, Comment Deletion IDOR). All 7 flags earned; each flag appeared on the page itself, and the lab awarded the flag for each.
  - Total: 13/13. Scoreboard and nav chip both show 13/201 after the run. Module index pages show "flag captured" pills on all 13 cards.

- What worked well:
  - CORS: the shared /cors/prove flow is a great beginner pattern. The module briefing explains exactly what prove does (real server-side request with my Origin, inspects the headers), and the result page shows the exact response headers plus a pass/fail verdict with the why-it-matters sentence. I always knew what I had proven.
  - CORS: negative cases are handled honestly. Proving cors-null with origin=https://evil.com says "Not vulnerable for this Origin" and awards nothing. Proving cors-regex with a legitimate subdomain (https://app.pentrix.lab) shows the headers but awards nothing. Re-running a solved proof just re-shows the same flag, no double counting.
  - IDOR: flags appearing on the page itself is the cleanest feedback loop of any module I have seen. No separate prove step to learn. The confirmation pages are explicit ("The email for admin (id 1) is now pwned@evil.com", "Comment #2 by alice was deleted"), so I knew exactly whose boundary I crossed.
  - IDOR: cheats fail correctly. Hitting /idor/admin or /idor/users/1 with no session returns 401 "Sign in required", no flag. So you must at least hold a valid non-admin session, which teaches that IDOR is about crossing a boundary, not about no auth at all.
  - No bare claim endpoints exist (tried /claim, /beacon, /cors/claim, /cors/beacon, all 404), so there is no way to snag flags without the exploit.
  - Every challenge was reproducible in curl, which maps 1:1 to Burp Repeater steps, so a beginner can follow along without a GUI.

- Bugs found (with reproduction):
  - BUG 1 (copy bug, affects 3 challenges): starting-point text cites http://localhost:3000/... URLs, but the lab runs on 127.0.0.1:18402 here, so copy-pasting the URL gets a dead page. Reproduced by reading the module pages: /cors card "Exposed Admin Token Header" starting point says "Open http://localhost:3000/cors/expose through the Burp proxy browser"; /idor card "API Key Regeneration IDOR" says "visit http://localhost:3000/idor/login/alice"; /idor card "Comment Deletion IDOR" says "visit http://localhost:3000/idor/login/bob". Fix: use relative paths (/cors/expose, /idor/login/alice) or the actual host:port.
  - BUG 2 (destructive shared state): the Comment Deletion challenge has no way to restore deleted comments on a shared instance. I deleted alice's comment (id 2) as bob via POST /idor/comments/delete with id=2, then found no add-comment form anywhere on /idor/comments, so the seeded comment is permanently gone for every other student on this shared pool instance until a restart/reseed. Only admin's comment (id 1) remains as a deletable target. Fix: add a reseed button or a "restore lab data" action, or make the comments reset per session.
  - BUG 3 (confusing copy, CORS reflect card): the card "how" text says "The reflected ACAO plus Allow-Credentials: true earns the flag; or prove via /cors/prove?vuln=cors-reflect&origin=https://evil.com". As a beginner I first read this as "see the headers in Repeater and the flag appears", but nothing awards until you actually run /prove. I only figured that out by re-reading. Same "or prove via" phrasing appears on the wildcard card. Fix: say "Repeater shows you the vulnerable headers; the flag is awarded when you submit that Origin through /cors/prove".
  - NOT a bug (verified working): /scoreboard shows both modules correctly, all 13 challenges listed as Captured with correct names, counts (CORS 6/6, IDOR 7/7) and difficulties, nav chip and header counter both read 13/201. The challenge cards on /cors show 6 "flag captured" pills.

- Friction/confusion points:
  - The CORS card "how" text for 5 of 6 challenges is effectively the full payload (e.g. "Burp Repeater: GET /cors/api/profile with header Origin: https://evil.com"). I solved the challenge by reading the card before ever opening a hint. That is fine for day one, but the hints then feel redundant rather than educational.
  - CORS Hint 3 on cors-reflect tells me to use the "Burp Proxy" and "the attacker page (127.0.0.1 origin)" with no curl equivalent. The briefing's "mirrors what curl -H Origin: ... shows you by hand" helped more than the hint did.
  - IDOR "Invoice Download IDOR": the challenge page /idor/invoice/:id just renders an HTML page, no download button. I spent a minute looking for a file download because of the name. Minor.
  - IDOR forced browsing: the module briefing's "Pages in the store" table openly lists "Member directory /idor/admin/users" with its path, so the "force browse an unlinked path" discovery moment never happens; I just copied the path from the table. For a beginner this is kind, but the challenge's premise (unlinked URL) contradicts the briefing.
  - Shared-pool confusion: after my email-change test, the member directory showed admin's email as the value I set (expected) but ALSO showed alice's email as "attacker@evil.com", which I never set. That had to be another tester's change leaking into my view. As a day-one student I briefly thought I had broken something. A note in the IDOR briefing like "this is a shared instance, other students' changes may appear in your pages" would have saved the panic.
  - The IDOR module cards say "Open the page" while CORS cards say "Open challenge", tiny inconsistency, not blocking.
  - First-run UX: the IDOR briefing says "Sign in as a normal shopper, then look closely at what your browser sends", but the fastest path is the /idor/login/alice shortcut links, which are only in the "Session" box, not in the briefing paragraph. I found them, but a beginner skimming the brief could miss them.

- Hint quality (helpful? spoilery? useless?):
  - cors-reflect: card "how" text spoiled it before hints; Hint 1 would have been enough. Helpful but the card preempts it.
  - cors-null: Hint 1 good nudge (try values, watch headers); Hint 2 names the literal "null" answer, which unlocked it. Helpful, rung 2 unlocked.
  - cors-regex: Hint 1 hands me the exact regex (^https://.*pentrix\.lab), so rung 1 basically unlocked it. Helpful but spoilery at rung 1; I learned the concept anyway because the prove result page explains it.
  - cors-wildcard-data: Hint 1 asks "What does * mean?" and tells me where to look. Unlocked at rung 1, genuinely taught. Helpful.
  - cors-subdomain: Hint 1 hands me hostname.endsWith('.trusted.pentrix.lab'). Unlocked at rung 1. Helpful but spoilery.
  - cors-expose-headers: Hint 1 good question, Hint 2 named Access-Control-Expose-Headers, which unlocked it. Helpful, rung 2 unlocked.
  - IDOR profile: Hint 1 ("Your profile page has a number in its URL") unlocked it. Helpful, perfect rung 1.
  - IDOR admin panel: Hint 2 ("A hidden link is not an access control") taught the concept, unlocked at rung 2. Helpful.
  - IDOR invoice: Hint 1 ("Find your own invoice request in Burp's Proxy history first") was the key step; the rest followed. Helpful, rung 1 unlocked (I used /idor/invoice/1 by guessing sequential ids, which Hint 2 confirms is intended).
  - IDOR email change: Hint 1 ("the form carries more than just the new address") made me read the hidden user_id field; unlocked at rung 1. Helpful.
  - IDOR apikey regen: Hint 2 says "the admin is id 1", fully explicit. Helpful but spoilery; a beginner could not fail after rung 2.
  - IDOR forced browsing: Hint 3 only hints at "a path under /idor/admin/", but the briefing table gave me /idor/admin/users outright. Between the two, no friction at all. Helpful.
  - IDOR comment delete: Hint 2/3 give the exact steps ("send that POST to Repeater and try a different id"). Unlocked at rung 2. Helpful.
  - Overall: no useless hints. The ladder shape (nudge, technique, explicit) works, but rungs 1 often contain the full answer (exact regex, exact check, exact id), so they read as spoilers for anyone past day one.

- Difficulty fairness:
  - Fair overall for the labels given. The two Easy CORS challenges (wildcard, expose headers) were genuinely easy. The four Medium CORS challenges were fair for a beginner because the prove page tells you exactly what combination it wants.
  - IDOR Easy challenges were all solvable in under 2 minutes each. The three Medium ones (invoice, apikey regen, forced browsing) were still beginner-fair because the hints name the id parameter, the admin id, and the /idor/admin/ path area.
  - Nothing felt unfair or required knowledge outside the briefings and hints. The hardest real step was understanding what an Origin header is on CORS challenge 1, and the briefing covers it.

- Burp-first feasibility:
  - Yes for all 13 with Burp Community. Every exploit is a single GET or POST with a modified header or parameter, all doable in Repeater. Session handling for IDOR (login as alice/bob via /idor/login/alice) works in the Burp embedded browser, cookies carry automatically. The CORS regex challenge suggests Intruder Sniper over the Origin header; a 3-origin list is fine within Community throttling. The /cors/prove submission is a plain GET in the browser, which works through Burp's proxy browser. The flag-copy and scoreboard checks are browser-side. No Burp Pro features needed anywhere.

- Suggestions (concrete):
  - Replace the three localhost:3000 URLs in starting points with relative paths (e.g. "Open /cors/expose through the Burp proxy browser", "visit /idor/login/alice").
  - Reword the CORS reflect/wildcard "how" text: "Repeater shows the vulnerable headers; submit the Origin through /cors/prove to earn the flag."
  - Add a per-session or one-click reseed for the IDOR comments (or make comments per-session), since Comment Deletion permanently removes seeded data on a shared instance.
  - Add one line to the IDOR briefing: "This is a shared instance, so emails, keys and comments may reflect other students' tests. That is normal."
  - Either remove the member directory path from the IDOR "Pages in the store" table (keep the discovery in Forced Browsing) or reframe that challenge as "the path is listed, the lesson is that unlinked does not mean protected".
  - Make hint rung 1 slightly less explicit (describe the check type instead of printing the regex/endsWith code) so rung 2 still has something to teach; keep rung 3 as the safety net.
  - Add a curl one-liner to the CORS challenge "Starting point" blocks, e.g. curl -H "Origin: https://evil.com" /cors/api/profile, for students without Burp running yet.

- Rating: 4
