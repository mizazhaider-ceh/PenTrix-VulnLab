# EXISTING_FEATURES: PenTrix VulnLab (Phase Zero)

Verified live on 2026-10-19 (local run, see INITIAL_TEST_RESULTS.md).
Status legend: VERIFIED = exercised live, CODE = read in source, UNTESTED = not yet tried.

## Student journey (all VERIFIED at the page level)

1. Home `/` (200): hero + 29 module cards. Each card: name, tagline, difficulty
   pill, live `done/total` flag counter from the session.
2. Module page `/<id>` (VERIFIED for /sqli): briefing box, table of vulns with
   difficulty, hint in `<details>`, "how" line, link to each challenge page.
3. Challenge pages (VERIFIED for /sqli/login): real forms/endpoints to attack.
4. Flag capture: `flagBox` renders `PENTRIX{...}` on successful exploit; stored in
   `req.session.flags`; scoreboard reflects it immediately.
5. Scoreboard `/scoreboard` (200 VERIFIED): per-module tables, captured vs not
   captured, progress bar with percentage.
6. About `/about` (CODE): safety warning, how-to-use, lab rules.

## Exploitability (VERIFIED end to end)

- SQLi login bypass: `admin' OR '1'='1' -- ` -> logged in as admin, the
  per-deployment flag for that challenge awarded and persisted in session
  (at the time of testing flags were still deterministic
  `PENTRIX{module_vuln}`; since then flags are random per deployment).
  Real vulnerability, real technique, real validation. This is the quality
  bar every module must meet (Rule 2).

## Module contract (CODE, from MODULE_CONTRACT.md)

- Real vulnerabilities only; award on success, never before; every vuln marked
  `// VULN:`; self-contained routers (no touching app.js/lib/public, no new
  deps); module index must show brief + vuln table; every vuln needs a visible
  attack surface; fixed flag format; `node --check` robustness rule; honest
  difficulty labels.

## What the platform does NOT have (observed gaps)

- No learning paths, no prerequisites, no difficulty progression across modules.
- No per-lab timer, notes, evidence collection, or reporting workflow.
- No reset button per lab (state resets only via DB delete / container rebuild).
- No user accounts or persistent identity (session cookie only; MemoryStore, so
  progress dies with server restart).
- No search, filter, or sort on the module list.
- No skill tagging (which tools a lab needs: Burp, curl, etc.).
- No remediation/secure-alternative teaching after capture (SOLUTIONS.md has
  walkthroughs, but the app itself does not teach the fix).
- Hints are single-level (one hint per vuln, no progressive disclosure).
- Scoreboard has no export, no per-student view, no timestamps.
- Accessibility: no skip links, no ARIA landmarks beyond basics, no
  prefers-reduced-motion handling (no motion exists yet), focus styles are
  browser defaults.
- Mobile: single responsive grid; forms are usable but not tuned.

## Content inventory

- 29 modules, 235 vulns (corrected in Phase One; was 244 by hint-grep overcount), 280 VULN markers, SOLUTIONS.md (132 KB), 12 solution
  batch files. Every module ships hints and full solutions already.
