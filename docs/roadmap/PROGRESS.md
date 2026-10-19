# PROGRESS: PenTrix VulnLab transformation

Date: 2026-10-19. Statuses: NOT STARTED / IN PROGRESS / BLOCKED / IMPLEMENTED /
VERIFIED / INTEGRATED / COMPLETE.

## Current ledger (reconciled against git and a live run, 2026-10-19)

Git history shows M3-M7 merged to `main` (safety, verification integrity,
claymorphism shell, motion system, curriculum pass to 201 challenges). The
"Phase One review gate" text further down is historical and no longer current.
See `docs/audit/KNOWN_ISSUES.md` for the verified baseline and open issues.

| Unit | Status | Evidence | Next action |
|---|---|---|---|
| Fresh audit (runtime, inventory, flags, scoreboard) | VERIFIED | `docs/audit/KNOWN_ISSUES.md`; isolated container on :3100 | Browser UI audit (KI-10) |
| Test harness (`npm test`, Node 20) | IMPLEMENTED, run in Docker: 10/10 pass | `tests/platform.test.js` | Extend with per-module exploit tests |
| Persistent sessions (KI-1) | VERIFIED (restart test) | `lib/session-store.js`, `tests/platform.test.js` | Not committed yet |
| Docs/UI text corrections (KI-2, KI-3) | IMPLEMENTED | `app.js`, `README.md` | none |
| Per-challenge exploit tests (KI-4) | IN PROGRESS: 1/201 covered (sqli:login-bypass) | `tests/platform.test.js` | Start with `sqli` module, then `auth`, `idor`, `xss` claim flow |
| Lab network isolation (KI-7) | NOT STARTED | n/a | Compose internal network + egress restriction design |
| Challenge file split | NOT STARTED (contract exists) | `docs/roadmap/CHALLENGE_SPLIT_CONTRACT.md` | Decide after KI-4 coverage exists |

## Continuation note

Resume by running `docker build -t pentrix-audit:test . ; docker run --rm pentrix-audit:test npm test`
(host Node 24 cannot load better-sqlite3 v11). Re-verify before trusting this table.

# Historical notes (pre-M3, kept for context)


## Done

### Phase Zero (audit baseline)
- `docs/audit/PROJECT_DISCOVERY.md`: stack, structure, module inventory,
  Docker review, git state, seed data. (235-vuln correction applied in
  Phase One.)
- `docs/audit/EXISTING_FEATURES.md`: verified student journey, exploit
  bar (SQLi login bypass end to end), module contract, gap list.
- `docs/audit/ARCHITECTURE_AND_RISKS.md`: architecture, ranked risks.
- `docs/audit/INITIAL_TEST_RESULTS.md`: boot matrix (v11 vs v12), live
  HTTP checks, environment limits stated honestly.
- Live instance on the VM verified; SQLi login bypass exploited with a
  session cookie jar, flag persisted.

### Phase One (research and planning)
- `docs/roadmap/ARCHITECTURE_ASSESSMENT.md`: request flow, loader contract
  gaps, session/flag trust model, Dockerfile and compose line-by-line,
  isolation risks, 11 minimal improvements, compatibility surface, 11
  ranked risks, lab-engine deep dive (verification, reset layers,
  per-student sketch), hypotheses H1-H11.
- `docs/curriculum/LAB_QUALITY_MATRIX.md`: all 29 modules audited against
  router code; 235 vulns with verdicts (68% strong, 16% needs work, 2%
  shallow, 14% duplicate); 34 duplicates; difficulty analysis; top-10
  improvement plan; platform gaps.
- `docs/design/DESIGN_BRIEF.md`: UI audit, 5 user journeys, "Precision
  Instrument" direction, Lab Paper plus Bench Dark tokens (AA-checked),
  12 component specs, accessibility and performance acceptance criteria,
  current-UI reference renders.
- `docs/design/MOTION_SYSTEM.md`: 7 motion primitives, timing/easing
  tokens, reduced-motion plan, performance rules, mobile fallbacks,
  acceptance checklist.
- `docs/research/AGENT_SKILLS_RESEARCH.md`: 4 repos verified via GitHub
  API; one selective recommendation (better-web-ui subset, staged);
  Aceternity UI spelling and incompatibility recorded; addendum with
  mystery-reference verdicts and staged install commands.
- `docs/research/CYBERSECURITY_PLATFORM_BENCHMARK.md`: 5 platforms
  compared on learning design; 14 adoptable principles, no copied
  branding.
- `docs/roadmap/IMPLEMENTATION_PLAN.md`: 10 milestones with exit criteria.
- `docs/roadmap/DECISIONS.md`: 14 decisions with alternatives and
  tradeoffs.
- `docs/qa/screenshot.sh`: verified curl to WeasyPrint to PNG pipeline;
  baseline renders in `docs/qa/shots/` (home, scoreboard, sqli module,
  sqli/login challenge).

### Owner inputs folded in (2026-10-19)
- Push authorized: branches plus PRs, never force-push main, nothing
  pushed until Phase One docs are reviewed.
- Live target is the VM instance only; never touch his localhost.
- Visual reviews via the screenshot pipeline, attached in chat.
- UI reference list evaluated against the actual stack before adoption.
- "Animaster Leap" and "Hipa UI" investigated; unverifiable, awaiting URLs.
- Balance rule: lab engine equals design in weight.

## Next

1. Owner reviews the Phase One docs (this is the current gate).
2. Decisions needed from the owner (see Open questions).
3. On approval: create `phase-one-audit` branch from tagged
   `phase-zero-baseline`; run the staged skill install if approved.
4. Begin Milestone 3 (safety and compatibility groundwork).

## Open questions for izaz

1. Approve the better-web-ui selective subset install (`setup`, `add-ui`,
   `critique`, `audit`)? Optionally the three hueyexe UX skills?
2. "Animaster Leap" and "Hipa UI": can you share URLs? Neither could be
   verified; closest guess for the first is Animmaster Lib
   (animmasterlib.dev), unconfirmed.
3. Learning paths: the plan proposes Foundations, Injection, Auth and
   Sessions, Advanced. Do these track names match how you teach, or do
   you want different ones?
4. Graded/classroom use: is anyone grading with the scoreboard today? The
   session secret is committed and awards are trust-based; the fix
   priority depends on whether grading is real or future.
5. cors rebuild scope: full attacker/victim rebuild is Milestone 7.3. OK
   to cut the current quiz-style harness entirely?

## Known limitations (honest)

- No Docker daemon on the VM: Dockerfile and compose reviewed statically,
  not built here. The owner's Windows Docker run is his side to confirm.
- No browser automation used: visual verification is static PNG renders;
  motion states are reviewed as frames plus spec.
- better-sqlite3 v11 does not run on Node 24: the VM verify copy uses v12;
  the repo pin is unchanged and correct for its Node 20 target.
- Skill content quality beyond READMEs was not assessed; star counts and
  commit dates are reported, nothing more is claimed.
