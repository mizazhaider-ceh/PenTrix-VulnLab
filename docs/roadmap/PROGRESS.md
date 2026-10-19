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
| Per-challenge exploit tests (KI-4) | IN PROGRESS: 63/201 covered (api, sqli, xss, auth, idor, csrf, cmdi, lfi); every split challenge carries its own exploit test | `tests/`, `modules/<id>/challenges/*.js` on main at 3375613 | Continue with `ssrf`, `upload`, `xxe`, then the rest in checklist order |
| Lab network isolation (KI-7) | NOT STARTED | n/a | Compose internal network + egress restriction design |
| Challenge file split | IN PROGRESS: 8/29 modules split (63/201 challenges), each with exploit tests, on main at 3375613 | `modules/<id>/challenges/<vulnId>.js`; contract at `docs/roadmap/CHALLENGE_SPLIT_CONTRACT.md` | Split remaining 21 modules (138 challenges) in the checklist order below |

## Challenge split progress (2026-10-19)

8 of 29 modules split so far, 63 of 201 challenges, all on `main` at
`3375613`. Every split challenge ships with its own per-challenge exploit
test, and the tests caught real bugs that the split commits fixed:

- `sqli`: the login-bypass challenge awarded the flag when real admin
  credentials were used (it should only award on an actual injection
  bypass).
- `idor`: an IDOR challenge leaked the admin secret and awarded flags to
  admin sessions (the flag must only go to the intended exploit).
- `csrf`: the referer host check was wrong (allowed wrong-host requests).
- `xss`: the dom-clobber challenge state was shared across students.
- Wrong hint payloads in some challenges (hints that would never work).

21 modules remain, to be split in this order: ssrf, upload, xxe, ssti,
misconfig, jwt, session, race, bizlogic, redirect, hostheader, cors, proto,
crypto, oauth, postmsg, csti, http, jsonp, formula, redos (138 challenges).

### Per-module split checklist

Legend: `done` = split, tested, verified and committed on main at 3375613
(verified means the per-challenge exploit tests pass). `pending` = not
started. Challenge counts are listed for done modules; pending counts are
tbd and sum to 138.

| # | Module | Challenges | Split | Tests | Verified | Committed |
|---|---|---|---|---|---|---|
| 1 | api | 5 | done | done | done | done |
| 2 | sqli | 11 | done | done | done | done |
| 3 | xss | 9 | done | done | done | done |
| 4 | auth | 8 | done | done | done | done |
| 5 | idor | 7 | done | done | done | done |
| 6 | csrf | 5 | done | done | done | done |
| 7 | cmdi | 9 | done | done | done | done |
| 8 | lfi | 9 | done | done | done | done |
| 9 | ssrf | tbd | pending | pending | pending | pending |
| 10 | upload | tbd | pending | pending | pending | pending |
| 11 | xxe | tbd | pending | pending | pending | pending |
| 12 | ssti | tbd | pending | pending | pending | pending |
| 13 | misconfig | tbd | pending | pending | pending | pending |
| 14 | jwt | tbd | pending | pending | pending | pending |
| 15 | session | tbd | pending | pending | pending | pending |
| 16 | race | tbd | pending | pending | pending | pending |
| 17 | bizlogic | tbd | pending | pending | pending | pending |
| 18 | redirect | tbd | pending | pending | pending | pending |
| 19 | hostheader | tbd | pending | pending | pending | pending |
| 20 | cors | tbd | pending | pending | pending | pending |
| 21 | proto | tbd | pending | pending | pending | pending |
| 22 | crypto | tbd | pending | pending | pending | pending |
| 23 | oauth | tbd | pending | pending | pending | pending |
| 24 | postmsg | tbd | pending | pending | pending | pending |
| 25 | csti | tbd | pending | pending | pending | pending |
| 26 | http | tbd | pending | pending | pending | pending |
| 27 | jsonp | tbd | pending | pending | pending | pending |
| 28 | formula | tbd | pending | pending | pending | pending |
| 29 | redos | tbd | pending | pending | pending | pending |

## Continuation note

Resume by running `docker build -t pentrix-audit:test . ; docker run --rm pentrix-audit:test npm test`
(host Node 24 cannot load better-sqlite3 v11). Re-verify before trusting this table.

## Milestone 11 (break-then-fix mode): IN PROGRESS

Recorded 2026-10-19. M11 adds a fix mode on top of the exploit
challenges: after capturing a flag the student gets the vulnerable code
and must patch it. A fix is accepted only when the exploit is blocked
and legitimate use still works. Pilot scope: `sqli` (11) + `xss` (9) =
20 fix blocks, each living at `modules/<module>/fixes/<vulnId>.js`.

### Framework

| File | Status | What it does |
|---|---|---|
| `lib/fixmode.js` | done | Sandboxed runner: executes student code in `node:vm` with a minimal sandbox (plain JS builtins plus a neutered console; no `require`, no `process`, no file or network access), 2s run timeout, 50KB code cap. Exports `listFixBlocks`, `hasFixBlock`, `getFixBlock`, `validateBlock`, `testFix`, `resetFixCache` |
| `lib/fixbadges.js` | done | Badge storage: `fix_badges` SQLite table keyed by express `sessionID` (same user identity as the flag system), so badges survive server restarts |
| `lib/page.js` fix UI | done | `fixCta`, `fixEditorPage`, `fixResultHtml`, `fixBadgePill`; challenge pages render the fix CTA when a block exists |

### The four runner checks (`testFix` in `lib/fixmode.js`)

A student fix is accepted only when all four pass
(`ok: true, exploitBlocked: true, legitWorks: true`):

1. Block sanity (`validateBlock`): the block has `vulnerableCode`,
   `fixedCode`, `testExploit`, `testLegit`; the vulnerable code defines a
   callable `vulnFn` in the sandbox; `testExploit` returns `true` on the
   vulnerable code (the exploit really works); `testLegit` returns `true`
   on the vulnerable code (normal use really works).
2. `definesVulnFn`: the student's fixed code defines a callable `vulnFn`
   in the sandbox.
3. Exploit blocked: `testExploit` evaluates to something other than
   `true` against the student's fixed code.
4. Legit use preserved: `testLegit` evaluates to `true` against the
   student's fixed code.

### Pilot fix blocks

| Module | Fix blocks | Status |
|---|---|---|
| `sqli` | 11/11: blind, error, groupby-having, insert-inject, like-wildcard, limit-offset, login-bypass, order-by, second-order, union-filter-bypass, union | done |
| `xss` | 9/9: dom, reflected, stored, xss-attr-breakout, xss-backtick, xss-dom-clobber, xss-js-context, xss-markdown, xss-svg-upload | done |

Each block carries `title`, `vulnerableCode`, `fixedCode` (reference
solution), `fixHint`, `testExploit` (expression that is `true` when the
exploit succeeds), and `testLegit` (expression that is `true` when
legitimate use works). Block ids mirror their challenge ids one to one.

Rule for the other 181 challenges: `fixCta` degrades to the honest
"Fix mode is coming soon for this challenge." note until a fix block
lands for that challenge.

### Tests

| File | Status |
|---|---|
| `tests/fixmode.test.js` | in progress (file not yet present) |
| `tests/fixmode-sqli.test.js` | in progress (file not yet present) |
| `tests/fixmode-xss.test.js` | in progress (file not yet present) |
| `tests/fixmode-badges.test.js` | in progress (file not yet present) |

### Next actions

1. Write the four fix-mode test files above and run them (VM Node 24
   needs the better-sqlite3 v12 verify copy, or Docker).
2. Re-verify this section after the tests land.

## Milestone 12 (kill-chain scenarios): IN PROGRESS

Recorded 2026-10-19. M12 chains several challenges across modules into
story-driven kill chains with staged unlock: stage N+1 opens only after
stage N's flag is captured. Scenario flags live in the flags table with
module_id `scenario` (same `PENTRIX{<32 hex>}` format, seeded by
`ensureFlags`, INSERT OR IGNORE makes reseeding safe).

### Framework

| File | Status | What it does |
|---|---|---|
| `scenarios/index.js` | done | Defensive def loader, `GET /scenarios` (clay cards: name, tagline, difficulty pill, per-scenario progress bar, link), `GET /scenarios/:id` (story brief panel, gated stage list, completion award). Exports `{ router, scenarios, setScenariosRegistry }` |
| `scenarios/shop-takeover.js` | done (real def, landed 2026-10-19) | sqli/login-bypass, idor/admin, bizlogic/biz-price-tamper, xss/stored |
| `scenarios/api-heist.js` | done (real def) | api/exposure, api/mass-assignment, jwt/none-admin, api/api-version-bypass |
| `scenarios/ghost-in-the-cms.js` | done (real def, landed 2026-10-19) | misconfig/git, auth/reset-predictable, upload/upload-double-ext, xss/stored |
| `app.js` wiring | done | `RESERVED_IDS` gains `scenarios` and `paths`; router mounted at `/scenarios`; registry injected via `setScenariosRegistry`; `ensureFlags` also seeds the three scenario flags |
| `lib/page.js` nav | done | `Scenarios` link added (`activeNav: 'scenarios'`) |
| Scoreboard | done | New "Kill-chain scenarios" section (`sb-scenarios` class, not `sb-module`, so test parsing is untouched): per-scenario captured/missing pill plus link; the `<b>got / total</b> flags` line counts module challenges only, unchanged |

### Stage gating rules

1. Stage 0 is always unlocked; stage i unlocks iff stage i-1's flag is captured (checked per request via `captured(req, moduleId, vulnId)`).
2. Unlocked stage: title, briefing, clay "Enter the challenge" button resolving the challenge's `vuln.link` from the injected registry, falling back to `/<moduleId>`.
3. Locked stage: lock orb, title, "Complete the previous stage to unlock". No link, no briefing leaked.
4. Completion: when all stage flags are captured and the scenario flag is not yet captured, `award(req, 'scenario', sc.id)` fires once and `flagBanner` renders at the top of the scenario page. Revisits re-render the banner from `flagFor('scenario', sc.id)` (read from the seeded flags row, never re-awarded).
5. Unknown scenario id returns the styled 404.

### Tests

| File | Status |
|---|---|
| `tests/scenarios-api.test.js` | green (2026-10-19, 32 tests total across the four scenario suites, all pass) |
| `tests/scenarios-shop.test.js` | green |
| `tests/scenarios-ghost.test.js` | green (delivered by test authors, real end-to-end exploit chain) |
| `tests/scenarios-edge.test.js` | green (unlock edge cases: out-of-order completion, fresh-session isolation, unknown-id 404, revisit banner, locked-stage view-source) |
| `tests/platform.test.js` | run green after wiring (see infra lead report) |

### Page copy

Checked 2026-10-19 (fixer pass): the `/scenarios` index page explains what a
kill chain is for a newcomer ("Real attacks are chains, not single bugs")
and states the staged-unlock rule ("Stages unlock one at a time: capture
the previous stage's flag to open the next") plus how the scenario flag is
earned ("Finish every stage to earn the scenario flag"). Each scenario page
now carries a "How the scenario flag is earned" line under the tagline, so
the rule is visible before the first stage, not only after completion.
Stage blocks render with `id="stage-N"` anchors, a contract the scenario
tests rely on. No em dashes anywhere in the scenario copy.

### Next actions

1. Screenshot pass on the three shipped scenarios.

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
