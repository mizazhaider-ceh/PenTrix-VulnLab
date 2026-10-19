# IMPLEMENTATION PLAN: PenTrix VulnLab transformation

Date: 2026-10-19. Status: Phase One complete, awaiting owner review before any
code changes, skill installs, or pushes.

This plan integrates four Phase One tracks: architecture assessment
(`ARCHITECTURE_ASSESSMENT.md`), lab quality matrix
(`docs/curriculum/LAB_QUALITY_MATRIX.md`), design brief plus motion system
(`docs/design/`), and skills plus platform research (`docs/research/`).
It follows the directive's milestone structure, rebalanced per izaz's rule:
visual quality is half the project, the lab engine (isolation, challenge
verification, reset behavior, learning outcomes, realistic tool usage) is the
other half. Milestones below alternate between the two halves deliberately.

Standing constraints for every milestone:
- Docs and code land on branches with pull requests for review. Never
  force-push main. Nothing is pushed until the owner reviews the Phase One
  docs (this plan included).
- The app is intentionally vulnerable. It is never exposed beyond localhost,
  never given a public URL. Live testing targets the VM instance only.
- The module loader contract (`{id, name, tagline, description, difficulty,
  vulns[], router}`) stays stable. No new npm dependencies for module code,
  no build step, no framework migration.
- Every UI change is verified with `docs/qa/screenshot.sh` (curl to
  WeasyPrint to PNG); renders are attached for review. Motion states are
  reviewed as static frames plus the written spec.
- No em dashes in any file. Claims in docs tie to observed evidence.

## Milestone 1: Discovery and baseline (DONE)

Completed in Phase Zero and Phase One. Exit criteria met:
- `docs/audit/`: PROJECT_DISCOVERY.md, EXISTING_FEATURES.md,
  ARCHITECTURE_AND_RISKS.md, INITIAL_TEST_RESULTS.md (235-vuln correction
  applied in Phase One).
- Live instance verified on the VM; SQLi login bypass exploited end to end
  with session-persisted flag (the Rule 2 quality bar).
- `docs/qa/screenshot.sh` built and verified; baseline renders in
  `docs/qa/shots/`.

## Milestone 2: Research and design (DONE)

Completed in Phase One. Exit criteria met:
- Architecture assessment with ranked risks, tech debt, 11 minimal
  improvements, and compatibility surface documented.
- Lab quality matrix: all 29 modules, per-vuln verdicts (68% strong, 16%
  needs work, 2% shallow, 14% duplicate), 34 duplicates identified,
  top-10 improvement plan.
- Design brief ("Precision Instrument", Lab Paper light-first plus Bench
  Dark) and motion system (7 primitives, tokens, reduced-motion plan).
  NOTE (2026-10-19, D15): the owner replaced this direction with
  High-Fidelity Claymorphism (light-only); both docs were rewritten and the
  milestones below follow the clay system.
- Skills research (one selective recommendation, staged) and platform
  benchmark (14 adoptable principles).

## Milestone 3: Safety and compatibility groundwork (lab engine)

Goal: make the default deployment safe and the contract enforceable before
any feature work. Small, reversible changes only.

Work items:
1. Create `phase-one-audit` branch from a tagged `phase-zero-baseline`
   checkpoint. All later work branches from here.
2. Compose: bind `127.0.0.1:3000:3000` (reversible, documented). Add
   healthcheck, restart policy, and resource limits.
3. Session secret: read from env with a dev fallback; document that the
   committed secret must never be used for graded use.
4. Loader hardening: validate module `id` format and uniqueness at boot;
   reserve `scoreboard`, `about`, `uploads`; fail fast with a clear message.
5. Dockerfile: run as non-root (`USER node`), drop capabilities
   (`cap_drop: ALL` in compose), keep build tools out of the final image
   (multi-stage or documented tradeoff).
6. `.gitignore` the database properly; keep first-boot seeding as the
   canonical path.

Exit criteria: `docker compose` equivalent boots locally, binds localhost
only, healthcheck passes, duplicate or reserved module id fails boot with a
clear error, no module code changed.

## Milestone 4: Core experience shell (design)

Goal: the claymorphism shell around the existing labs. Server-rendered HTML
and vanilla CSS only, plus one small deferred enhancement script.

Work items:
1. Expand `public/style.css` with the clay token system from
   docs/design/DESIGN_BRIEF.md (`:root` custom properties: candy palette,
   the four shadow stacks, radii scale, Nunito plus DM Sans with system
   fallbacks). Keep it under ~25 KB unminified.
2. Extend `lib/page.js` helpers: difficulty pills, progress bars, empty
   states, copy buttons, briefing panel, flag capture banner
   (`role="status"`), styled 404/500 pages inside the template, floating
   blob container. Where uiverse.io elements inspire a treatment (copy
   buttons, toggles, loaders), hand-port the CSS into the clay tokens;
   never paste Tailwind classes or vendor snippets (see DESIGN_BRIEF.md
   section 8).
3. Home: clay module cards (numbered orb, title, tagline, difficulty pill,
   progress), bento rhythm mixing standard and wide hero cards, difficulty
   filter and text search (progressive enhancement), "start here"
   affordance, learning-path entry points (paths defined in Milestone 7,
   UI affordance first).
4. Scoreboard: clay cards per module with sticky section headers, captions
   and scopes where tables remain, icon-plus-text status, per-module
   progress, client-side filter with no-JS fallback, starter panel at
   0 flags.
5. Challenge pages: one clay form pattern (recessed inputs, squish
   buttons), labeled attacker input vs server output in recessed mono
   wells, copyable payload blocks, visible focus everywhere. Challenge
   pages stay restrained per MOTION_SYSTEM.md section 5: no entrance
   stagger, dimmed or omitted blobs.
6. Accessibility pass per the brief's acceptance criteria (computed
   contrast pairs in DESIGN_BRIEF.md 3.3 are the law); screenshots of
   every route attached for review.

Exit criteria: all routes render in the single light clay theme with zero
console errors, keyboard-only task completion works, contrast meets AA
per the pairs table, every page has a verified PNG render via
docs/qa/screenshot.sh, no module contract breakage.

## Milestone 5: Challenge verification integrity (lab engine)

Goal: every flag award must be proof of genuine multi-step exploitation,
per Rule 2 and the owner's reinforced bar: no flag may be obtainable
without real exploitation work. Obvious, trivially visible, or
single-click flags must be reworked into real challenges or removed.
This is the highest-value lab-engine work (curriculum priority 1).

Work items:
1. Fix the `csrf/clickjacking` award-on-visit violation: award only on
   server-observable exploit evidence.
2. Harden beacon-style awards (xss, postmsg, csti, jsonp): bind awards to
   per-session nonces or secrets so a crafted curl cannot claim flags
   without executing the payload.
3. Replace input-pattern awards (cmdi, jsonp) with output-evidence awards
   where the module can observe command output server-side.
4. Flag difficulty audit: walk all 235 challenges in the quality matrix
   and flag every award that is obtainable without multi-step work
   (visible-on-page flags, single-click captures, guessable submissions).
   Each one is either reworked into a real multi-step challenge or
   removed; the matrix Verdict column records the outcome per vuln.
5. Document the verification model per module in the quality matrix
   (what the server observes for each award).

Exit criteria: each changed award is re-exploited live to confirm the flag
still drops on real exploitation and does not drop on the trivial bypass;
the flag difficulty audit covers all 235 challenges with zero remaining
"obtainable without exploitation" awards; matrix validation and verdict
columns updated.

## Milestone 6: Motion and interaction (design)

Goal: implement the clay motion system without degrading usability or the
lab workflows.

Work items:
1. Implement animations A1-A9 from docs/design/MOTION_SYSTEM.md (blob
   float loops, breathe, hover lift, active squish, staggered delays,
   scale accents, capture pop) in CSS plus the single deferred
   enhancement script (under 5 KB). Shadow-stack swaps on press are part
   of the squish, not decoration.
2. Full `prefers-reduced-motion` path: all motion disabled, blobs frozen,
   state changes instant, observer reveals skipped.
3. Mobile fallbacks (2 blobs, halved travel, no stagger under 480px,
   touch carries feedback via squish).
4. Challenge-page restraint audit per MOTION_SYSTEM.md section 5: dimmed
   or omitted blobs, no entrance stagger on forms or output wells.

Exit criteria: acceptance checklist in MOTION_SYSTEM.md passes; with
reduced motion forced, no visible animation occurs; with JS disabled, all
tasks completable; no feedback animation exceeds 500ms; static-frame
review of the capture moment attached via docs/qa/screenshot.sh.

## Milestone 7: Curriculum improvements (lab engine, content)

Goal: fewer, better, honestly-ordered labs with remediation teaching.

Work items (in order):
1. Dedupe pass: remove or merge the 16 exact-concept duplicates first
   (cutting ~35 redundant challenges), per the matrix.
2. Rebuild `cors` as a real exploit module (attacker/victim page pairs).
3. Per-vuln "the fix" remediation panels post-capture, linking the
   relevant OWASP Cheat Sheet (benchmark principle from Juice Shop).
4. Progressive hint ladder (2-3 steps) replacing single near-answer
   hints; solutions revealed only after solve.
5. Learning paths with honest difficulty (replace `Mixed` with real
   tracks: Foundations, Injection, Auth and Sessions, Advanced) and
   explicit prerequisites; per-lab tool mapping (curl, Burp/ZAP, devtools,
   Python) from the matrix Tools column.
6. Difficulty-weighted scoring on the scoreboard.

Exit criteria: matrix verdicts re-checked after changes; every path is
traversable in order with stated prerequisites; hints never give the full
answer at step one; remediation panel present on every changed vuln; the
M5 flag difficulty audit is re-confirmed after the dedupe pass (no merged
or rebuilt challenge reintroduces a trivially obtainable flag).

## Milestone 8: Reset and isolation (lab engine)

Goal: predictable lab lifecycle and documented deployment boundaries.

Work items:
1. Per-lab reset: each module gets a reset control covering its state
   layer (DB rows, filesystem writes, in-memory maps); document the four
   state layers from the assessment.
2. Test the full-reset procedure end to end (DB delete plus reboot
   reseeds; uploads cleared; MemoryStore fresh).
3. Publish the reference per-student deployment sketch from the
   assessment (one bridge-networked container per student, per-student
   data volume, resource limits) as `docs/deployment/`.
4. Audit logging for lab lifecycle events (launch, reset, capture).

Exit criteria: reset tested live per module changed; full reset reproduces
a clean instance; deployment doc reviewed; no cross-student state leakage
in the reference sketch.

## Milestone 9: Integration and hardening

Goal: the whole product verified as one system.

Work items:
1. Regression sweep: curl every module index and a sample exploit per
   module after each prior milestone (scripted).
2. Fix console errors, failed requests, layout breaks at mobile widths.
3. Accessibility re-verification (keyboard, focus, contrast, reduced
   motion, screen-reader landmarks on changed pages).
4. Performance check: CSS budget, no layout shift on enhancement load,
   scoreboard paint time.
5. Security review of the platform shell (not the intentional lab vulns):
   authz on new controls, no secret leakage, no verbose errors.

Exit criteria: `docs/qa/FINAL_VERIFICATION_REPORT.md` complete with real
results; critical user journeys pass; known limitations listed honestly.

## Milestone 10: Final delivery

Goal: handover that izaz or a contributor can run and continue.

Deliverables:
1. Updated README (235 challenges, run instructions, reset procedure,
   troubleshooting, architecture overview).
2. `docs/roadmap/PROGRESS.md` final state; changelog of what changed per
   milestone.
3. Recovery instructions and the per-student deployment guide.
4. Pull request(s) to main for review; nothing merged without approval.

Exit criteria: a fresh clone can go from zero to running labs following
the README alone; every claim in the docs traces to a verified result.
