# DECISIONS: PenTrix VulnLab transformation

Date: 2026-10-19. Records key Phase One decisions, alternatives considered,
and tradeoffs. New decisions get appended with dates; nothing here is
rewritten silently.

## D1. Keep the Express 4 plus server-rendered template-string stack

Decision: no framework migration, no view engine, no ORM, no Redis.
Alternatives considered: Next.js/React rebuild, EJS or Pug templates,
Sequelize or Prisma, Redis-backed sessions. Rejected: a migration would
break the module contract, add a build step, and force 29 modules to be
rewritten for no lab-engine gain. The current stack is simple, readable,
and sufficient; the assessment found the problem is thinness (duplicated
HTML patterns, no shared components), not wrongness. Fix thinness with
shared helpers, not a new stack.

## D2. 235 is the authoritative challenge count

Decision: treat 235 as correct everywhere. Alternatives: none, this is a
correction. Two independent verifications (node probe summing
`vulns.length`, live scoreboard) agree; the Phase Zero 244 was a hint-grep
overcount (lfi has 10 vulns, not 20). Phase Zero docs corrected; README was
right all along.

## D3. Verification integrity before curriculum expansion

Decision: Milestone 5 (challenge verification integrity) precedes
Milestone 7 (curriculum improvements). Rationale: several awards are not
proof of exploitation (beacon curls, input-pattern matches, one
award-on-visit Rule 2 violation). Expanding or reordering labs on top of
unverifiable awards would cement the weakness. Fix the trust model first,
then dedupe, then paths.

## D4. Dedupe before learning paths

Decision: the 16 exact-concept duplicates (~35 redundant challenges) are
removed or merged before paths are authored. Rationale: paths over a
duplicated catalog teach the same lesson twice and waste the path
designer's ordering work.

## D5. Adopt better-web-ui selectively, staged for approval

Decision: recommend `aladicf/better-web-ui`, subset only (`setup`,
`add-ui`, `critique`, `audit`), install command staged, nothing installed
in Phase One. Alternatives: JustineBijuPaul/frontend-ai-skills (rejected:
React/Next/GSAP/Three.js bulk, one-day snapshot, 1 star; a 4-skill subset
is staged only if the owner overrides), OpaceDigitalAgency/ai-ui-ux-motion-engine
(rejected: marketing-site/cinematic genre mismatch for a functional
training app), hueyexe/frontend-agent-skills (optional second pick: three
UX skills only). All are markdown guidance with zero runtime or build
impact, which is why any of them are acceptable at all.

## D6. Aceternity UI rejected for this stack

Decision: do not adopt Aceternity UI components. It is a React plus
Tailwind plus Motion copy-paste library, not an agent skill; adopting it
requires a React renderer and a Tailwind build step, contradicting D1.
Borrow its entrance patterns as CSS primitives instead (documented in the
motion system).

## D7. Motion: CSS plus View Transitions plus IntersectionObserver

Decision: no animation library for the core transformation. Alternatives:
GSAP plus ScrollTrigger (verified free since 3.13, kept as the documented
bench upgrade path if scroll-choreographed explainers are ever added),
Motion for React (rejected: assumes React), Lenis smooth scroll (rejected:
fights the precision-instrument feel, adds a permanent rAF loop for zero
lab benefit). All motion is transform/opacity only, max 400ms, with a full
reduced-motion path.

## D8. Light-first theme strategy

Decision: ship "Lab Paper" (light) as the default theme, "Bench Dark" as
secondary. Rationale: light themes render code and tables better for long
study sessions and report screenshots; light-first forces accessible
contrast by default; the banned cliche is specifically neon-green-on-black,
so the dark theme must be designed deliberately, not inherited. All palette
pairs pre-checked to WCAG AA (5.06 to 15.42:1).

## D9. Branches and PRs; never force-push main; no push before review

Decision (owner-authorized 2026-10-19, his words: "you can push, no
worries"): all work lands on branches with pull requests for review.
Nothing is pushed until the owner reviews the Phase One docs. Main is
never force-pushed. Rationale: the transformation touches a working lab;
review gates keep it recoverable.

## D10. Visual verification via the WeasyPrint pipeline; no public URL, ever

Decision: every UI change is verified with `docs/qa/screenshot.sh`
(curl page, inline CSS, WeasyPrint to PDF, pdftoppm to PNG) and renders
are attached for review. Meta Chromium on the VM blocks localhost, so
this is the pipeline. The lab is intentionally vulnerable and the owner's
own directive forbids public exposure; no public URL will ever be used
for "convenient" visual review.

## D11. Balance rule: lab engine carries equal weight to design

Decision (owner's rule, 2026-10-19): visual quality is half the project.
Target isolation, challenge verification, reset behavior, learning
outcomes, and realistic tool usage matter equally. The milestone plan
alternates design and lab-engine milestones deliberately; verification
integrity (M5) and reset/isolation (M8) are first-class milestones, not
stretch goals.

## D12. Mystery references unresolved; ask the owner for URLs

Decision: "Animaster Leap" and "Hipa UI" could not be verified (no repos,
sites, or registry entries found; closest guesses are Animmaster Lib, a
component library, and a phonetic guess at HyperUI/shadcn, neither
confirmed). Do nothing with these names until the owner supplies URLs.
Recorded plainly rather than guessed.

## D13. better-sqlite3 stays pinned for the Docker target

Decision: the repo keeps better-sqlite3 v11 (correct for its Node 20
Docker target). The v12 swap exists only in the throwaway verify copy for
the Node 24 VM. A v12 bump is a tested, separate decision for later, not
drive-by scope creep.

## D14. Per-student isolation as documented reference, not default

Decision: the default stays a single local container (bound to localhost,
M3 hardening). The per-student deployment sketch (one bridge-networked
container per student, per-student volume, dropped capabilities, resource
limits) is published as reference documentation for classroom use, not
imposed on the solo-learner default. Rationale: complexity must match the
deployment; the sketch exists so a teacher does not improvise isolation.

## D15. Design direction changed to High-Fidelity Claymorphism (owner instruction)

Decision (2026-10-19, owner's explicit choice: "a very best one", with a
full claymorphism spec and uiverse.io named as component inspiration):
the visual direction is now High-Fidelity Claymorphism ("digital clay"),
replacing the "Precision Instrument" / Lab Paper direction from Phase One.
Design brief and motion system rewritten accordingly
(docs/design/DESIGN_BRIEF.md, docs/design/MOTION_SYSTEM.md).
Alternatives considered: keep the Precision Instrument direction (rejected:
the owner explicitly chose clay); a dark clay variant (rejected: the
shadow stacks only read on a pale canvas, and the owner prefers light
themes, so the system is light-only). uiverse.io
(https://uiverse.io, open-source CSS UI elements) is adopted as
inspiration only: browse, hand-port the CSS into the clay token system,
never paste Tailwind classes or vendor snippets (the project has no
Tailwind and no build step; see DESIGN_BRIEF.md section 8).
Tradeoffs, stated honestly: a playful toy-like aesthetic sits in tension
with a serious security-training tool. Mitigation is placement, not
dilution: playfulness lives in the shell (cards, buttons, blobs, the
flag-capture moment) while challenge pages stay clear, high-contrast, and
restrained (see MOTION_SYSTEM.md section 5). The lab-engine half of the
project (D11) is unaffected by this change.

## D16. Challenge catalog is 201 after dedupe (owner decision, supersedes D2)

Decision (2026-10-19, owner confirmed: KEEP 201): the M7 curriculum pass
removed 34 duplicate or near-duplicate challenges (235 to 201), every one
documented in docs/curriculum/LAB_QUALITY_MATRIX.md. D2 ("235 is the
authoritative challenge count") is superseded but kept as a historical
record, as are the 235 figures in docs/audit/* and the design briefs.
README, its diagrams, the demo cheat sheet, and SOLUTIONS.md were updated
to 201 (pushed as 5442473). Live code never hardcoded the count; the
scoreboard computes it from the module registry (verified: 0 / 201).
Per-module counts are recorded in PROGRESS.md.

## D17. Burp Suite is the lab's first-class tool (owner doctrine)

Decision (2026-10-19, owner instruction): every one of the 201 challenges
must be fully solvable through the standard Burp Suite workflow (Proxy
intercept, Repeater, Intruder, with Community edition sufficient unless a
challenge note says otherwise). The lab's voice now very highly recommends
industry-standard tools over raw bash/curl: Burp Suite first, then OWASP
ZAP, sqlmap, ffuf/gobuster, nmap where each fits. curl one-liners stop
being the default; challenge `start` fields and hint ladders name the Burp
step instead. Rationale: students learn the tooling real pentesters use,
and proxy-based testing is the industry default for web work. The
per-challenge HTTP tests already prove Burp solvability (Burp is only a
proxy), so the existing suite stays the verification backbone. FLAG BAR
(D-decisions on genuine multi-step exploitation) and FLAG SECRECY are
unchanged: Burp-first must never mean easier flags.
