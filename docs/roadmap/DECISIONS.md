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

## D18. Flag storage location is never disclosed in public materials (owner doctrine)

Decision (2026-10-20, owner instruction): no public material (README, docs,
website, presentations, videos, social posts) may say where or how flags are
stored. The only permitted statements: flags are randomly generated per
install at first boot on the student's own machine, no flag literal exists
in any tracked file, and only genuine exploits earn flags. This extends FLAG
SECRECY: even naming the storage mechanism is a spoiler, because it tells
people to go dig in the database instead of hacking the challenges.

## D19. Student-review improvement wave: evidence-gated awards, per-session state, guest-realm sandboxes (2026-10-20)

Decision (2026-10-20): the findings of the 6-expert audit and the 50-student
review wave (docs/roadmap/STUDENT_REVIEW_BACKLOG.md) were implemented in one
wave, verified by a 12-student retest (52/52 fixed and fair) and an
independent supervision gate (docs/audit/RETEST_REPORT.md,
docs/audit/SUPERVISION_REPORT.md). Standing rules adopted from that wave:

1. **Evidence-gated awards.** No flag may be awarded for a marker string,
   a scraped token, a file's mere presence, or a request's mere shape.
   Every award must verify evidence that only the genuine exploit produces
   (entity resolution, cross-site evidence, per-challenge derived targets,
   execution proofs against the stored artifact, per-boot seals, one-time
   proofs). Adversarial negative tests (the old cheat, attempted verbatim)
   are required coverage for every award change.
2. **Per-session state by default.** Challenge state that a student can
   mutate (race state, pollution state, roles, credentials, caches,
   exports) is scoped to the session. One student's actions must never
   change another student's lab. Process-global state is reserved for
   mechanics that are intentionally shared, and must be documented as such.
3. **Guest-realm sandboxes.** Any code that executes attacker-controlled
   scripts or templates in a Node `vm` context (the simulated-victim
   runners, the fix-mode runner) must build every helper inside the guest
   context from guest-realm intrinsics, exactly like lib/fix-worker.js.
   No host-realm object, function, or class may be reachable from guest
   code. This is a hard security boundary: the lab itself must not be
   exploitable through its own simulation machinery.
4. **Honest tooling claims.** Guidance may only promise what Burp Suite
   Community can actually do (D17); brute-force spaces must be walkable in
   minutes with Community Intruder, and claimed timings must be measured,
   not asserted.


## D20. Page-token beacons: the accepted bar, and what counts as execution proof (2026-10-20)

Decision (2026-10-20): the XOR-share page token in lib/jstoken.js is
accepted at the bar stated in its header, no higher. The bar is: the raw
token never appears in served HTML or feed bodies; a verbatim scraped
share, a guessed token, and a bare beacon with no page or feed load are
rejected; tokens stay per-session, per-vuln and single-use, as enforced by
the modules' nonce stores. Accepted residual, verified live on
2026-10-20 against xss reflected, csti basic and jsonp callback-xss: a
client that fetches the page or feed with a valid session and recomputes
the token from the two served shares outside any JavaScript execution (the
supervision reviewer's Python recombine, reproduced by stream P1D before
and after this decision) produces a beacon the server accepts. That is
not a defect against the stated bar and must not be described, in code
comments, docs, hints or solutions, as proof that JavaScript executed in
a page. Standing rules:

1. Any deterministic computation the browser performs from served material
   can be emulated off-browser, in any language, by anyone who can fetch
   that material. Obfuscating, re-encoding, encrypting with a served key,
   splitting into more shares, or moving part of the same computation
   behind another served endpoint raises the reimplementation effort only
   and is theatre if presented as an execution bar. Do not ship it as a
   fix for this residual.
2. Execution proof for a future challenge requires one of: (a) the
   victim-bound model, where the award secret never leaves the server for
   the claimant and the award flows through a server-driven victim context
   (the stored and upload model), or (b) evidence the server can verify
   independently of any value derivable from served material, or (c) a
   platform attestation mechanism, adopted deliberately and documented
   with its browser and simulator costs. All three are module or app level
   changes; none can be delivered inside a token formatting helper.
3. Raising a specific page-token challenge above this bar means
   redesigning that challenge under rule 2, scoped and tested as its own
   change, with adversarial negatives for the Python recombine attack.
   Until such a redesign is approved, the recombine residual stays open
   and documented here and in lib/jstoken.js.

Alternatives considered:

- Per-page-load rotating material (fresh shares, longer tokens, more
  shares, alternative encodings, Shamir style splits with all shares
  served): rejected as theatre. tokenShares already re-randomises the
  shares on every call; the recombine attacker fetches the same fresh page
  in the same session and applies the same inverse. Rotation of the
  underlying nonce belongs to the modules, and would not change this
  either: the fresh token is still fully determined by the fresh served
  shares.
- Split delivery, where part of the material arrives only via a separate
  script endpoint, fetch call, or second channel: rejected, and also not
  contained in lib/jstoken.js (it needs a new route and consumer changes).
  The endpoint is reachable with the same freely issued session cookie, so
  the attacker makes two requests instead of one and recomputes as before.
  Any header or fetch-metadata check on such an endpoint is set by the
  client and can be copied by the same client, and the check would live in
  the endpoint, not the helper.
- Page-context evidence on the beacon (DOM state, browser properties,
  timing, fingerprints, interaction flags): rejected, and not contained
  in lib/jstoken.js (beacon validation lives in the module routers, which
  this helper never sees; the helper receives only a token string and
  returns strings). Every such value is either served to the attacker,
  chosen by the attacker and merely echoed, or unverifiable by the server
  independently. It would also break legitimate contexts the lab supports:
  payloads executing on an attacker page (JSONP), in an isolated SVG
  document, and in the Node vm browser simulator used by the test suite.
- Proof of work or deliberate slowdowns on recombination: rejected. It
  taxes the honest browser and the emulator equally, proves nothing about
  where the computation ran, and its enforcement would again live in the
  modules, not the helper.
- Non-extractable WebCrypto keys or browser attestation as the helper's
  mechanism: rejected for this scope. There is no key enrollment or
  verification endpoint for the server to trust, the mechanism is
  unavailable in the vm simulator, the SVG document and the cross-origin
  JSONP contexts, and adopting it is an app level platform decision, not
  a helper change.
- Converting the affected challenges (xss reflected, csti basic and the
  other page-token labs, jsonp callback-xss and its siblings) to the
  victim-bound model: not rejected on merit; it is the one direction that
  genuinely removes the residual. It is deferred as a product decision
  because it changes what those challenges teach and how they are solved
  (several are deliberately same-page, self-execution labs where there is
  no distinct victim), and it requires per-challenge redesign in the
  module files, outside the lib/jstoken.js scope of this evaluation.

Rationale: the helper's API is a pure, stateless transform: a token string
in, share arrays and combine expressions out. It holds no server secret
beyond the token it is asked to split (and that token is, by construction,
fully encoded in the served shares), keeps no issuance record, registers
no endpoint, and never sees a beacon request. Information-theoretically,
no change inside that boundary can distinguish a token recomputed in
Python from one recomputed by the page's own script, because the beacon
endpoint receives the identical value either way. The honest options are
therefore exactly two: state the bar precisely and accept the residual, or
redesign the challenge at module level under rule 2. This decision takes
the first option and keeps the second available per challenge. The
verbatim-scrape cheat that motivated the shares stays dead, and
victim-bound challenges are unaffected. Honesty about what acceptance
means: for the sampled challenges the recombine path needed no payload
and no in-page execution at all. The Python reproduction loaded the plain
challenge page or feed, recomputed the token, and submitted it with the
documented beacon parameters (for csti basic, the taught result value),
and the award followed. So for page-token challenges the token is, in
practice, the server-side award gate, and this decision accepts that a
determined student who reimplements the served computation can pass that
gate without the intended in-page step. Anything stricter requires
rule 2.

## Evidence recorded by stream P1D (2026-10-20)

- Consumers pinned: lib/jstoken.js exports tokenShares, tokenScriptParts,
  tokenShareParams, combineHexShares, COMBINE_FROM_SEARCH_JS,
  COMBINE_HEX_JS, djb2Hex and DJB2_JS. Consumers are modules/xss/shared.js
  and modules/xss/challenges/xss-svg-upload.js, modules/csti (basic,
  filter-bypass, constructor, attr, stored, and index.js for djb2Hex),
  modules/jsonp/shared.js, modules/jsonp/challenges/array-hijack.js and
  modules/jsonp/challenges/csrf-data.js, and modules/postmsg/shared.js and
  modules/postmsg/challenges/wildcard.js. No consumer passes a request,
  session, or validator into the helper.
- Existing negative tests cover only the verbatim bar: tests/xss.test.js
  ("collector: scraped shares cannot forge a beacon token"),
  tests/csti.test.js (basic: scraped share arrays are not usable as the
  token) and tests/jsonp.test.js (callback-xss: scraped shares earn
  nothing). None previously asserted anything about recombined tokens.
- Reproduction, before the header correction: lab booted on
  PORT=19604 with a throwaway database; a Python script using only
  urllib (no JavaScript anywhere) fetched each page or feed, XORed the
  two served shares in Python, and submitted the forged beacon.
  xss reflected: HTTP 200, captured true. csti basic: HTTP 200, captured
  true. jsonp callback-xss: HTTP 200. After the header correction (a
  comment-only change, behaviour intentionally unchanged) the identical
  script returned the identical results; see the stream report.
- lib/jstoken.js header (and the djb2Hex comment) corrected in the working
  tree to state the bar above precisely, including removing the earlier
  wording that the value "has to be produced by executing the page's
  script" and that the djb2 proof is one "only code executing in the page
  can produce".
