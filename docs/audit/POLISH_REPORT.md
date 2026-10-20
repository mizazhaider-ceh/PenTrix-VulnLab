# PenTrix-VulnLab Polish Wave Report

Date: 2026-10-20. Method: same multi-layer verification as the improvement
wave: builders, UI/UX expert teams, 12 fresh student retesters, senior
supervision (pentest reviewer, code reviewer, QA). All work in the working
tree, nothing pushed. Zero em dashes in every changed file, D18 clean
throughout (no flag literals, no flag-storage disclosure anywhere in the
diff or the audit docs).

## P1. Code residuals

### P1A. Duplicate flag banners during parallel bursts: fixed

Duplicate banners could render cosmetically during one parallel burst
(counts were always correct). Fixed centrally in lib/flags.js with a
synchronous check-and-set firstness record (session snapshot plus a fresh
store read plus an in-memory claim registry, hourly swept, unref'd timer),
lib/request-context.js (firstness record plus claimBannerRender), and
lib/page.js flagBanner (suppresses duplicate renders; flagFor displays still
render; JSON/header flag call sites unchanged). No module files edited.

Three existing test assertions were updated to the banner-once spec
(auth brute-force repeat, lfi log-poison repeat, hostheader X-Host-Override
moved to a fresh session). Both the pentest reviewer (live 9/9) and the code
reviewer judged these strictly stronger, not weakened: the hostheader
variant now genuinely proves the variant awards instead of piggybacking a
same-session capture.

Tests: new tests/polish-banner-once.test.js, 4/4. Full suite green.

### P1B. Upload quota: per-session accounting

Replaced the global newest-200 sweep with strict per-session accounting in
modules/upload/shared.js (ownership buckets via lib/session-state, claim
counts, trackStoredUpload, MAX_KEPT_UPLOADS_PER_SESSION=200). Every
direct-root store path calls trackStoredUpload; the traverse escape path is
correctly excluded. Cross-session eviction is impossible: session A flooding
205 uploads trims only its own oldest files, session B's stored file keeps
serving and its beacon still awards (verified live by the pentest reviewer
and the retest team). Deliberate open choice, documented in code: restart
orphans are not swept at boot.

Tests: new tests/polish-upload-quota.test.js, 1/1, plus 22/22 and 9/9
isolation runs.

### P1C. postmsg csrf-action: tightened

Evaluated and tightened. The csrf crossSiteEvidence gate was rejected: the
genuine flow is same-origin at the HTTP layer, so the gate would break the
real exploit and is forgeable anyway. Instead the award is now bound to the
module's page-bound token (shared.js pmNonceScript): only token-presenting
deletes set pm_msg_deleted, and the beacon requires the single-use token
plus both deletion flags. A bare curl delete plus beacon now returns 400
(also with forged foreign headers); the genuine flow, executed in a Node vm
against the live page, awards; token replay does not double-award. No D20
needed from P1C.

Tests: tests/postmsg.test.js rewritten, 13/13 green with six new
adversarial negatives.

### P1D. lib/jstoken.js XOR-share recombine: documented, not fake-fixed

Verdict 3b. Reproduced the Python-only XOR recombine before and after:
identical by design. Raising the bar inside a token-formatting helper would
be theatre (any deterministic browser computation from served material can
be reimplemented off-browser). The header comment was rewritten to state the
bar precisely (it also corrected the false "only code executing in the
page" claim). Recorded as doctrine D20 in docs/roadmap/DECISIONS.md: the
accepted bar, the accepted residual, and the three routes by which a future
challenge could genuinely prove execution (victim-bound model,
server-verifiable evidence, or platform attestation). 48/48 consumer tests
green.

## P2. Content polish

### P2A. SOLUTIONS.md sqli rewrite

The sqli section was fully rewritten to the new per-challenge derived
targets (sqli_target() blind oracles, order-by submit box, wildcard,
group-by, filter bypass, insert), with Burp Intruder plus Grep-Match
workflows and zero curl mentions in the sqli section. Programmatic check:
201 registry entries match 201 SOLUTIONS entries; all 310 routes exist
except 2 that are correct as written. Stale flows fixed in csrf, xss, csti,
jsonp, upload, race, api, ssti, xxe, idor. 16 scaffolding trailers stripped.

### P2B/C/D. Spoiler pass plus time estimates, all 29 modules

De-spoilered module cards and briefings for every module (the improvement
wave had only fully done XXE): no card, briefing, or pre-filled sample
reveals the payload, the flag-pattern location, or the solve. Removed: the
cmdi wildcard's complete working payload, the csti constructor's printed
payload, the cors prove-form pre-filled winning origins, the ssrf module
index's 11 ready-made bypass URLs, the ssti variable-name giveaway, the xxe
collector starter DTD. Corrected: the oauth code-leak hint 3, the
hostheader "six labs" (there are five), the race $100/$0.00 text, and stale
modules/ssti/router.js comments in all six ssti-adjacent files. Added an
honest typical-time line to every briefing (59 estimates in set 3 alone,
all three sets covered). 213 + 109 + 105 module tests green; drift checks
green.

Retest fairness verdict (teams B and C, 107 challenges re-solved honestly):
all modules fair, nothing essential removed; time estimates mostly just
right.

Doc bugs found by retest and fixed by the coordinator, verified live:
- F1: the ssrf open-redirect flow prescribed 127.0.0.1 as the initial URL
  host, which fetch3's initial-host blocklist rejects with 403. Fixed to
  `localhost` for the initial `/ssrf/jump` URL (the redirect target keeps
  127.0.0.1, which is the blocked host being smuggled to). The repo's own
  test suite uses exactly this shape. The ssrf-redirect in-app hint 3 was
  updated to match.
- F2: the sqli error-based entry claimed "a bad function call" earns the
  flag, but the award regex does not match "no such function". Doc and the
  error.js hints/`how` now say a wrong-argument function call (e.g.
  substr(1)) or malformed JSON; `badfunc(1)` shows an error but earns
  nothing.
- The jwt alg-confusion PEM extraction regex was stale
  (`/<pre>([\s\S]*?)<\/pre>/` vs the `<pre class="payload-body">` the page
  renders). One-line fix, verified against the live page.
- The cmdi de-spoiler had over-corrected: three hints (cmdi-newline,
  cmdi-ifs, cmdi-braces) said "the second command's real output" while the
  evidence gate requires passwd lines specifically. Restored the precise
  wording ("passwd file lines show up... output from other commands proves
  execution, but it is not the evidence this gadget checks for") without
  reinstating the exact command.

## P3. UI/UX expert pass

### UI design expert team

Rendered and viewed lab and website at 1280px and 390px (Playwright),
computed-style checks, console errors, contrast (WCAG AA), touch targets.
Findings fixed:
- S1: hero carve-out so the lab hero renders on first paint (was blank under
  the JS reveal gate); safety net kept. First-paint screenshots prove it.
- S2: focus-ring transition fixed.
- S3/S4: spacing and alignment fixes across module indexes and challenge
  pages.
- F1-F11: illegible badge link (1.5:1) fixed; orb/progress/flag gradients
  re-colored to 3.77:1+; focus rings to 3.66:1; OAuth mobile overflow;
  card-top flex bug; website kicker/link-hover/focus contrast; sub-44px
  touch targets across both surfaces; print stylesheet reveal rule;
  difficulty-pill CSS awaiting data-level hooks.

Follow-up markup cleanup (N1-N9), all verified with screenshots:
- N1: OAuth quick-login chips are tappable chips (also applied to the
  client.js and idp.js sub-pages); api, csrf, idor already used chips.
- N2: fixSection card nesting flattened to one .clay-card per fix entry with
  the challenge name as h3.
- N3: scenario stage grid no longer stretches locked cards (authorized
  `.grid.stages{align-items:start}` rule).
- N4: setup guide has exactly one h1; TOC renders as `<ul class="toc">`
  with 44px+ link rows on mobile.
- N5: breadcrumb styling (muted links, ink/bold current, 44px rows mobile).
- N6: mid-sentence buttons in oauth challenge steps moved to their own
  paragraphs.
- N7: all 29 website difficulty pills carry data-level (7 beginner, 18
  intermediate, 4 advanced) and the pill-difficulty class the CSS hooks on.
- N8: the "565 tests" badge is a real link matching the other cards.
- N9: terminal widget dead black space removed (double padding), mobile
  font 13.6px with wrapping, typing animation intact.

50 UI evidence screenshots in docs/audit/polish-shots/ui/.

### UX expert team

Fixed: search focus landing, search live-region announcements, lab skip-link
focus (tabindex=-1), upload input label plus live error regions plus clearer
copy, copy-button aria-labels ("Copy flag", "Copy payload pattern"), hint
"(click to reveal)" to "(show)". Keyboard walks and mobile menu focus
verified; zero lab console errors. 74 UX evidence screenshots in
docs/audit/polish-shots/ux/.

Follow-ups completed in-stream:
- Breadcrumbs: central placeholder in lib/page.js page() plus app.js chrome
  middleware; 76/76 HTML pages pass the crawl (0/77 before); scenario/path
  linked crumbs; back-links.
- Count-up: root cause was the static 29/201 painting then being overwritten
  by the animation's first frame (24/169 were ease-out intermediates, not
  targets). Fixed: reset to 0 at init, per-element state guards, 2500ms
  fallback, reduced-motion/no-JS unchanged; verified monotonic at both
  widths and second-load immune.
- Filter live regions announced in-browser; 89 + 90 tests green.

**Blocking bug found by the code reviewer during verification (fixed):** the
breadcrumb chrome middleware interpolated `'/scenarios/' + segments[1]` and
`'/paths/' + segments[1]` unescaped into `<a href>`, a reflected XSS sink on
404 pages (empirically confirmed by the reviewer). Fixed with esc() on both
hrefs and verified live with the reviewer's PoC: raw quotes now render as
`&quot;`. Browser exploitability was limited (browsers percent-encode the
quote), but new chrome code must not ship a sink.

## P4. Contract tidy

MODULE_CONTRACT.md gained the "Module-level endpoint files" section (rules
a-e): module-level endpoint files are blessed, with the rule that award
logic conditions stay identical to the challenge files they serve. This
resolves the supervision MINOR on record. The missing challenge-naming
headers on modules/oauth/idp.js and client.js were added.

## Retest verdicts (12 fresh students, 4 teams)

- **Team A (P1):** all 8 upload challenges honestly solved; old cheats fail
  (one-byte .html, two-challenge one-POST). postmsg: genuine vm flow awards,
  bare curl plus forged headers do not. All 5 race challenges solved via
  bursts; 20-request burst renders exactly one banner with exactly one
  capture; repeat shows no banner; second challenge shows its own banner;
  captured flag stays viewable. XXE marker cheat, LFI bare-percent cheat
  still dead. POLISH_RETEST_A.md.
- **Team B (SOLUTIONS flows):** 44/44 solved: sqli 11/11 (real extraction
  scripts for all three blind oracles), xss 9/9, ssrf 9/9, cmdi 9/9, cors
  6/6. Spoiler check: no card/briefing gives away a payload. Time estimates
  mostly just right. Filed the F1/F2 doc bugs (fixed). POLISH_RETEST_B.md.
- **Team C (de-spoilered modules):** 63/63 solved: oauth 8, proto 6,
  misconfig 10, crypto 8 (real attack code: PIN brute force, ECB oracle,
  CBC bit-flip, SHA-256 length extension, MD5 crack, XOR crib-drag), jwt 8,
  api 5, auth 8, session 6, redos 4. Two improvement-wave cheats confirmed
  dead. All 9 modules fair; nothing essential removed. Filed the PEM regex
  doc bug (fixed). POLISH_RETEST_C.md.
- **Team D (UX):** 14/14 PASS, no P3 regression. Hero renders on first
  paint; breadcrumbs work on 10 challenge pages; keyboard Tab order logical
  with visible focus; website search opens on `/` with focus in the input
  and arrow-key navigation; count-up rises monotonically 0 to 29/201/3/3
  with no restart; filter live regions announce no-match text on home and
  scoreboard; copy buttons copy payload and flag text; skip link moves
  focus to main; upload empty-state has labeled input and spoken error
  copy; mobile 390px: no blank gaps, no horizontal overflow, all tap
  targets 44px+, terminal demo readable at 13.6px with wrapping, full
  honest solve of an Easy challenge usable on mobile. Verdict: the P3
  stream is ready to ship. POLISH_RETEST_D.md. (Note: the port-19704 lab
  server died twice mid-test from box load, infrastructure only.)

## Supervision gate

- **Pentest reviewer: PASS (38/38 live checks).** postmsg tightening both
  directions (7/7), banner-once (8/8), upload quota isolation (6/6), 4
  original-cheat spot-checks (8/8), P1A test updates judged HONEST (9/9).
  No blockers.
- **Code reviewer: FIX FIRST, then verified fixed.** One blocking item: the
  reflected XSS in the breadcrumb href (fixed and verified, see P3). Three
  MINORs fixed: request-context.js comment over-claim, redundant aria-label
  on the flag copy button, cmdi passwd-evidence hint precision. D18 clean,
  em-dash clean (228 lab files plus 6 website files), no test gaming, FLAG
  BAR intact (the only award-logic delta is a tightening).
- **QA: SHIP.** node --check sweep: 225 lab JS files plus website JS, zero
  failures. Full suite: 572/572, 0 fail (baseline 565, +7 new). Boot check:
  29/29 modules mounted, 204 flags, zero error lines, all probes 200. The 4
  flaky cmdi subtests seen in earlier loaded runs were classified as
  parallel-state artifacts (pass 12/12 alone, final full run green under
  normal load). The coordinator re-ran the full suite on the final tree
  (result below).

## Test counts

- Coordinator full-suite run on the final tree: 572 tests, 24 suites, 572
  pass, 0 fail, 0 skipped (189s, exit 0). This run includes the XSS-sink
  fix, the cmdi hint precision fixes, and all retest doc fixes.
- QA full-suite run: 572 tests, 24 suites, 572 pass, 0 fail.
- New/updated test files: polish-banner-once.test.js 4/4,
  polish-upload-quota.test.js 1/1, postmsg.test.js 13/13.
- Website: no JS test suite; verified via Playwright (count-up monotonic,
  search keyboard walk, terminal demo, pill hooks).

## Open items and follow-ups

- Deliberate open choices (documented): P1B restart-orphan sweep; the xxe
  file-read hint relative path (test-mandated); proto-client/constructor/dos
  header comments name payload shapes (code comments only); P1A test updates
  flagged for supervision (judged honest).
- The website repo carries this wave's UI/CSS/JS changes uncommitted (parent
  flow pushes both repos).
- The v4 PORCELAIN deck stats predate the wave (says 490 tests); current
  count is 572.
