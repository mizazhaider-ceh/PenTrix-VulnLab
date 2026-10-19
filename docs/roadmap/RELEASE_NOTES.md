# Release Notes: PenTrix-VulnLab Transformation (2026-10-19)

This documents what changed between the pre-transformation baseline and the
current `main` state. Written for the repo owner, no marketing fluff.

## Headline

The platform was rebuilt from a 13-module, 34-challenge lab into a
29-module, 201-challenge training platform with a new UI shell, a flag
integrity model, and a per-challenge testing discipline. The challenge
split (one file per challenge, each with its own exploit test) is in
progress: 63 of 201 challenges are done on `main`; the rest are underway.

## What changed

### M3: Safety and compatibility groundwork
- Runtime and environment safeguards before anything else was built.
- Regression test suite (`tests/platform.test.js`, 10/10 passing in
  Docker/Node 20) plus a persistent SQLite session store
  (`lib/session-store.js`), so flags and sessions survive restarts.

### M5: Challenge verification integrity
- Exploit-verified flag awards. Flag routes now check that the award
  corresponds to a genuine exploit, not to knowledge of the answer.
- Per-deployment random flags: every install generates its own random
  `PENTRIX{<32 hex>}` flags at first boot, on your machine.
  No real flag literal exists in tracked files; flags cannot be derived
  from the source. `SOLUTIONS.md` teaches method, never lists flags.

### M4: Claymorphism experience shell
- High-fidelity claymorphism design system (light-only themes), Nunito and
  DM Sans type, hand-ported components, a module page standard where
  challenge pages feel like real small apps (shop, blog, login portal)
  instead of announcing the vulnerability.

### M6: Motion system
- Motion tokens, ambient keyframes, a reduced-motion path, mobile
  fallbacks, and page transitions, all spec'd against accessibility and
  performance acceptance criteria.

### M7: Curriculum pass (235 -> 201 challenges)
- Every module audited against its router code
  (`docs/curriculum/LAB_QUALITY_MATRIX.md`).
- 34 duplicates removed by owner decision (commit `5442473`), all counts
  updated in README, diagrams, cheat sheet, and `SOLUTIONS.md`.
- 3-level hint ladders per challenge, realism pass on challenge pages,
  learning paths added.
- XSS claim UX fix: beacon-based flags were failing silently for
  token-less requests, so challenge pages now show a visible "How to
  claim this flag" box with a live claim-status widget.

## Architecture: the challenge split

This is the main structural change, driven by the contract at
`docs/roadmap/CHALLENGE_SPLIT_CONTRACT.md`.

- Before: one `router.js` per module holding all challenges.
- After: `modules/<module>/challenges/<vulnId>.js`, one file per
  challenge, with a thin `index.js` aggregator per module.

### Verification story (per-challenge exploit tests)

Every split challenge ships with its own exploit test, written against
the real route. The tests have already caught real bugs that the split
commits fixed:

- `sqli`: a login-bypass challenge awarded the flag for valid admin
  credentials (should only award on an actual injection bypass).
- `idor`: a challenge leaked the admin secret and awarded flags to admin
  sessions (flag must only go to the intended exploit).
- `csrf`: a referer host check allowed wrong-host requests.
- `xss`: a dom-clobber challenge shared state across students.
- Wrong hint payloads that would never work.

### Split progress

8 of 29 modules are split, tested, and committed on `main`
(`3375613`): `api` (5), `sqli` (11), `xss` (9), `auth` (8), `idor` (7),
`csrf` (5), `cmdi` (9), `lfi` (9). That is 63 of 201 challenges.

21 modules remain (138 challenges), in this order: `ssrf`, `upload`,
`xxe`, `ssti`, `misconfig`, `jwt`, `session`, `race`, `bizlogic`,
`redirect`, `hostheader`, `cors`, `proto`, `crypto`, `oauth`, `postmsg`,
`csti`, `http`, `jsonp`, `formula`, `redos`.

## In progress (not on main yet)

### M11: Break-then-fix mode
- IN PROGRESS as of 2026-10-19. After capturing a flag, the student gets
  the vulnerable code and must patch it. A fix is accepted only when the
  exploit is blocked and legitimate use still works.
- Framework done in the working tree (not committed): `lib/fixmode.js`
  (sandboxed runner: `node:vm`, 2s timeout, 50KB cap, no `require`/`process`/file/network
  access), `lib/fixbadges.js` (fix badges in SQLite, keyed by session
  ID), fix UI in `lib/page.js` (`fixCta`, `fixEditorPage`,
  `fixResultHtml`, `fixBadgePill`).
- Pilot fix blocks done for `sqli` (11) and `xss` (9) at
  `modules/<module>/fixes/<vulnId>.js`, each with a reference solution
  and the four runner checks (block sanity, `vulnFn` defined, exploit
  blocked, legit use preserved). Other challenges show an honest
  "coming soon" note.
- The four fix-mode test files are not yet written (`tests/fixmode*.test.js`).

### Remaining split work
- The other 13 modules whose `router.js` files are deleted in the working
  tree (`ssrf`, `upload`, `xxe`, `ssti`, `misconfig`, `jwt`, `session`,
  `race`, `bizlogic`, `redirect`, `hostheader`, `cors`, `proto`, `csti`,
  `http`, `jsonp`) are mid-split and not committed yet.

## Known limitations (honest)

- No Docker daemon on the build VM: Dockerfile and compose were reviewed
  statically. The test harness runs in Docker; host Node 24 cannot load
  better-sqlite3 v11 (the repo pin is correct for its Node 20 target).
- Visual verification is static PNG renders (curl to WeasyPrint to PNG);
  no browser automation was used.
- Lab network isolation (internal network, egress restriction) is not
  started; see `docs/audit/KNOWN_ISSUES.md` for the full verified issue
  list.

## Counts to quote

- Challenges: 201 unique (34 duplicates removed).
- Modules: 29.
- Split: 63/201 on `main`; 138 remaining.
- Platform tests: 10/10 passing.
- Fix blocks: 20 (sqli + xss pilot).
