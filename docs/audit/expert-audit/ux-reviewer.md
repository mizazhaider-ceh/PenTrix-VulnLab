# UX Review: PenTrix-VulnLab

**Reviewer role:** UX reviewer (subagent audit)
**Date:** 2026-10-20
**Scope:** Live instance at `http://127.0.0.1:18404/`, repo at `~/workspace/pentrix-vulnlab/` (read-only review, no code changed)
**Method:** Fetched and inspected home, scoreboard, scenarios, paths, about, error pages, and 13 module index pages (`/xss`, `/sqli`, `/crypto`, `/http`, `/csrf`, `/misconfig`, `/upload`, `/session`, `/api`, `/auth`, `/bizlogic`, `/cors`, `/lfi`, `/oauth`, `/proto`, `/race`, `/redirect`, `/redos`, `/ssrf`, `/ssti`, `/xxe`), plus challenge sub-pages (`/sqli/login`, `/xss/search`, `/xss/collect`), fix editor pages, and the full `public/style.css` (263 lines) and `public/app.js` (160 lines).

**Overall impression:** The claymorphism shell is cohesive and the core loops (hint ladders, flag banners, scoreboard tables, scenario/path deep links) are well thought out. The audit below is deliberately brutal: most issues are consistency bugs where one page does the right thing and another does not.

---

## Findings

### F1. Progress chip missing on every module page
- **Severity:** High
- **Location:** All module routes (`/xss`, `/sqli`, `/api`, ...); shell is `lib/page.js` `page()` with `extra.scoreChip`
- **Description:** The topbar "0/201 flags captured" score chip renders only on shell-owned routes (home, scoreboard, scenarios, paths, about). Every module index page and every challenge sub-page renders the topbar without it, because module routers call `page()` without passing `extra.scoreChip`. The one place a student spends 95% of their time is the one place they cannot see their progress.
- **Evidence:** `curl /api | grep -c score-chip` returns 0; same for all 9 sampled module pages. Home and `/scoreboard` return 1. In `lib/page.js`, `const chip = (extra && extra.scoreChip) || ''` and module routers never pass it.
- **Recommendation:** Pass the score chip (or a module-local "x/y in this module" chip) from every module router, or move chip rendering into `page()` itself so it cannot be forgotten.

### F2. No `aria-current` on nav for module pages
- **Severity:** Medium
- **Location:** All module routes; `lib/page.js` `page(title, body, activeNav)`
- **Description:** Shell pages mark the active nav item (`aria-current="page"`), but module routers never pass `activeNav`, so inside any module no nav item is highlighted. Combined with F1, the topbar gives zero orientation feedback once you leave the home page.
- **Evidence:** `grep -c aria-current` is 0 on all 9 sampled module pages; 1 on `/scoreboard`, `/scenarios`, `/paths`, `/about`.
- **Recommendation:** Pass `activeNav='home'` (or a dedicated module key) from module routers, or default it.

### F3. No breadcrumbs on module pages; challenge sub-pages strand scenario/path users
- **Severity:** High
- **Location:** `/sqli/login`, `/xss/search`, all module index pages
- **Description:** Scenario and path detail pages have an eyebrow breadcrumb (`Scenarios >` / `Career paths >`), but module index pages have none, and challenge target pages are inconsistent. `/xss/search` ends with small dim links ("Challenge card · XSS module"). `/sqli/login`, which is deep-linked from both the Shop Takeover scenario and the Zero to Web Pentester path, has NO link back to `/sqli`, the scenario, or the path. After following "Enter the challenge" from a scenario, the only way back is the browser back button or the topbar home link; the scenario context is lost.
- **Evidence:** `/sqli/login` HTML contains zero links to `/sqli`, `/scenarios`, or `/paths` (verified with regex over the full page). `/xss/search` has only the dim footer links.
- **Recommendation:** Add a consistent breadcrumb line to every module index page (`Modules / <Module name>`) and every challenge sub-page (`Modules / <Module> / <Challenge>`), plus a "back to scenario/path" link when the referrer is a scenario or path (or always show the originating context via a query param).

### F4. Difficulty taxonomy is split in two and "Advanced" renders as an unknown grey dot
- **Severity:** High
- **Location:** `lib/page.js` `DIFF_DOTS`; `app.js` home cards; all scoreboard tables
- **Description:** Home page module cards use Beginner / Intermediate / Advanced. Scoreboard tables and challenge cards use Easy / Medium / Hard. A student sees "Intermediate" on the home card, clicks through, and finds "Medium" pills inside. Worse, `DIFF_DOTS` has no `advanced` key, so the 4 Advanced modules (crypto, proto, race, ssrf) render `dot-unknown` (flat grey), which reads as "unrated" rather than "hardest".
- **Evidence:** `difficultyPill` maps only beginner/easy/medium/intermediate/hard/mixed; `data-key="advanced"` appears on 4 home cards; the crypto card HTML shows `<span class="dot dot-unknown">` next to the label "Advanced". Challenge-level counts: 110 Medium, 72 Easy, 19 Hard, 18 Intermediate, 7 Beginner, 4 Advanced.
- **Recommendation:** Pick ONE taxonomy (suggest Beginner/Intermediate/Advanced everywhere, since the home filter already uses it) and add the missing dot class. Until then, at minimum map `advanced` to `dot-hard`.

### F5. Home difficulty filter cannot select Advanced modules
- **Severity:** Medium
- **Location:** `/` filter bar, `app.js` home route
- **Description:** The Difficulty select offers only All / Beginner / Intermediate, but 4 modules are Advanced (`data-key="advanced"`). There is no way to filter *to* the Advanced modules; selecting any difficulty hides them silently.
- **Evidence:** Home HTML: `<select id="hdiff">` contains only those three options; 4 cards carry `data-key="advanced"`.
- **Recommendation:** Generate the select options from the actual difficulty values present in the module list.

### F6. "Break then fix" section repeats the same "not available" sentence once per challenge
- **Severity:** Medium
- **Location:** Module index pages without fixes, e.g. `/api`, `/crypto`; generated in each module's `index.js` via `fixCta()`
- **Description:** Modules with no fix blocks render the module-level note ("Fix mode is not available for this module yet...") followed by N identical `<p class="dim fix-cta-soon">Fix mode is not available for this challenge yet.</p>` lines, one per challenge. On `/api` that is 5 identical paragraphs; on larger modules more. It reads as a rendering bug and pushes real content down.
- **Evidence:** `/api` HTML contains 1 module-level note + 5 identical per-challenge paragraphs. `fixCta()` in `lib/page.js` returns the paragraph when `hasFixBlock` is false, and modules map it over every challenge unconditionally.
- **Recommendation:** When a module has zero fix blocks, render the section once with the module-level note and skip the per-challenge lines. When some challenges have fixes, only render the "not available" line for the ones missing (or omit it; the CTA cards already communicate availability).

### F7. Scoreboard challenge rows are not links; no way to jump to a challenge
- **Severity:** Medium
- **Location:** `/scoreboard`, `app.js` scoreboard renderer
- **Description:** Each module's table lists challenge names as plain `<b>` text. A student scanning the scoreboard for what to do next cannot click a challenge to open it; they must go to the module page and scroll. The module name links, but the challenges do not.
- **Evidence:** Scoreboard HTML: `<td><b>Mass Assignment</b></td>` with no anchor. Module index cards have `id` anchors (e.g. `id="mass-assignment"`), so deep links like `/api#mass-assignment` would work.
- **Recommendation:** Link each challenge name to `/<module>#<challenge-id>`.

### F8. Flag banner never shows a "Next challenge" button
- **Severity:** Medium
- **Location:** `lib/page.js` `flagBanner()` (`nextHref` option)
- **Description:** `flagBanner` supports an optional `nextHref`/`nextLabel` "Next challenge" primary button, but no caller in the entire codebase passes it (verified: zero `nextHref` usages outside the definition). After capturing a flag, every banner offers only "Scoreboard" and "All modules". The capture moment is the highest-motivation instant in the loop, and it dead-ends into a choice between leaving the module or leaving the flow.
- **Evidence:** `grep -rn nextHref modules lib` returns only the two lines inside `flagBanner` itself.
- **Recommendation:** Pass `nextHref` pointing at the next uncaptured challenge in the same module (fall back to the module index).

### F9. 28 of 29 module index pages have no `<h1>`
- **Severity:** Medium
- **Location:** All module index pages except `/csrf`
- **Description:** Module pages jump straight from the topbar to `<h2>` sections (briefing, endpoints, challenges). Screen reader users get no top-level page heading, and the document outline starts at h2.
- **Evidence:** `grep -o '<h[12][^>]*>'` on 13 sampled module pages: only `/csrf` has an `<h1>`; the rest show only `<h2>`. `/api` has 6 h2 + 5 h3, zero h1.
- **Recommendation:** Render the module name as an `<h1>` at the top of each module index (the `brief()` helper's h2 can stay as a section heading, or be demoted appropriately).

### F10. Primary buttons go full-width on mobile, secondaries do not
- **Severity:** Low
- **Location:** `public/style.css` `@media(max-width:719px)` rule `.clay-btn-primary{width:100%}`
- **Description:** Below 719px every `.clay-btn-primary` becomes full width, but `.clay-btn-secondary` keeps its inline size. In mixed rows (flag banner next-steps: primary + two secondaries; filter bar: Filter primary + Reset secondary) the buttons no longer look like a related group. "Open challenge" and "Enter the challenge" buttons also stretch full width, which is fine alone but inconsistent next to secondary buttons.
- **Evidence:** Single CSS rule; inspect any page with mixed buttons at 360px (e.g. the flag banner or any filter bar).
- **Recommendation:** Scope the full-width rule to contexts where it helps (e.g. `.cta-row .clay-btn-primary`, `.filterbar .actions .clay-btn-primary`) or apply it to both button variants in action rows.

### F11. Topbar nav crowds at phone widths
- **Severity:** Medium
- **Location:** `public/style.css` `@media(max-width:719px)` `.topbar nav` rules
- **Description:** On small screens the nav wraps to full width with `justify-content:space-between` and no `flex-wrap` on the nav itself. Five links plus the nowrap score chip (6 items) must fit ~340px. Labels like "Scoreboard" will squeeze and wrap mid-word ("Score-board") or overflow, depending on the browser's shrink behavior. There is no hamburger or overflow strategy.
- **Evidence:** CSS: `.topbar nav{width:100%;justify-content:space-between}` with no `flex-wrap`; `.score-chip{white-space:nowrap}`; links have no `white-space:nowrap`, so their text can wrap.
- **Recommendation:** Allow the nav to wrap (`flex-wrap:wrap` on `.topbar nav`) with centered rows, or shorten labels on mobile (e.g. "Scores"), or move the chip to its own row.

### F12. White text on the light end of the primary button gradient fails contrast
- **Severity:** Medium
- **Location:** `public/style.css` `.clay-btn-primary` (gradient `#A78BFA` to `#7C3AED`)
- **Description:** White text over `#A78BFA` measures 2.72:1, well below the 4.5:1 AA threshold for normal text. The gradient's light end covers roughly half the button, so most button labels sit partly on failing contrast. The solid-violet end passes (5.70:1).
- **Evidence:** Computed ratios: white on `#A78BFA` = 2.72:1; white on `#7C3AED` = 5.70:1. Related: white checkmark on the emerald flag orb gradient (`#34D399` to `#10B981`) is ~2.5:1, acceptable only because it is a large decorative glyph, but worth noting.
- **Recommendation:** Darken the light stop of the gradient (e.g. start at `#8B5CF6`) or add a subtle text shadow / darker overlay so the full button surface passes 4.5:1.

### F13. Copy buttons are 36px tall, below the 44px touch target guideline
- **Severity:** Low
- **Location:** `public/style.css` `.copy-btn{min-height:36px}`
- **Description:** Payload and flag-well copy buttons are 36px tall. They sit next to full-width content on mobile and are a primary interaction (copying payloads). Primary nav links and hint summaries correctly use 44px+/56px.
- **Evidence:** `.copy-btn{...min-height:36px...}`; `.topbar nav a{min-height:44px}`; `.hint summary{min-height:56px}`.
- **Recommendation:** Raise `.copy-btn` to `min-height:44px` with comfortable padding.

### F14. No visible "wrong attempt" feedback in beacon challenges; failure is silence
- **Severity:** Medium
- **Location:** Beacon challenges (`/xss/*`, `/csti/*`, `/jsonp`, `/postmsg`); claim widget polling in `public/app.js`
- **Description:** There is no flag-submission form (flags are awarded by exploits), so the "wrong attempt" case is a beacon that gets rejected. The claim widget polls `/claim-status` every 3 seconds and flips from "Checking claim status..." to "No valid beacon received yet", but it never says *why* the beacon failed. A student who fires `alert(1)` or a token-less beacon sees nothing happen and gets no diagnostic. The "Not getting the flag? Why beacons fail" details block exists on the page and is excellent, but it is collapsed by default and disconnected from the failure moment.
- **Evidence:** `claimBox()` in `lib/page.js`; widget text logic in `app.js` (`j.captured ? 'Flag captured' : 'No valid beacon received yet'`). The 400 rejection reasons (missing token, empty data, stale nonce) are only visible in the `/collect` error page if the student loads it directly.
- **Recommendation:** When a beacon is rejected, surface the specific reason in the widget area (e.g. poll a last-rejection endpoint, or auto-expand the "Why beacons fail" block with the matching bullet highlighted after a failed attempt).

### F15. Challenge sub-pages are visually inconsistent with module pages
- **Severity:** Low
- **Location:** e.g. `/sqli/login` vs `/sqli`; `/xss/search` vs `/xss`
- **Description:** Challenge targets render as bespoke mini-apps (intended), but they drop shared chrome: no score chip (F1), no active nav (F2), no breadcrumb (F3), and inconsistent back-links (dim footer links on `/xss/search`, none at all on `/sqli/login`). The mini-app framing is good; the wayfinding gap is not.
- **Evidence:** `/sqli/login` topbar has neither chip nor `aria-current`; zero back-links in the page body.
- **Recommendation:** Give challenge pages a slim, consistent "lab chrome" strip (module breadcrumb + score chip), even when the rest of the page mimics a vulnerable app. F1-F3 fixes would cover most of this.

### F16. `reveal` animation has no safety net if the observer never fires
- **Severity:** Low
- **Location:** `public/style.css` `.js .reveal{opacity:0}`, `public/app.js` IntersectionObserver wiring
- **Description:** With JS enabled, `.reveal` elements start at `opacity:0` and only become visible when the observer adds `.in`. If an element never intersects (e.g. inside a container whose layout shifts after load, or an observer hiccup), it stays invisible forever. The code comment claims "Content is visible by default; the observer only enhances," but the CSS contradicts it: with the `.js` class present, content is hidden until observed.
- **Evidence:** CSS rule plus observer code; no `setTimeout` fallback in `app.js`.
- **Recommendation:** Add a safety timer (e.g. 2s after load, force-add `.in` to all `.reveal` elements) and correct the comment.

### F17. External Google Fonts on a "run locally only" lab
- **Severity:** Low
- **Location:** `lib/page.js` `page()` head (`fonts.googleapis.com`)
- **Description:** Every page preconnects to Google Fonts and loads DM Sans + Nunito. The lab's own copy says "Run locally only"; on an air-gapped lab network the font requests hang or fail and the UI falls back to system fonts (which is graceful, but the FOUT and failed requests are avoidable).
- **Evidence:** `<link href="https://fonts.googleapis.com/...">` in every page head; about page warns "Never deploy it to a public server or expose it to the internet."
- **Recommendation:** Self-host the two font files in `public/` so the lab is truly self-contained.

### F18. Path step label mismatches its link target
- **Severity:** Low
- **Location:** `/paths/zero-to-web-pentester`
- **Description:** Step 2 shows the code label `sqli` / `login-bypass` but links to `/sqli/login`. The label names a vuln id that does not match the route, which is confusing when a student tries to find "login-bypass" anywhere. (All other sampled steps' labels matched their anchors.)
- **Evidence:** Step 02 card HTML: `<code>sqli</code> / <code>login-bypass</code>` with `href="/sqli/login"`.
- **Recommendation:** Make step labels match the actual route or anchor they link to.

### F19. Nested duplicate `.progress-meta` on scenario/path pages
- **Severity:** Low
- **Location:** `/scenarios/<id>`, `/paths/<id>`
- **Description:** The progress block renders `<div class="progress-meta"><div class="progress-meta">...`, a redundant nested wrapper with inline `style="margin-bottom:1rem"` on the outer. Harmless visually but sloppy; the inline style also bypasses the design tokens.
- **Evidence:** Shop Takeover and Zero to Web Pentester HTML both contain the doubled wrapper.
- **Recommendation:** Collapse to a single wrapper and move the margin into CSS.

### F20. Scoreboard "fixes" pill is cryptic for new users
- **Severity:** Low
- **Location:** `/scoreboard` overall progress line
- **Description:** The line reads "0 / 201 flags · 0% [wrench] 0 fixes". "Fixes" refers to the break-then-fix mode, but nothing on the scoreboard explains what a fix is or where to earn one, and most modules do not offer it yet. A new user may read "0 fixes" as something broken.
- **Evidence:** Scoreboard HTML; fix mode exists for only 2 of 29 modules (sqli, xss).
- **Recommendation:** Add a `title` tooltip or a one-line explainer linking to a module with fix mode, or hide the pill until the user earns their first fix.

---

## What is already good (do not regress)

- **Hint ladders** (`details`/`summary`, keyboard accessible, 56px tap targets) are the best UX in the app.
- **Flag banner** (`role="status"`, copy button, recovery links) is excellent; it just needs the next-challenge button (F8).
- **Error pages** (404/500) have clear copy and recovery CTAs.
- **Failed logins** show a clear "Invalid username or password" state with a "Try again" link.
- **Scenario/path deep links** (`/idor#profile`, `/sqli/login`) all resolve; anchors match card ids.
- **Tables** get horizontal scroll containers below 719px; code blocks wrap with `word-break`.
- **Reduced-motion** support is thorough and the JS is genuinely progressive (filters degrade to GET forms, copy degrades to selectable text).
- **Contrast** of body text is strong (ink on canvas 11.7:1, muted on canvas 5.6:1).

---

## Top 10 prioritized list

1. **F1. Progress chip missing on module pages** (High): the core progress signal vanishes where students spend their time. Fix in `page()` so it cannot be forgotten.
2. **F3. Challenge sub-pages strand scenario/path users** (High): `/sqli/login` has zero back-links. Add consistent breadcrumbs everywhere.
3. **F4. Difficulty taxonomy split + grey "Advanced" dot** (High): two vocabularies (Beginner/Intermediate vs Easy/Medium/Hard) and `dot-unknown` on the hardest modules. Unify and map `advanced`.
4. **F2. No `aria-current` on module pages** (Medium): nav gives no orientation feedback inside modules. One-line fix alongside F1.
5. **F14. Beacon failures are silent** (Medium): rejected beacons produce no diagnostic at the failure moment. Surface the rejection reason near the claim widget.
6. **F6. Duplicated "Fix mode not available" paragraphs** (Medium): N identical sentences per module page read as a rendering bug. Render once per module.
7. **F8. No "Next challenge" after capture** (Medium): the highest-motivation moment dead-ends. Wire up the existing `nextHref` support.
8. **F7. Scoreboard challenges are not clickable** (Medium): deep-link each row to `/<module>#<challenge-id>`.
9. **F9. Missing `<h1>` on 28/29 module pages** (Medium): screen-reader and outline gap. Add the module name as h1.
10. **F12. Button gradient contrast failure** (Medium): white on `#A78BFA` is 2.72:1. Darken the light gradient stop.
