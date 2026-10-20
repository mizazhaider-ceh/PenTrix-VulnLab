# Polish-wave retest: Team D (2 UX desktop learners, 1 mobile learner)

Date: 2026-10-20. Coordinator: Team D lead. Scope: validate the P3 UI/UX fixes from a real user's seat, lab and website.
Method: Playwright (Chromium), screenshots viewed by the tester, evidence in `docs/audit/polish-shots/retest/` (prefix `rtd-`).
Lab: verify copy at `~/workspace/pentrix-verify`, port 19704. Website: `~/workspace/pentrix-website`, port 19705.
Product code was never edited; nothing was committed or pushed.

Overall: 14 of 14 items PASS. No P3 regression found.

## Student 1 (desktop, 1280px)

### S1a. Lab hero renders immediately, no blank gap: PASS
Screenshot taken right after load shows the full hero (title, lead copy, "View scoreboard" / "How to use" CTAs, stats row 29 / 201 / 0) with no blank region above or below it.
Evidence: `docs/audit/polish-shots/retest/rtd-s1a-hero-firstpaint.png`

### S1b. Breadcrumbs on 10 challenge pages: PASS
All 10 pages (chosen from real module indexes, including previously bare `/sqli/login` and `/misconfig/debug`) render a `<nav aria-label="Breadcrumb">` line `Modules / <Module name> / <Challenge name>` plus a "Back to <Module>" link. Both were clicked through on every page (20 navigations total); every one landed on the correct module index.
Pages: `/sqli/login`, `/misconfig/debug`, `/cmdi/ping`, `/xxe/collector`, `/oauth/code-leak`, `/lfi/view?file=readme.txt`, `/xss/search`, `/ssrf/fetch`, `/jwt/none`, `/csrf/account`.
Evidence: `docs/audit/polish-shots/retest/rtd-s1b-breadcrumb.png`

### S1c. Keyboard-only Tab walkthrough: PASS
Tab order on home, module index (`/sqli`), challenge (`/sqli/login`), and scoreboard is logical: skip link first, then brand, nav, page CTAs, filters, then content cards. Every focused element sampled showed a visible focus indicator (outline/box-shadow); the screenshot shows the focus ring clearly on the breadcrumb link after 9 Tabs.
Evidence: `docs/audit/polish-shots/retest/rtd-s1c-keyboard-focus.png`

### S1d. Website search overlay keyboard flow: PASS
Pressing `/` opens the overlay and focus lands immediately in the search input (placeholder "Search pages, modules, tools..."). Typing `sqli` announces "5 results for sqli. Use the arrow keys to choose one, then press Enter." through a visually-hidden `role="status"` `aria-live="polite"` region. Arrow keys move the selection via `aria-activedescendant` (correct combobox pattern, focus stays in the input); Enter opens the highlighted result (verified: second result opened `index.html#gallery-h`).
Evidence: `docs/audit/polish-shots/retest/rtd-s1d-search-open.png`, `rtd-s1d-search-results.png`

## Student 2 (desktop, 1280px)

### S2a. Website count-up stats, sampled every 100ms: PASS
Trace of the four stats (targets 29 / 201 / 3 / 3): final values in DOM at 64ms, reset to 0 at 397ms (DOMContentLoaded init), animation starts at 774ms, rises monotonically (0, 24, 27, 28, 29 for modules; 0 ... 201 for challenges), done at 2311ms, each stat animating exactly once. No dip after animation start, no restart.
Observation (not a fail): the HTML ships final values so no-JS users see correct numbers; the JS resets to 0 at DOMContentLoaded and first paint (956ms in the trace) happens after the reset, so users see the intended 0 to target rise. Only on very slow loads could the finals flash briefly before the reset. This is the pre-polish bug's old symptom, but in the measured flow it does not occur.
Evidence: samples at `~/workspace/polish-rtd/s2a_samples.json` (working scratch, not an audit artifact)

### S2b. Lab filter live regions: PASS
Home: typing a no-match string announces "No modules match your filter. Try clearing the search." in the polite live region; 0 cards shown, the empty-state box appears.
Scoreboard: announces "No challenges match your filter. Try clearing the search."; 0 rows shown, empty-state box appears.
Evidence: `docs/audit/polish-shots/retest/rtd-s2b-filter-nomatch-home.png`, `rtd-s2b-filter-nomatch-scoreboard.png`

### S2c. Copy buttons on a challenge page: PASS
`/cors/reflect`: the single copy button (aria-label "Copy Burp Repeater") copied the payload text exactly; button flipped to "Copied". Honest solve of `/sqli/login` (`admin' --` bypass): flag banner appeared, and the banner's "Copy flag" button copied the exact flag text to the clipboard; button flipped to "Copied". Both pastes were verified in a scratch file; the flag value was then redacted from that file.
Evidence: `docs/audit/polish-shots/retest/rtd-s2c-copy-payload.png`, `rtd-s2c-copy-flag.png`, paste log `~/workspace/polish-rtd/rtd-s2c-scratch.txt`

### S2d. Lab skip link: PASS
Activating "Skip to content" moved focus to `<main id="main">` (verified activeElement is the MAIN node).
Evidence: `docs/audit/polish-shots/retest/rtd-s2d-skiplink.png`

### S2e. Upload page, empty upload: PASS
The file input is labeled ("Choose a file for v1, plain upload", `label for=file0`, `aria-describedby="out0"`). Pressing "Upload to v1" with nothing selected writes "Pick a file first: use the file picker above, then press the upload button again." into a `role="status"` `aria-live="polite"` region, so the error is spoken. The guidance names the next step explicitly (use the picker above, press upload again).
Evidence: `docs/audit/polish-shots/retest/rtd-s2e-upload-empty.png`

## Student 3 (mobile-only, 390px)

### S3a. First-paint screenshots, lab and website home: PASS
Both render at first paint with no blank gaps; `scrollWidth == clientWidth` (390), so no horizontal overflow. The lab header wraps to two lines cleanly; the website hero, CTAs, and stats all render.
Evidence: `docs/audit/polish-shots/retest/rtd-s3a-lab-home-mobile.png`, `rtd-s3a-web-home-mobile.png`

### S3b. Tap targets: PASS
All measured at least 44px in the smaller dimension and all respond:
- OAuth quick-login chips: "alice (victim)" 136x44, "bob (attacker)" 146x44, "admin" 87x44; tap goes to `/oauth/login/alice`.
- Breadcrumb links: Modules 70x44, SQL Injection 101x44, "Back to" 101x44; tap navigates to the module.
- Mobile menu toggle 44x44: opens and closes (`aria-expanded` toggles), menu links 327x50.
- Search open 44x44: overlay opens, focus lands in input; close 44x44: closes.
- FAQ summary 313x44: opens on tap.
Evidence: `docs/audit/polish-shots/retest/rtd-s3b-oauth-chips.png`, `rtd-s3b-oauth-after.png`, `rtd-s3b-breadcrumb-tap.png`, `rtd-s3b-mobile-menu.png`, `rtd-s3b-faq.png`

### S3c. Website terminal demo: PASS
On 390px the simulated terminal shows readable light-on-dark text at 13.6px, the demo lines wrap inside the box, and there is no dead black space (term block 266px tall, screen content fills it).
Evidence: `docs/audit/polish-shots/retest/rtd-s3c-terminal-mobile.png`

### S3d. Full honest mobile solve (Easy): PASS
Solved `/sqli/login` at 390px honestly with the `admin' --` bypass: username/password fields 278x56, login button 278x56, no overflow anywhere, the flag banner renders readably with a wrapping flag well, the "Copy flag" button is 85x44 and taps to "Copied", and the header scoreboard pill updated 0/201 to 1/201. The whole flow is usable at 390px.
Evidence: `docs/audit/polish-shots/retest/rtd-s3d-login-form-mobile.png`, `rtd-s3d-flag-banner-mobile.png`

## UX regressions vs pre-polish behavior
None attributable to P3. Everything the polish stream touched (hero first paint, breadcrumbs, focus visibility, search keyboard flow, count-up animation, filter announcements, copy buttons, skip link, upload empty-state guidance, mobile layout and tap targets, terminal demo) now behaves as intended or better. Two test-harness artifacts during the run (breadcrumb taps read too early before navigation completed) were traced to my own scripts, not the product, and re-verified correctly.
Note on infrastructure, not product: the lab server on port 19704 died twice mid-test and had to be restarted (sibling agents run their own instances on 19702/19703). Also `/tmp` is being cleaned aggressively: keep working scripts under `~/workspace/polish-rtd/`.

## Flag secrecy note
`rtd-s3d-flag-banner-mobile.png` shows a live per-install flag value in pixels (it is a screenshot of a genuine capture). Keep the `polish-shots/retest/` audit folder internal; never publish these screenshots. The paste scratch file at `~/workspace/polish-rtd/rtd-s2c-scratch.txt` has its flag value redacted.

## Verdict on the P3 stream
All 14 retest items pass with viewed evidence. The P3 UI/UX stream is ready to ship. Recommend no further polish blocking: the one observation (stats reset timing under slow loads) is a minor progressive-enhancement edge, not a regression, and the count-up now runs exactly once with no dip and no restart as specified.
