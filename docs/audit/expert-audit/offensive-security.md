# Offensive-Security Audit: PenTrix-VulnLab

Auditor role: offensive-security expert. Method: source review of all 29 modules (201 challenges) plus live black-box cheat testing against the running instance at `http://127.0.0.1:18401/`. No code was changed.

Scope checked: FLAG BAR compliance (does every flag require genuine multi-step exploitation), cheat resistance (bare beacons, token replay, marker echo), difficulty curve, realism, vulnerability diversity.

Headline: the flag plumbing is sound (per-install random flags, no flag literals in source, scenario gating works), and most injection challenges genuinely require exploitation. But there are real FLAG BAR failures: six XXE challenges fall to a single POST containing a literal marker string, the beacon model behind ~21 XSS/CSTI/JSONP/postMessage challenges is forgeable with curl and zero payload execution, three CSRF challenges award for self-requests with no victim, and one upload challenge awards for a one-byte file. Details below.

---

## Finding 1: XXE flags awarded for echoing a literal marker string, no entity required

- Severity: Critical
- Location: `modules/xxe/challenges/file.js:63-68`, `modules/xxe/challenges/ssrf.js:65-69`, `modules/xxe/challenges/xxe-soap.js:59`, `modules/xxe/challenges/xxe-svg.js:39`, `modules/xxe/challenges/xxe-xinclude.js:37` (the shared `POST /xxe/import` path in `file.js` covers two challenge ids)
- Description: every one of these challenges awards its flag when the string `XXE-SECRET-4471` (or `SSRF-INTERNAL-9921`) appears anywhere in the expanded output. The check never verifies that an external entity was declared, that a `file://` or `http://` URI was resolved, or that the marker arrived via entity substitution rather than being typed literally into the request body. The intent ("success of the attack is measured on the raw expanded output") measures the wrong thing: it measures that the marker is present, not that XXE happened.
- Reproduction/evidence (all verified live, fresh sessions):
  - `POST /xxe/import` with body `xml=<data>XXE-SECRET-4471</data>` returned a flag for `xxe/file`. No DOCTYPE, no entity, no file read.
  - `POST /xxe/import` with body `xml=<data>SSRF-INTERNAL-9921</data>` returned a flag for `xxe/ssrf`. No HTTP entity, no SSRF.
  - `POST /xxe/soap` with `xml=<data>XXE-SECRET-4471</data>` returned a flag for `xxe/xxe-soap`.
  - `POST /xxe/svg` with `svg=<svg><text>XXE-SECRET-4471</text></svg>` returned a flag for `xxe/xxe-svg`.
  - `POST /xxe/xinclude` with `xml=<data>XXE-SECRET-4471</data>` returned a flag for `xxe/xxe-xinclude`.
  - Each is a single request. The existing test suite passes with this behavior (`node --test tests/xxe.test.js`: 11 pass), because negative tests only use benign input, never adversarial input containing the marker.
- Concrete recommendation: award only when the marker demonstrably arrived through entity resolution. Track which external entities were declared and resolved during expansion, and require (a) the raw input to contain an `<!ENTITY ... SYSTEM ...>` (or `xi:include`, or parameter-entity) declaration pointing at `file://`/`http://`, and (b) the marker to be present in the output but absent from the raw input. The two OOB challenges (`xxe-external-dtd`, `xxe-param-oob`) already do this correctly by checking the server-side OOB log; use them as the pattern. Add negative tests that POST the literal marker and assert no flag.

## Finding 2: beacon-nonce model forgeable with curl, zero payload execution (~21 challenges)

- Severity: High
- Location: `modules/xss/index.js` (`GET /xss/collect`, 8 beacon challenges), `modules/csti/index.js` (`GET /csti/beacon`, 5 challenges), `modules/jsonp/index.js` (`GET /jsonp/beacon-xss`, 3 challenges), `modules/postmsg/index.js` (beacon endpoint, 5 challenges)
- Description: all four modules award flags on a beacon GET that carries a per-session nonce scraped from the challenge page HTML (`window.__px`, `CSTI_NONCE`, etc.). Loading the page in curl, extracting the token with grep, and firing the beacon directly awards the flag. No JavaScript runs, no payload is injected, no template is evaluated. The code comments acknowledge the gap ("or at least that the challenge page was loaded in this session"), but per the FLAG BAR that is not exploitation. Affected: all 8 beacon XSS challenges, 4 of 5 CSTI challenges (the 5th, `constructor`, needs only a non-empty `d`), all 3 JSONP beacon challenges (the `jsonpFbAttempt`/`jsonpMimeAttempt` session flags are set by merely requesting the JSONP endpoint with matching callback shapes, still no script execution), and all 5 postMessage challenges (beacon needs `d` starting with `<vuln>:` plus the scraped nonce).
- Reproduction/evidence (verified live): `GET /xss/search` with a cookie jar, extract `window.__px` value, then `GET /xss/collect?c=anything&v=reflected&n=<token>` returned a flag. Two requests, no browser, no XSS.
- Concrete recommendation: for stored XSS at minimum, move to a victim-bot model (a headless browser visits the attacker's stored payload URL; the flag is awarded only when the bot's session data arrives at the collector). For reflected/DOM/CSTI/JSONP/postMessage, either use the same bot or make the token derivable only by executing the page's JavaScript (e.g., the page renders a seed and inline JS computes the token from it; a pure-HTML scraper cannot produce it without a JS engine). Short-term mitigation: stop rendering the raw token in HTML source.

## Finding 3: CSRF flags awarded for self-requests, no victim and no cross-site request

- Severity: High
- Location: `modules/csrf/challenges/email.js:68-69`, `modules/csrf/challenges/json-csrf.js:76`, `modules/csrf/challenges/method-override-csrf.js:52`
- Description: these challenges award the flag when the state-changing request is performed in the attacker's own session, against the attacker's own account. There is no victim, no attacker origin, and no cross-site request involved. The challenge page even provides a clickable "Load the forged request" link, so the intended solve is literally clicking a link that changes your own email. The `referer-bypass` challenge in the same module does this correctly (it requires a forged non-same-origin Referer), which makes the inconsistency sharper.
- Reproduction/evidence (verified live): `GET /csrf/login/alice` (sets session), then `GET /csrf/change-email?email=attacker@evil.com` returned a flag. Two requests, zero CSRF.
- Concrete recommendation: require evidence the request is genuinely cross-site before awarding: check that the `Referer`/`Origin` indicates the attacker page (the way `referer-bypass` already does), or introduce a victim-bot that loads the student's attacker page while logged in and award only when the victim's session performs the state change. Remove the "Load the forged request" shortcut link or gate it so it cannot award.

## Finding 4: Stored-XSS upload flag awarded at upload time, no execution required

- Severity: High
- Location: `modules/upload/challenges/stored-xss.js:70-76` (`POST /upload?filename=`)
- Description: the flag is awarded the moment any `.html`/`.svg` file is stored, regardless of content. The challenge is "stored XSS", but nothing ever needs to execute. The response text even says "open it to see the payload run", yet the flag was already granted.
- Reproduction/evidence (verified live): `POST /upload?filename=pwn.html` with a one-byte body (`x`) returned a flag.
- Concrete recommendation: do not award on store. Award when the stored file is subsequently served inline and a beacon (see Finding 2's bot recommendation) proves script execution, or at minimum require the uploaded bytes to contain an actual script payload and require a separate GET of the served file that renders it as active content.

## Finding 5: upload-case and upload-double-ext cross-award each other's flags

- Severity: Medium
- Location: `modules/upload/challenges/upload-case.js:40,48`, `modules/upload/challenges/upload-double-ext.js:86-93`
- Description: `upload-case.js` awards both `upload-case` and `upload-double-ext`, and `upload-double-ext.js` awards both `upload-double-ext` and `upload-case`. A student can capture both challenges' flags from a single endpoint without ever touching the other challenge. Challenges should be independent; cross-awards also corrupt per-challenge progress tracking.
- Reproduction/evidence: code review (both files contain both `award(req, 'upload', 'upload-case')` and `award(req, 'upload', 'upload-double-ext')` calls).
- Concrete recommendation: each challenge file awards only its own challenge id. If a bypass technique legitimately satisfies two challenges, decide which one owns it and document the overlap instead of double-awarding.

## Finding 6: challenge and module pages disclose payloads, secret paths, and marker strings

- Severity: Medium
- Location: `modules/xxe/index.js:114` (prints the `SSRF-INTERNAL-9921` marker), `modules/xxe/challenges/xxe-svg.js` hint box (prints the absolute `secret.txt` path), `modules/sqli/challenges/union.js` brief ("Your search term is interpolated into the SQL query"), `modules/xxe/index.js` ("hand-rolled, regex-based entity expander... No allowlists, no DTD hardening" plus an example payload)
- Description: pages narrate the vulnerability and hand out exact payloads, file paths, and marker strings. This hurts realism (real apps do not announce their flaws) and directly enables black-box cheats: Finding 1's `xxe/ssrf` cheat is fully black-box precisely because the module index page prints the marker. Hints exist as a progressive ladder already; the answers should live there, not on the landing page.
- Reproduction/evidence: `GET /xxe/` rendered HTML contains the marker string and the internal secret endpoint path; `GET /sqli/products` brief states the interpolation.
- Concrete recommendation: keep challenge landing pages in-fiction (describe what the app does, not how it is broken). Move payload recipes, file paths, and marker names into the hint ladder behind at least one reveal step.

## Finding 7: difficulty curve gaps and mixed taxonomies

- Severity: Medium
- Location: module `index.js` files (module-level `difficulty`/`track`) and challenge `vuln.difficulty` fields
- Description: (a) the SSTI module has zero Easy challenges (seven Medium, two Hard); there is no gentle on-ramp to a hard topic. (b) Only 7 challenges across all 29 modules carry the `Beginner` label, so the bottom of the curve is thin. (c) Step 1 of the "Zero to Web Pentester" beginner path is reflected XSS, whose flag requires beacon exfiltration; the step note says "watch the popup appear", but `alert()` does not earn the flag, so the first thing a day-one beginner meets is a mismatch between the taught action and the graded action. (d) Two parallel difficulty scales coexist: modules use Beginner/Intermediate/Advanced (`track`), challenges use Easy/Medium/Hard (plus a few `Beginner`/`Intermediate` strays), which is confusing in the UI.
- Reproduction/evidence: difficulty census via grep (72 Easy, 110 Medium, 19 Hard, 7 Beginner, 18 Intermediate, 4 Advanced-label mentions at module track level); `paths/zero-to-web-pentester.js` step 1 text vs `modules/xss/index.js` award logic.
- Concrete recommendation: add at least one Easy SSTI challenge (plain `{{7*7}}` reflection); add a true Beginner XSS challenge whose flag is awarded for a simple reflection proof before introducing the beacon, or reword path step 1 to teach the beacon payload from the start; unify on one taxonomy (module track = max challenge difficulty, or drop one scale).

## Finding 8: vulnerability diversity, over-representation and gaps

- Severity: Medium
- Location: `modules/cmdi/challenges/` (9 files), module challenge counts overall
- Description: injection dominates: sqli 11, xss 9, ssti 9, lfi 9, ssrf 9, cmdi 9 = 56 of 201 challenges. The cmdi module is the worst offender: 9 challenges that are the same ping gadget with different blacklist evasions (`cmdi-backtick`, `cmdi-braces`, `cmdi-ifs`, `cmdi-newline`, `cmdi-pipe`, `cmdi-tab`, `cmdi-wildcard`, plus `basic` and `bypass`). That is one vulnerability taught nine times, not nine vulnerabilities. Under-represented or missing classes: deserialization (none), LDAP/XPath injection (none), GraphQL (none), WebSocket (none), HTTP request smuggling (none), and the `http` module has only 3 challenges. The `formula` (4) and `redos` (4) modules are thin by comparison.
- Reproduction/evidence: challenge file census per module (see totals: 201).
- Concrete recommendation: collapse the cmdi filter-evasion variants into 3 (basic, one blacklist-bypass, one advanced technique) and spend the budget on a deserialization module and an XPath/LDAP module, which are conspicuous absences in a 29-module lab.

## Finding 9: misconfig flags are single-GET discovery, at the edge of the FLAG BAR

- Severity: Low
- Location: `modules/misconfig/challenges/` (`env.js`, `git.js`, `backup.js`, `robots.js`, `swp.js`, `trace.js`, `debug.js`, `manager.js`)
- Description: roughly ten flags are awarded for a single GET of a well-known sensitive path (`/.env`, `/.git/objects/...`, `/backup.sql`, ...). Discovery is a real skill, but "genuine multi-step exploitation" is a stretch when the whole attack is one request to a guessable path. This is a design tension rather than a bug, and the module is honest about what it is.
- Reproduction/evidence: code review; each challenge awards inside its GET handler upon serving the file.
- Concrete recommendation: keep the discovery step, but require the student to *use* what they find for at least some of these (e.g., the `/.env` database password must be used to authenticate somewhere, the `/backup.sql` hash must be cracked). That turns one-step discovery into the multi-step chain the FLAG BAR demands.

## Finding 10: test suite has a cheat-shaped blind spot

- Severity: Low (process, not product)
- Location: `tests/xxe.test.js`, and by pattern the other module test files
- Description: negative tests assert that benign input ("plain XML", "plain SVG", "no DTD") earns no flag, but no test submits adversarial input containing the marker strings or scraped nonces. The Finding 1 cheat passes the full suite (`tests/xxe.test.js`: 11/11 pass with the cheat live).
- Reproduction/evidence: ran the suite; wrote no new tests (read-only audit).
- Concrete recommendation: add adversarial negative tests per module: marker-literal input for echo-based awards, beacon-without-page-load for nonce awards, self-request for CSRF awards, empty/byte uploads for upload awards. These are the cheapest FLAG BAR enforcement available.

---

## What held up (verified genuine)

To keep this honest, the following sampled challenges genuinely require multi-step exploitation and resisted the cheat attempts I tried: `sqli/union` and `sqli/second-order` (flag requires the admin secret to surface through a real injection; second-order correctly requires a quote in the stored value), `sqli/blind` structure, `idor/profile` and `idor/admin` (require authenticated cross-user access), `auth/brute-force` (requires 5+ failed attempts then the real password in one session), `auth/reset` and `auth/reset-predictable` (forged-token logic correctly excludes legitimately issued tokens), `auth/otp-bruteforce` (4-digit, no rate limit, genuinely brute-forceable), `jwt/none-admin` and `jwt/weak-secret` (require real token forgery), `crypto/crypto-ecb-oracle`, `crypto-cbc-bitflip`, `crypto-hash-ext` (require the actual cryptanalysis), `crypto-md5-crack` (wordlist + login), `lfi/traversal` and `lfi/config-read` (require `..`/absolute path plus the marker from a real file read), `lfi/log-poison` (requires the chained User-Agent poisoning), `ssrf/basic` and the bypass variants (blocked-host-string checks force real bypasses), `race/race-balance` (real TOCTOU, single requests cannot drive the balance negative), `bizlogic/biz-price-tamper` and `biz-otp-client` (require real parameter/business-logic abuse), `proto/*` (require actual prototype pollution to admin), `cmdi/basic` (requires real command output via `executedSomething`), `csrf/referer-bypass` (correctly requires a forged non-same-origin Referer), `hostheader/evil-collect` (requires a token issued under a poisoned host), `http/cache-deception` (requires real cache poisoning with victim data), `formula/*` (require injecting a live formula then exporting), and the scenario kill-chains (stages unlock strictly on prior flag capture; completion requires all stages). Flag generation itself is clean: per-install random flags, no flag literals in source.

## Top-10 prioritized list

1. Fix XXE echo-marker awards (Finding 1, Critical): require proof of entity resolution, not marker presence. Six challenges, fully cheat-able today in one request each.
2. Harden the beacon model (Finding 2, High): ~21 challenges across xss, csti, jsonp, postmsg award on a scraped nonce with zero payload execution. Victim-bot for stored XSS first; JS-computed tokens or bot for the rest.
3. Fix CSRF self-request awards (Finding 3, High): require cross-site evidence (Referer/Origin or victim-bot); remove the clickable self-CSRF shortcut.
4. Fix upload stored-xss award-on-store (Finding 4, High): award on proven execution, not on file receipt.
5. Stop pages from disclosing payloads, paths, and markers (Finding 6, Medium): move answers into the hint ladder; this is also the enabler for Finding 1's black-box variant.
6. Remove upload cross-awards (Finding 5, Medium): one challenge, one flag, one endpoint.
7. Collapse cmdi filter-evasion padding; add deserialization and XPath/LDAP modules (Finding 8, Medium).
8. Fill the curve bottom: Easy SSTI entry, more Beginner challenges, fix path step 1's popup-vs-beacon mismatch, unify the difficulty taxonomy (Finding 7, Medium).
9. Make misconfig flags two-step: find the secret, then use it (Finding 9, Low).
10. Add adversarial negative tests (marker literals, beacon-without-load, self-CSRF, trivial uploads) so the suite actually enforces the FLAG BAR (Finding 10, Low).
