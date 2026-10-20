# Polish-Wave Retest, Team B

Retest coordinator report. Instance: fresh copy of `~/workspace/pentrix-vulnlab` (git main, uncommitted polish changes included) synced to `~/workspace/pentrix-verify`, run on `PORT=19702` with a fresh DB. Three simulated students, one cookie jar each, all flows taken from the rewritten `SOLUTIONS.md`. In-app hints treated as authoritative where checked. No product code edited, nothing committed or pushed. No flag literals appear in this report (D18).

## Method

* Student 1 (beginner): all 11 `sqli` challenges, executing the `SOLUTIONS.md` sqli section step by step, including writing real extraction scripts for the three blind oracles (boolean blind, ORDER BY, LIKE wildcard).
* Student 2 (intermediate): all 9 `xss` challenges via the intended exploits, with beacon firing simulated in a Node `vm` browser context exactly as `tests/xss.test.js` does (fetch page, run live inline scripts, deliver produced beacons to the real `/xss/collect`); all 9 `ssrf` challenges via direct HTTP.
* Student 3 (Burp learner): all 9 `cmdi` and 6 `cors` challenges with curl as the Repeater stand-in, following the Burp workflows in the doc, and checking that every hinted Burp step exists in Burp Suite Community.

Success criterion per challenge: the documented flow produces the flag award ("Flag captured" banner / submit acceptance) on a fresh session.

## Student 1: sqli (11/11 solved)

| # | Challenge | Result | Evidence |
|---|---|---|---|
| 1 | Login bypass | SOLVED | `POST /sqli/login` with `username=' OR '1'='1' -- ` returned the "Flag captured" banner. |
| 2 | UNION-based | SOLVED | `GET /sqli/products?q=' UNION SELECT id,username,password,secret FROM users-- ` rendered the admin secret as products and the banner. |
| 3 | Boolean blind | SOLVED | Oracle verified (`Product exists` vs `Not found`). Extracted the full 41-char `sqli_target()` value with a script, `POST /sqli/blind-submit` accepted it, banner shown. |
| 4 | Error-based | SOLVED | `id='` gives "unrecognized token" and the banner. Runtime path verified separately: `id=json('bad')` gives "malformed JSON", `id=substr(1)` gives "wrong number of arguments", `id=nosuchcolumn` gives "no such column"; all three messages are in the award regex. See Finding F2. |
| 5 | ORDER BY | SOLVED | CASE WHEN oracle verified (id-order vs name-order). Extracted the 41-char secret with a script, `POST /sqli/sort/submit` accepted it. |
| 6 | Second-order | SOLVED | Registered `display_name=admin'--`, `GET /sqli/profile?u=evil1` landed on the admin account, banner shown. |
| 7 | LIKE wildcard | SOLVED | Oracle verified ("5 of 5 products match" vs "0 of 5 products match"). Extracted the 41-char secret, `POST /sqli/wildcard/submit` accepted it. |
| 8 | LIMIT/OFFSET | SOLVED | `limit=-1` pulled the hidden "Archived Prototype X9" row and the banner. Award code confirms the doc: limit must contain a non-digit char and the output must contain the challenge token, so `limit=10` shows the row but earns nothing. |
| 9 | GROUP BY | SOLVED | `by=(SELECT sqli_target())` collapsed all rows into one group keyed by the secret, banner in a single request. |
| 10 | UNION filter bypass | SOLVED | Uppercase `UNION` sails through, banner shown. Lowercase `union` is stripped and yields `near "SELECT": syntax error`, exactly the "filter working" behavior the doc describes. |
| 11 | INSERT injection | SOLVED | `POST /sqli/feedback` with `name=x', (SELECT secret FROM users WHERE username='admin')) -- `, then `GET /sqli/feedback` showed the banner. |

Also verified from code: a login with the real admin password signs in but earns no flag (`u !== row.username` check), matching the doc.

## Student 2: xss (9/9) + ssrf (9/9) solved

XSS (browser sim, documented payloads):
1. reflected: script in `q` beacons with `n=window.__px`, collector awards. SOLVED.
2. stored: beacon comment posted, `/xss/victim-visit` fires it in the victim session, flag awarded. SOLVED.
3. dom: fragment `<img src=x onerror=...>` reaches `innerHTML`, handler runs, beacon delivered. SOLVED.
4. attr-breakout: `">` breakout verified in reflected markup, beacon delivered. SOLVED.
5. js-context: `';beacon;//` keeps page script valid, beacon delivered. SOLVED.
6. svg-upload: SVG with CDATA script uploaded, file served as `image/svg+xml`, token rebuilt from `pxa`/`pxk` shares at runtime, beacon delivered. SOLVED.
7. markdown: `[click](javascript:beacon)` renders `<a href="javascript:...">`, simulated click fires beacon. SOLVED.
8. dom-clobber: saved `<form id="settings"><input name="isAdmin" value="1">`, `/xss/clobber-admin` awarded. SOLVED.
9. backtick: `${beacon}` evaluated in template literal, beacon delivered. SOLVED.

SSRF (direct HTTP, lab address `127.0.0.1:19702`):
1. basic: `url=http://127.0.0.1:19702/ssrf/internal/secret`. SOLVED.
2. blocklist bypass: decimal `http://2130706433:19702/...`. SOLVED.
3. open-redirect: doc flow FAILED as written, working variant found. See Finding F1.
4. userinfo: `http://pentrix.lab@127.0.0.1:19702/...`. SOLVED.
5. hex-ip: `http://0x7f.0.0.1:19702/...`. SOLVED.
6. octal-ip: `http://0177.0.0.1:19702/...`. SOLVED.
7. zero-ip: `http://0.0.0.0:19702/...`. SOLVED.
8. metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. SOLVED.
9. file: `file:///etc/passwd` shows `root:` lines and awards. SOLVED.

## Student 3: cmdi (9/9) + cors (6/6) solved

cmdi (curl as Repeater): `ping?host=127.0.0.1;id`, `ping2` with `%26%26`, `ping3` with `cat$IFS`, `ping4` with `cat%24%7BIFS%7D`, `ping5` with `%0a`, `ping6` with backticks, `ping7` with `?` globs, `ping8` with `|`, `ping9` with `%09`. All nine returned the injected command's real output plus the banner. SOLVED.

cors: raw header checks first (`Origin: https://evil.com` reflected with credentials on `/cors/api/profile`; `Origin: null` trusted on `/cors/api/settings`), then the six `/cors/prove?vuln=...&origin=...` flows from the doc. All six returned "Vulnerable combination confirmed" with the banner. The prove endpoint makes a genuine server-side request with the attacker Origin and checks headers via `def.check`, so the awards are evidence-gated, not free. SOLVED.

Burp Community honesty: every Burp step in the tested hints exists in Community (Proxy intercept, Repeater, Intruder Sniper with small payload sets, Decoder tab, URL-decode view). The `cors-regex` hint explicitly steers away from Intruder ("a handful of edits beats setting up Intruder Sniper for this one"), which is the honest Community guidance. No hint requires Burp Pro.

## SOLUTIONS.md flow mismatches (doc bugs)

### F1. ssrf open-redirect: doc flow is blocked when the lab address is 127.0.0.1 (breaks the challenge)

Doc says:
```
curl --get --data-urlencode \
  "url=http://<your-lab-address>/ssrf/jump?to=http://127.0.0.1:<lab-port>/ssrf/internal/secret" \
  http://<your-lab-address>/ssrf/fetch3
```
Running the lab locally, the natural fill-in for `<your-lab-address>` is `127.0.0.1`. But `/ssrf/fetch3` rejects any initial URL whose parsed hostname is in `REDIRECT_BLOCKED = ['127.0.0.1']`, so this exact flow returns 403 "Blocked: URL contains a forbidden host." The doc's premise ("the blocklist only inspects the initial URL's hostname") is true, but the doc's own example fails its own check.

Correction: the initial URL's host must be a spelling the blocklist does not list. Use `localhost` for the jump URL:
```
curl --get --data-urlencode \
  "url=http://localhost:<lab-port>/ssrf/jump?to=http://127.0.0.1:<lab-port>/ssrf/internal/secret" \
  http://<your-lab-address>/ssrf/fetch3
```
This works (verified: banner shown, and the flag requires at least one real redirect, which this produces). The repo's own test suite uses `http://localhost:${port}/ssrf/jump?to=...` for this challenge, confirming the doc is the outlier. Suggested doc fix: replace `<your-lab-address>` in the jump URL with `localhost` and add one line explaining why (the initial host is checked against the blocklist, so it must not be a blocked literal).

### F2. sqli error-based: "a bad function call" is imprecise (minor)

Doc says a runtime error can be "a bad function call, malformed JSON, or a missing column". The award regex is `/syntax error|unrecognized token|malformed JSON|wrong number of arguments|no such column|datatype mismatch/i`. A call to a nonexistent function (`id=badfunc(1)`) yields "no such function", which is NOT in the regex: the error displays, but no flag. Verified working runtime triggers: `id=json('bad')` ("malformed JSON"), `id=substr(1)` ("wrong number of arguments"), `id=nosuchcolumn` ("no such column").

Correction: change "a bad function call" to "a bad function call with the wrong argument count (e.g. `substr(1)`)", or list the accepted error texts. A student following the doc literally with `badfunc()` would see an error, reasonably conclude the technique works, and be confused when no flag appears.

No other flow mismatches found in the tested modules. The LIKE-wildcard oracle, LIMIT award gating (`/[^0-9]/` on the limit plus token in output), GROUP BY single-request exfil, second-order read-time detonation, SVG share-token rebuild, markdown `javascript:` link, DOM-clobber admin check, all nine cmdi filter bypasses, and all six CORS prove flows work exactly as written.

## Spoiler check (modules tested)

Checked the module index cards (`v.how` text), the `brief()` text on challenge pages, and the prove-form defaults for the tested modules. Findings:

* Cards/briefings describe the vulnerability class and the goal ("The query behind this form is vulnerable to SQL injection", "Log in below"), never the payload. The two `how` texts that name techniques ("bypass the naive blacklist with case or comment tricks", "the link target becomes a javascript: URL") describe the idea, not the literal input.
* The CORS prove forms pre-fill neutral origins (`https://example.com`, empty), not the answers.
* The XSS claim boxes show the beacon *pattern* (`c`, `v`, `n=window.__px`), which is the intended teaching scaffold, not the injection payload.
* The in-app hint ladders are progressive (H1 nudges, H3 is specific). H3 hints can name the exact function or sink (e.g. the blind H2 shows the oracle shape `0' OR substr(sqli_target(),1,1)='P' -- `), but hints are opt-in and that is their purpose; the unaided card/briefing gives nothing away.
* Verdict: no card or briefing I read gave away a payload I needed. The challenges must still be worked.

## Time estimate accuracy

Ratings are for a real student working without the answer key, based on the observed difficulty.

sqli: login-bypass (5-10 min) just right; union (10-25) just right; blind (about 30 min) just right, the Intruder path is genuinely that long; error (5-10) just right; order-by (10-25) just right; second-order (20-40) slightly high, the two-step shape is simple once the read-time detonation clicks, 10-20 would be fairer; like-wildcard (10-25) just right; limit-offset (5-10) just right; groupby-having (10-25) slightly high, it is a single request and most students land it in under 10 once they try a subquery; union-filter-bypass (10-25) just right; insert-inject (10-25) just right.

xss: reflected (5-10) just right; stored (5-10) just right; dom (10-25) just right; attr-breakout (10-25) just right; js-context (10-25) just right; svg-upload (10-25) borderline low, the share-token XOR rebuild is the hardest conceptual step in the module and a real student may need 25-35; markdown (10-25) just right; dom-clobber (25-45) just right; backtick (10-25) just right.

ssrf: basic (10-25) slightly high, a first SSRF fetch is a 3-minute win; blocklist bypass (20-40) just right; redirect (10-25) just right once F1 is fixed; userinfo (5-10) just right; hex-ip (10-25) just right; octal-ip (10-25) just right; zero-ip (5-10) just right; metadata (10-25) just right; file (10-25) just right.

cmdi: basic (10-15) just right; bypass (10-20) just right; ifs (10-20) just right; braces (15-25) just right; newline (10-20) just right; backtick (5-10) just right; wildcard (20-40) just right, the trickiest in the set; pipe (5-10) just right; tab (5-10) just right.

cors: all six (about 10 min / 5-10 min) just right; each is one Repeater check plus the prove form.

## Caveats

* The test VM cleaned `/tmp` mid-run (DB, jars, and helper scripts deleted; the app process survived but stopped responding on 19702). All 44 challenge validations above completed before that. The report file itself was written after, into the verify copy.
* Scores shown on the nav chip were not used as evidence (my scripts spread awards across sessions via cookie-jar handling); evidence is the per-request "Flag captured" banner or submit acceptance observed at solve time.
* Student 2's XSS solves used the documented payloads with a vm browser sim for beacon firing, the same technique as the repo's own test suite; no shortcuts (bare curl beacons, scraped tokens) were used.
