# Lab Quality Matrix: PenTrix VulnLab Curriculum Audit

Auditor: curriculum track, 2026-10-19. Every verdict below is grounded in the
module's `router.js`: its `vulns[]` definitions (id, difficulty, hint, how), the
`// VULN:` markers, and the `award()` call sites (what condition triggers the
flag). SOLUTIONS.md and the live instance at `http://localhost:3000` were used
for spot checks only.

## How to read this file

- **Module header**: id, name, module-level difficulty label, vuln count.
- **Columns**: `ID` (vuln id) | `Lvl` (the module's own Easy/Medium/Hard label) |
  `Learning objective` (one line, inferred from code) | `Tools` (what a student
  realistically needs) | `Validation` (how the flag is awarded, from code) |
  `Verdict` + one-line justification.
- **Verdicts**: `strong` (real vuln, honest label, evidence-based award),
  `needs work` (fixable flaw in label, validation, naming, or pedagogy),
  `shallow` (technically valid but trivial or thin), `duplicate` (concept already
  covered elsewhere; keep at most one).
- **Validation codes**: `OUT` = outcome/state-based (secret matched, state
  changed, file actually read); `MARK` = marker string found in server response;
  `BCN` = beacon endpoint (flag awarded when a beacon arrives); `INP` =
  input-pattern check (flag awarded because the request *looked* like an
  exploit); `VIS` = awarded on visiting/fetching an artifact; `CFG` =
  config-checker harness; `TIME` = timing measurement.
- **Tool codes**: `B` browser, `DT` browser devtools, `C` curl, `P` python,
  `BZ` Burp/ZAP proxy, `N` node/jwt CLI tooling, `W` wordlist/hashcat.

## Method notes (affect many rows)

1. **Beacon-honor-system weakness** (xss, postmsg, csti, partly jsonp): award
   endpoints accept `?v=<known-id>&d=<data>` from *any* client. Nothing bound the
   beacon to actual script execution, so flags were one crafted curl away from a
   student who never ran a payload. This was the single largest verification gap
   in the curriculum; fixed in M5 (per-session page-bound tokens, see
   VERIFICATION_MODEL.md).
2. **Module difficulty labels are mostly uninformative**: 21 of 29 modules are
   labeled `Mixed`; only csrf/idor/misconfig say `Beginner` and only
   api/cmdi/ssrf/ssti/xxe say `Intermediate`. There is no cross-module ordering,
   prerequisite chain, or learning path; the home page lists modules
   alphabetically.
3. **Count correction**: code exports **235** vulns, matching README's "235
   challenges". `docs/audit/PROJECT_DISCOVERY.md` claims 244 "by hint-count"
   and lists lfi:20; the actual lfi `vulns[]` has 10 entries. Treat 235 as
   authoritative; the audit docs are stale here.

---

## xss: Cross-Site Scripting [Mixed], 11 vulns

Module verdict: strong content; verification fixed in M5 (page-bound beacon tokens). The context ladder
(reflected, stored, attribute, JS string, template literal, DOM, markdown,
clobbering) is genuinely pedagogical. All BCN-based awards are bound to per-session page tokens since M5. `xss-svg-upload` conceptually duplicates upload-module
SVG XSS.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| reflected | Easy | Unescaped reflection into HTML executes script | B | BCN + page token (single-use) | strong |
| stored | Easy | Persisted payload executes for every later visitor | B | BCN + page token (single-use) | strong |
| dom | Medium | `location.hash` into `innerHTML` is client-side only | B, DT | BCN + page token (single-use) | strong |
| stored-xss-profile | Easy | Stored XSS via profile bio field | B | BCN + page token (single-use) | duplicate of `stored` (same sink class, different field) |
| xss-attr-breakout | Medium | Break out of an HTML attribute context with `">` | B | BCN + page token (single-use) | strong (context teaching) |
| xss-js-context | Medium | Break out of a JS string context with `';//` | B | BCN + page token (single-use) | strong (context teaching) |
| xss-svg-upload | Medium | SVG served as `image/svg+xml` runs embedded script | B, C | BCN + page token (single-use) | duplicate: same lesson as upload's SVG XSS |
| xss-markdown | Medium | Naive `[text](url)` renderer allows `javascript:` URLs | B | BCN + page token (single-use) | strong (real-world pattern) |
| xss-dom-clobber | Hard | Named DOM elements shadow `window` properties, flipping an auth check | B, DT | OUT (form+input detected server-side) | strong |
| xss-hash-write | Medium | Fragment into `document.write` executes | B, C | BCN + page token (single-use) | duplicate of `dom` (both DOM XSS sinks) |
| xss-backtick | Medium | Code execution inside a JS template literal via `${}` | B | BCN + page token (single-use) | strong (context teaching) |

## sqli: SQL Injection [Mixed], 12 vulns

Module verdict: strong. The best-built module in the curriculum: real
technique per vuln, outcome-based awards (secret actually appears in output),
honest Easy to Hard progression. Minor: two error-based vulns, two shallow
injection points.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| login-bypass | Easy | Classic `' OR '1'='1` authentication bypass | B, C | OUT (logged in as admin) | strong |
| union | Medium | UNION SELECT column-count matching to dump users | B, C | OUT (secret in rendered page) | strong |
| blind | Medium | Boolean oracle extraction, submit recovered secret | B, C | OUT (submitted == admin secret) | strong |
| error | Hard | Trigger visible SQLite syntax errors via id param | B, C | OUT (error message matches) | needs work: labeled Hard but a stray quote is Easy; near-duplicate of error-cast |
| order-by | Medium | CASE WHEN boolean oracle inside ORDER BY | B, C | INP (sort contains CASE WHEN + users) | needs work: INP check, no output-oracle verification |
| second-order | Hard | Stored payload executes on a later read (profile view) | B | OUT (non-admin member resolves to admin) | strong |
| like-wildcard | Medium | `%`/`_` wildcards dump unintended rows | B | OUT (`%` present and full catalog returned) | shallow: one character, no real technique |
| limit-offset | Easy | Negative LIMIT / comma offsets dump extra rows | B | OUT (non-numeric LIMIT ran, rows returned) | shallow but honest Easy |
| groupby-having | Medium | Inject GROUP BY to exfiltrate via grouping key | B, C | OUT (secret in grouped output) | strong |
| union-filter-bypass | Medium | Beat naive case-sensitive blacklist (case, comments) | B, C | OUT (secret UNIONed despite filter) | strong |
| insert-inject | Medium | Subquery inside VALUES writes secret into your row | B, C | OUT (secret in inserted row) | strong |
| error-cast | Easy | Runtime (non-syntax) SQLite errors leak data | B, C | OUT (runtime error path) | duplicate: second error-based vuln; merge with `error` |

## auth: Broken Authentication [Mixed], 11 vulns

Module verdict: strong breadth, one cross-module duplicate. OTP brute force is
honestly grindy (10k codes, scriptable with python, good tool realism).
`jwt-none` duplicates the jwt module's `none-admin`.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| brute-force | Medium | No rate limit or lockout enables password guessing | B, P | OUT (login after 5+ failures) | strong |
| jwt-none | Medium | `alg:none` tokens accepted with no signature check | B, N | OUT (admin via unsigned JWT) | duplicate of jwt/none-admin; delete one |
| reset | Easy | Reset token is just base64(username), forgeable | B, C | OUT (admin password changed) | strong |
| user-enum | Easy | Different error messages reveal valid usernames | B, C | OUT (valid username submitted) | strong |
| rememberme | Easy | Unsigned base64 cookie maps straight to a session | B, DT | OUT (admin session from forged cookie) | needs work: near-duplicate of crypto/crypto-b64-cookie; keep the better one |
| otp-bruteforce | Medium | 4-digit OTP, no lockout/expiry, scriptable | P, C | OUT (correct code submitted) | strong (tool realism) |
| reset-predictable | Medium | Deterministic SHA-256 reset token from public data | B, P | OUT (forged token works) | strong |
| security-question | Easy | "Secret" answer is public info in the user's bio | B | OUT (password reset via bio answer) | strong (OSINT angle) |
| change-pass-noverify | Easy | Password change needs session only, not current password | B | OUT (password changed) | strong |
| support-impersonate | Medium | Sequential ticket ids, no authZ: enumerate to admin session | B, C | OUT (admin session obtained) | strong |
| apikey-leak | Easy | Admin API key in HTML comment, reuse at admin API | DT, C | OUT (admin API call succeeds) | needs work: near-duplicate of crypto/crypto-key-in-js (secret in client code) |

## idor: Broken Access Control [Beginner], 11 vulns

Module verdict: needs work. Honest Beginner labeling, but 11 vulns teach
essentially one move ("change the id"), and api/bola-orders plus
api/id-enumeration repeat the same invoices idea. Keep 5-6, cut the rest or
add forced-browsing depth.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| profile | Easy | Object fetched by id with no ownership check | B, C | OUT (other user's secret read) | strong (archetype) |
| order | Easy | Same pattern on orders | B, C | OUT | duplicate of `profile` (same technique) |
| admin | Easy | Admin panel checks login, not role | B | OUT (panel rendered) | strong (function-level, distinct) |
| idor-download | Medium | Invoice download by id, no ownership check | B, C | OUT | duplicate: same as `profile`; also duplicated by api/id-enumeration |
| idor-email-change | Easy | Target account from client-supplied `user_id` param | BZ, C | OUT (other user's email changed) | strong (parameter-level IDOR) |
| idor-cart | Easy | Cart looked up by `user_id` query param | B, C | OUT | duplicate of `idor-email-change` (param IDOR) |
| idor-apikey-regen | Medium | Regenerate another user's key via their id, then use it | B, C | OUT | strong (chained impact) |
| idor-address | Easy | Stored address by id, no ownership check | B, C | OUT | duplicate of `profile` |
| function-browse | Medium | Force-browse admin function URL as non-admin | B | OUT | strong (forced browsing, distinct) |
| idor-comment-delete | Easy | Delete keyed by comment id only, no authorship check | B, C | OUT | strong (write-primitive IDOR) |
| idor-notes | Medium | Private note by numeric id, no ownership check | B, C | OUT | duplicate of `profile` |

## ssrf: Server-Side Request Forgery [Intermediate], 10 vulns

Module verdict: strong. The bypass ladder (decimal/hex/octal/0.0.0.0
encodings, userinfo, redirect, metadata, file://) is the most complete
single-topic treatment in the curriculum. Awards are marker-based with
explicit anti-cheat for the bypass challenge (blocked host strings rejected).
10 endpoints repeating the same "fetch internal secret" loop is repetitive but
each teaches a distinct bypass; keep.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| basic | Medium | Unvalidated server-side fetch reaches internal endpoint | B, C | MARK (marker in fetched body) | strong |
| bypass | Hard | Blocklist bypass via decimal-IP encoding | C | MARK + anti-cheat (no literal blocked host) | strong |
| ssrf-redirect | Medium | Blocklist checked on initial URL only; redirect lands internal | C | MARK (+ redirect required) | strong |
| ssrf-userinfo | Easy | `user@host` parsing confusion bypasses naive checks | C | MARK | strong |
| ssrf-hex-ip | Medium | Hex IP encoding bypass | C | MARK | strong |
| ssrf-octal-ip | Medium | Octal IP encoding bypass | C | MARK | strong |
| ssrf-zero-ip | Easy | `0.0.0.0` as loopback bypass | C | MARK | strong |
| ssrf-single-int | Medium | Integer IP bypass (same as `bypass`, dedicated endpoint) | C | MARK | duplicate of `bypass` (2130706433 in both); merge |
| ssrf-metadata | Medium | Cloud link-local metadata service reachable | C | MARK | strong (real-world impact) |
| ssrf-file | Medium | `file://` scheme turns fetcher into local file reader | C | MARK (`root:` in body) | strong |

## upload: Unrestricted File Upload [Mixed], 10 vulns

Module verdict: strong. Filter-bypass ladder is excellent and awards check
server state (file stored with dangerous ext, served as active content).
Overlaps xss on SVG; two blacklist-bypass entries are near-duplicates.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| stored-xss | Easy | HTML/SVG served inline executes script (stored XSS) | B, C | OUT (stored, served inline) | strong |
| blacklist-bypass | Medium | Exact-match ext blacklist beaten by double ext / .phtml | C | OUT (dangerous file stored) | needs work: near-duplicate of upload-double-ext |
| upload-double-ext | Medium | `shell.svg.jpg` passes final-ext check, served as SVG | C | OUT (served as active content) | strong |
| upload-case | Easy | Case-sensitive blacklist misses `.SVG` | C | OUT | strong |
| upload-ctype | Easy | Client-supplied Content-Type trusted as validation | C | OUT (HTML accepted as image/png) | strong |
| upload-traversal | Medium | Filename joined with no basename check; write outside dir | C | OUT (file exists outside uploads) | strong |
| upload-svg-onload | Easy | SVG event handlers survive naive upload | B, C | INP (`onload=` in bytes) | duplicate: same lesson as xss/xss-svg-upload; keep one |
| upload-strip-once | Medium | Single-strip filter beaten by `evil.s.svgvg` | C | OUT (stored as evil.svg) | strong |
| upload-overwrite | Medium | Predictable avatar path lets you overwrite another user's avatar | C | OUT (victim avatar bytes changed) | strong |
| upload-polyglot | Hard | GIF89a magic bytes + HTML: sniffing vs fixed content-type | C | INP (magic bytes + script pattern) | strong |

## cmdi: Command Injection [Intermediate], 10 vulns

Module verdict: strong ladder; validation fixed in M5. The v1-v10 filter-bypass
series ($IFS, ${IFS}, newline, backticks, globs, pipe, tab) is excellent
technique teaching, and basic/bypass now award on output evidence (the
injected command's output in the shell output); the empty-second-command
award is gone. `cmdi-newline` and `cmdi-env` are both newline injection.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| basic | Medium | Unescaped input concatenated into shell command | B, C | OUT (injected command output in shell output) | strong |
| bypass | Medium | Single-strip `;` filter beaten by `&&`, `||`, newline | B, C | OUT (injected command output in shell output) | strong |
| cmdi-ifs | Medium | Space-stripping beaten with `$IFS` | B, C | INP | needs work: same as above |
| cmdi-braces | Medium | `$IFS` string-strip beaten with `${IFS}` | B, C | INP | needs work: same as above |
| cmdi-newline | Medium | Separator blacklist beaten with `%0a` newline | B, C | INP | duplicate of cmdi-env (both newline); keep one |
| cmdi-backtick | Easy | `$(` strip beaten with legacy backticks | B, C | INP | strong (technique), INP validation needs work |
| cmdi-wildcard | Hard | `cat` and `/` word-blacklist beaten with `?` globs | B, C | INP | strong (creative bypass) |
| cmdi-pipe | Easy | `;` strip beaten with pipe chaining | B, C | INP | strong |
| cmdi-tab | Easy | Space strip beaten with `%09` tab | B, C | INP | strong |
| cmdi-env | Medium | Metachar blacklist missing newline, unquoted value | B, C | INP | duplicate of cmdi-newline; merge |

## xxe: XML External Entity Injection [Intermediate], 8 vulns

Module verdict: strong. Covers in-band, OOB (parameter entities, external
DTD), DoS (billion laughs with elapsed-time/size gates), and format variants
(SVG, SOAP, XInclude). Awards are evidence-based (secret in expansion,
collector hits, parse time). Keep as is.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| file | Medium | SYSTEM `file://` entity reads local file into output | B, C | MARK (secret in expanded output) | strong |
| ssrf | Hard | External entity with http:// URL hits internal endpoint | C | MARK (internal marker) | strong |
| xxe-billion-laughs | Medium | Recursive entity expansion as DoS; time/size evidence | C | TIME (elapsed > 1500ms or > 5MB expansion) | strong |
| xxe-external-dtd | Medium | Attacker-hosted DTD exfiltrates file content OOB | C | OUT (collector received secret) | strong |
| xxe-svg | Medium | XXE inside uploaded SVG's DOCTYPE | B, C | MARK | strong |
| xxe-xinclude | Medium | `xi:include` file inclusion as XXE alternative | B, C | MARK | strong |
| xxe-param-oob | Hard | Parameter-entity OOB exfiltration chain | C | OUT (collector hit) | strong |
| xxe-soap | Easy | Same XXE class in a SOAP envelope | B, C | MARK | shallow: same payload as `file`, new wrapper; acceptable Easy entry |

## ssti: Server-Side Template Injection [Intermediate], 10 vulns

Module verdict: strong, one naming bug. Filter-bypass ladder (word, underscore,
bracket, dot, curly, quote blacklists) is excellent; scope-leak and RCE
endpoints show real impact. Vuln `rce` is *named* "Flag Extraction via Scope
Leak" while `ssti-rce` is the actual RCE; rename the former (e.g. `scope-leak`).
`ssti-echo2` duplicates `basic` on a second endpoint.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| basic | Medium | `{{7*7}}` evaluates server-side; output proves injection | B, C | OUT (`{{}}` in input, 49 rendered) | strong |
| rce | Medium | In-scope variable (`secretFlag`) readable from template | B, C | OUT (secret rendered) | needs work: id/name say RCE but it is a scope leak; rename |
| ssti-echo2 | Easy | Same class on a second endpoint (`msg` param) | B | OUT | duplicate of `basic`; cut or keep as warm-up |
| ssti-wordfilter | Medium | Word blacklist beaten by string concatenation + eval | B, C | OUT (filtered var read) | strong |
| ssti-nounderscore | Medium | Underscore blacklist beaten with `String.fromCharCode(95)` | B, C | OUT | strong |
| ssti-nobrackets | Medium | Bracket blacklist beaten with `JSON.stringify` | B, C | OUT | strong |
| ssti-dotblock | Medium | Dot blacklist beaten with bracket notation | B, C | OUT | strong |
| ssti-curly | Medium | Curly-strip beaten by doubling braces | B, C | OUT | strong |
| ssti-noquotes | Hard | Quote blacklist beaten with char-code-built strings + eval | B, C | OUT | strong |
| ssti-rce | Hard | `require("child_process")` in scope: SSTI to real RCE | B, C | OUT (`uid=` in output) | strong |

## lfi: Path Traversal / LFI [Mixed], 10 vulns

Module verdict: strong. Good bypass ladder (single-pass strip, double
encoding, absolute paths, encoded separators) plus a genuine chained lab
(log poisoning: plant marker via User-Agent, then traverse to the log).
`double-encode` and `enc-slash` are close cousins.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| traversal | Easy | `../` escapes the docs dir; secret marker proves read | B, C | OUT (marker shown, `..` in param) | strong |
| filter-bypass | Medium | One-shot strip beaten by `....//` collapsing | B, C | OUT | strong |
| absolute | Easy | Absolute path used verbatim; read /etc/passwd | B, C | OUT (`root:` shown) | strong |
| double-encode | Medium | Double decode after single decode beats the filter | C | OUT | needs work: near-duplicate of enc-slash; merge |
| nested-deep | Easy | One-pass global strip beaten with nested dots | B, C | OUT | strong |
| lang | Easy | Traversal via an unexpected parameter (`lang`) | B, C | OUT | strong (parameter discovery) |
| log-poison | Hard | Chain: poison log via User-Agent, then include the log | C | OUT (log marker via traversal) | strong (chaining) |
| proc-self | Medium | `/proc/self/environ` read via filename param | B, C | OUT (environ marker) | strong |
| enc-slash | Medium | Encoded separator slips past pre-decode check | C | OUT | duplicate of double-encode (encoding bypass); merge |
| config-read | Easy | Planted secret config one directory up | B | OUT | shallow: same as `traversal` with a different file; fine as warm-up |

## csrf: CSRF & Open Redirect [Beginner], 11 vulns

Module verdict: needs work. Broad coverage (GET CSRF, JSON/text-plain,
multipart, login CSRF, referer bypass, content-type confusion, method
override, 2FA disable) but two structural problems: (1) `clickjacking` awarded
on merely visiting `/csrf/framedemo`, a Rule 2 violation (fixed in M5: the
framed form submission with a one-time token is now required); (2) `redirect` duplicates the entire redirect module, and several
entries duplicate http-module concepts (referer, method override).

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| email | Easy | State-changing GET with no token: forged request changes email | B | OUT (email changed) | strong |
| redirect | Easy | Unvalidated `to` param redirects off-site | B | INP (external target) | duplicate: whole redirect module covers this; cut from csrf |
| clickjacking | Easy | Missing X-Frame-Options allows framing | B | OUT (framed form submitted with one-time token) | strong |
| json-csrf | Medium | text/plain "simple request" carries JSON to tokenless API | BZ, C | OUT (email changed via JSON API) | strong |
| login-csrf | Medium | Forged login switches the victim's session | B | OUT (session switched) | needs work: overlaps oauth/no-state; keep the better one |
| multipart-csrf | Easy | multipart POST with no token changes password | B | OUT | duplicate of `email` (same no-token CSRF, different content type) |
| referer-bypass | Medium | Substring referer check beaten with `evil.com/?pentrix.lab` | C | OUT (cross-origin accepted) | duplicate: http/referer-auth covers referer trust; merge |
| get-passwd-change | Easy | Password change over GET, no token | B | OUT | duplicate of `email` (state-changing GET); keep one |
| contenttype-bypass | Medium | Plain form hits JSON endpoint (content-type confusion) | BZ, C | OUT | needs work: near-duplicate of json-csrf; merge |
| method-override-csrf | Medium | `_method=DELETE` smuggling triggers privileged path | BZ, C | OUT (override used) | duplicate: http/method-override covers this; merge |
| 2fa-disable-get | Easy | 2FA disabled via GET link, no token | B | OUT | duplicate of `email`/`get-passwd-change` (GET CSRF); keep one representative |

## api: API Security Flaws [Intermediate], 11 vulns

Module verdict: needs work. Good OWASP API Top 10 coverage (BOLA, excessive
data exposure, rate limiting, mass assignment, versioning) but mass
assignment is implemented **four times** (`mass-assignment`,
`mass-assign-role`, `unsafe-put`, `patch-self-admin`), and BOLA/invoice
enumeration duplicate the idor module. Consolidate to one mass-assignment lab
and cross-link BOLA to idor.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| mass-assignment | Medium | No allowlist: JSON body sets privileged fields | C | OUT (privilege escalated) | duplicate: 4 mass-assignment vulns; keep 1-2 |
| exposure | Easy | User list bundles fields the client should never see | B, C | OUT (secret fields read) | strong |
| rate-limit | Medium | Unlimited login attempts; flag after 15+ tries then success | P, C | OUT (attempts >= 15, then login) | strong |
| bola-orders | Medium | `:id` trusted, no ownership check on orders | C | OUT | duplicate: idor/order covers this |
| mass-assign-role | Easy | PATCH with `role:admin` in JSON body | C | OUT | duplicate of mass-assignment |
| data-exposure-keys | Easy | `api_secret` hiding in `/me` response | B, C | OUT | duplicate of `exposure` (same class) |
| ratelimit-xff | Medium | Rate-limit identity from spoofable X-Forwarded-For | C | OUT (locked-out IP logs in under spoofed IP) | duplicate: http/xff-admin covers XFF trust; merge |
| unsafe-put | Medium | PUT copies every client key incl. `is_admin` | C | OUT | duplicate of mass-assignment |
| api-version-bypass | Medium | v2 copy-pasted from v1 without the authZ check | C | OUT (v1 blocked, v2 served) | strong (real-world pattern) |
| id-enumeration | Easy | Sequential invoice ids enumerable to other users' data | C | OUT | duplicate: idor/idor-download covers this |
| patch-self-admin | Medium | PATCH `/me` with `is_admin:1` | C | OUT | duplicate of mass-assignment |

## misconfig: Security Misconfiguration [Beginner], 11 vulns

Module verdict: strong for its level, honestly labeled. All VIS awards, but
for information-disclosure vulns the fetch *is* the exploit; the challenge is
discovery (robots.txt, .git, dir listing). Keep; add a "read the artifact,
find the secret" validation step where cheap (e.g. submit the leaked key).

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| debug | Easy | `?err=1` renders stack trace + config dump | B | VIS | shallow but honest |
| backup | Easy | DB backup in web root, served to anyone | B, C | VIS | strong (discovery) |
| listing | Easy | Hand-rolled dir listing exposes secret.txt | B | VIS | strong (discovery) |
| git | Medium | `.git` over HTTP: HEAD, refs, commit object with secret | C | VIS (commit fetched) | strong |
| swp | Easy | Vim swap file in web root leaks source | C | VIS | strong (discovery) |
| trace | Easy | TRACE reflects the request (XST primitive) | C | VIS | strong |
| env | Medium | `.env` with production secrets served | C | VIS | strong (discovery) |
| debug-param | Easy | `?debug=1` flips verbose errors | B | VIS | duplicate of `debug` (same vuln, different param); merge |
| manager | Easy | Vendor default creds admin:admin on mgmt panel | B | OUT (logged in) | strong |
| robots | Easy | robots.txt advertises backup.zip; download it | B, C | VIS | strong (chained discovery) |
| put | Medium | Unauthenticated PUT writes into the served tree | C | OUT (file written and read back) | strong |

## jwt: JWT Attacks [Mixed], 8 vulns

Module verdict: strong. The classic eight (none, weak secret, kid SQLi, jku,
alg confusion, expiry, audience, default kid) with honest Easy/Hard labels.
`kid-sqli` nicely chains back to the sqli module. Drop auth/jwt-none as the
duplicate, keep this module's version.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| none-admin | Easy | `alg:none` accepted: mint your own claims, no signature | B, N | OUT (admin via unsigned token) | strong |
| weak-secret | Medium | Classic default HMAC secret: guess, then sign offline | N, W | OUT (admin token signed with recovered secret) | strong |
| kid-sqli | Medium | `kid` header interpolated into SQL key lookup | N, C | OUT (lookup returns attacker key) | strong (cross-module chaining) |
| jku | Hard | Untrusted `jku` URL: host your own key server | N, C | OUT (token verified against attacker key) | strong |
| alg-confusion | Hard | RS256 public key reused as HS256 secret | N | OUT (HS256 admin token verifies) | strong |
| no-expiry | Easy | `exp` never checked: replay the expired admin token | B | OUT (expired token accepted) | strong |
| aud-bypass | Medium | `aud` never validated: partner token works here | B, C | OUT (billing-service token accepted) | strong |
| kid-default | Medium | Missing `kid` falls back to guessable default key | N | OUT (kid-less token verifies) | strong |

## session: Session Management [Mixed], 6 vulns

Module verdict: strong. Each vuln is a distinct session flaw with
state-based awards. Good fixation demo (pre-login sid kept post-login).

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| fixation | Medium | Pre-login session id kept after login: fix, login, confirm | B, DT | OUT (sid unchanged after admin login) | strong |
| logout | Easy | Logout flips a flag; old cookie still opens admin page | B, DT | OUT (admin page with old cookie) | strong |
| predictable | Medium | Sequential session ids: read admin's, replay it | B, DT | OUT (admin panel as replayed sid) | strong |
| url | Easy | sid in URL lands in proxy logs; replay from log | B, DT | OUT (admin home with logged sid) | strong |
| never-expires | Easy | 10-year lifetime: archived admin sid still works | B, DT | OUT (legacy panel with old sid) | strong |
| log-leak | Easy | sid written to verbose debug log; replay it | B, DT | OUT (admin panel with logged sid) | strong |

## race: Race Conditions [Mixed], 8 vulns

Module verdict: strong. Outcome-based awards (redeems > 1, balance < 0,
dupes > 1) with `captured()` guards; genuinely requires parallel requests
(python), which is the right tool realism for this class. TOCTOU upload/scan
is a nice non-obvious entry.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| race-coupon | Medium | Check-then-act gap: parallel redeems double-spend a coupon | P, C | OUT (redeems > 1) | strong |
| race-balance | Medium | Check, await, debit: parallel transfers drive balance negative | P, C | OUT (balance < 0) | strong |
| race-vote | Easy | Duplicate-name check raced by simultaneous votes | P, C | OUT (votes > 1) | strong |
| race-referral | Medium | Parallel claims land the bonus twice | P, C | OUT (claims > 1) | strong |
| race-register | Medium | Uniqueness check raced: two accounts, one name | P, C | OUT (dupes > 1) | strong |
| race-upload-scan | Hard | TOCTOU: fetch the file before the 2s AV scan deletes it | P, C | OUT (live file fetched) | strong |
| race-ratelimit | Medium | Burst 20 parallel requests through a 5/window limit | P, C | OUT (count > 5) | strong |
| race-stock | Easy | Parallel buys oversell 5 items of stock | P, C | OUT (sold > 5) | strong |

## bizlogic: Business Logic Flaws [Mixed], 8 vulns

Module verdict: strong. All awards are outcome-based on server state
(balance increased, total < price, email changed, refund > total). Good
coverage of the "no CVE, just broken rules" class.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| biz-negative-qty | Easy | Unvalidated qty: negative quantity credits balance | B | OUT (balance > start) | strong |
| biz-price-tamper | Easy | Hidden price field honored as-is | BZ, B | OUT (total < real price) | strong |
| biz-coupon-stack | Medium | Percentages stack past 100% with no cap | B | OUT (total <= 0) | strong |
| biz-otp-client | Medium | Server trusts client-side `otp_ok` flag | BZ, C | OUT (wrong OTP accepted) | strong |
| biz-workflow-skip | Medium | Confirm endpoint never checks payment ran | BZ, C | OUT (confirmed unpaid) | strong |
| biz-currency | Easy | Currency param changes unit economics (JPY) | BZ, B | OUT (paid ~$0.34 for $50) | strong |
| biz-email-noreauth | Medium | Email change without re-auth enables account takeover via reset | B | OUT (email changed, reset link works) | strong |
| biz-refund | Medium | Refund amount from hidden field, never clamped | BZ, B | OUT (refund > order total) | strong |

## redirect: Open Redirect [Mixed], 6 vulns

Module verdict: strong, but triple-covered across the curriculum
(csrf/redirect here too, plus oauth/redirect-bypass). Keep this module as the
canonical home; delete csrf/redirect and cross-link the oauth one.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| redirect-double-slash | Easy | Protocol-relative `//evil.com` bypasses naive checks | B, C | OUT (Location points at evil.com) | strong |
| redirect-javascript | Medium | `javascript:` scheme honored in Location | C | OUT (Location starts with javascript:) | strong |
| redirect-data | Medium | `data:` scheme honored in Location | C | OUT | strong |
| redirect-backslash | Medium | Backslash confuses prefix allowlist (`https:\\evil.com`) | C | OUT (check passed, host != pentrix.lab) | strong |
| redirect-oauth-theft | Hard | Chain victim login + authorize to steal code via evil redirect_uri | B, C | OUT (code caught at collector) | needs work: overlaps oauth/redirect-bypass; keep one, cross-link |
| redirect-pollution | Medium | Duplicate params: last value wins over the validated first | C | OUT (evil host in Location) | strong |

## hostheader: Host Header Injection [Mixed], 6 vulns

Module verdict: strong. Distinct impacts per vuln (reset poisoning,
cache poisoning, SSRF, X-Forwarded-Host variants, absolute continue URL).
`host-ssrf` conceptually overlaps the ssrf module but the *vector* (Host
header as SSRF source) is distinct enough to keep with a cross-link.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| host-reset-poison | Medium | Reset link built from untrusted Host; token lands at collector | C | OUT (token issued for evil host) | strong |
| host-cache-poison | Hard | Path-keyed cache serves attacker-Host page to victims | C | OUT (poisoned entry served to normal host) | strong |
| host-ssrf | Medium | Health check builds target URL from Host header | C | OUT (internal agent key in body) | needs work: overlaps ssrf module; keep with cross-link |
| host-xforwarded | Easy | X-Forwarded-Host trusted for reset links | C | OUT | strong |
| host-override | Easy | X-Host-Override trusted for reset links | C | OUT | duplicate of host-xforwarded (same lesson, second header); merge |
| host-abs-url | Easy | Post-login continue rendered as absolute URL from Host | B, C | OUT (302 Location at evil host) | strong |

## http: HTTP Layer Flaws [Mixed], 6 vulns

Module verdict: needs work. Three of six duplicate other modules
(referer-auth vs csrf/referer-bypass, method-override vs
csrf/method-override-csrf, xff-admin vs api/ratelimit-xff). Keep
crlf-log, verb-tamper, cache-deception; merge or cross-link the rest.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| crlf-log | Medium | CR/LF in `ref` forges log lines (+ HTML in log viewer) | C | INP (CR/LF in input) | needs work: award on forged line appearing in log view, not input pattern |
| method-override | Medium | `_method` param rewrites verb; DELETE without approval | BZ, C | OUT (override used, item deleted) | duplicate: csrf/method-override-csrf; keep one |
| verb-tamper | Easy | POST-only feedback action also runs over GET | B, C | OUT (GET fired the action) | strong |
| xff-admin | Easy | X-Forwarded-For: 127.0.0.1 grants admin | C | OUT (admin page served) | duplicate: api/ratelimit-xff; keep one |
| cache-deception | Medium | Path-only cache key serves victim's personalized CSS to attacker | B, C | OUT (other user's data in cached body) | strong |
| referer-auth | Easy | Authorization from client-controlled Referer | C | OUT (hidden page served) | duplicate: csrf/referer-bypass; keep one |

## cors: CORS Misconfiguration [Mixed], 6 vulns

Module verdict: needs work. The `/cors/prove` harness is a *config checker*,
not an exploit: students submit origin/header combos and the server pattern-
matches them. Nobody performs an actual cross-origin read. Rebuild around a
real attacker page + victim flow (like postmsg does) so the lesson is
"steal the data", not "guess the config".

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| cors-reflect | Medium | Arbitrary Origin reflected with credentials | B | CFG (combo matches) | needs work: CFG validation, no real exploit |
| cors-null | Medium | `null` origin trusted | B | CFG | needs work: same |
| cors-regex | Medium | Regex allowlist bypass (`pentrix.lab.evil.com`) | B | CFG | needs work: same |
| cors-wildcard-data | Easy | Wildcard origin on sensitive-data endpoint | B | CFG | needs work: same |
| cors-subdomain | Medium | Suffix-only subdomain check bypass | B | CFG | needs work: same |
| cors-expose-headers | Easy | Sensitive response header exposed cross-origin | B | CFG | needs work: same |

## proto: Prototype Pollution [Mixed], 6 vulns

Module verdict: strong. Query, JSON body, constructor-path, unicode-escape,
and client-side variants all funnel into the same `role` admin check, which
reads as a deliberate ladder rather than duplication. The blacklist-bypass
progression is the pedagogy.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| proto-query | Medium | Query params deep-merged into config pollute `Object.prototype.role` | B, C | OUT (admin check passes) | strong |
| proto-json | Medium | JSON body deep-merge with no key filtering | C | OUT | strong |
| proto-constructor | Medium | `constructor`/`prototype` path beats `__proto__` blacklist | C | OUT | strong |
| proto-dos | Easy | Polluting `toString` crashes the widget render | B | OUT (crash page) | strong (DoS angle) |
| proto-client | Easy | Client-side pollution via `__proto__[theme]` param | B | OUT (polluted value rendered) | strong |
| proto-unicode-bypass | Hard | `\u005f` escapes smuggle the key past the text blacklist | C | OUT | strong |

## crypto: Cryptographic Failures [Mixed], 8 vulns

Module verdict: strong. Real cryptanalysis per vuln (ECB oracle, CBC
bit-flip, length extension, XOR crib-dragging) with submit-the-plaintext
validation, plus honest "don't roll your own" entries (MD5, base64, key in
JS). Tool realism is right (offline python/node). `crypto-key-in-js`
near-duplicates auth/apikey-leak.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| crypto-rand-pin | Easy | `Math.random` PIN brute-forced over 0000-9999 | P, C | OUT (correct PIN submitted) | strong |
| crypto-ecb-oracle | Hard | ECB block-equality leaks; byte-at-a-time decryption | P, C | OUT (plaintext == secret) | strong |
| crypto-cbc-bitflip | Hard | CBC malleability: flip IV bits to turn `guest` into `admin` | P, C | OUT (role admin in cookie) | strong |
| crypto-hash-ext | Hard | Merkle-Damgard length extension forges admin MAC | P, C | OUT (valid MAC over extended msg) | strong |
| crypto-md5-crack | Easy | Unsalted fast MD5 of dictionary password, cracked offline | W, P | OUT (password matches hash) | strong |
| crypto-b64-cookie | Easy | "Encryption" is base64: decode, edit role, re-encode | B, DT | OUT (role admin) | needs work: near-duplicate of auth/rememberme; keep one |
| crypto-xor-crib | Medium | Repeating-key XOR falls to known-plaintext crib dragging | P | OUT (plaintext == original) | strong |
| crypto-key-in-js | Easy | AES key shipped in public JS; decrypt offline | DT, P | OUT (note plaintext submitted) | needs work: near-duplicate of auth/apikey-leak (secret in client code); keep one |

## oauth: OAuth Flaws [Mixed], 8 vulns

Module verdict: strong. A working in-lab IdP + client simulation makes these
genuinely exercisable (code leak via logs, PKCE downgrade, replay,
scope tampering, implicit-flow token reuse). This is the most
realistic multi-actor module in the curriculum.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| redirect-bypass | Medium | Naive prefix check on redirect_uri leaks code to evil host | B, C | OUT (code issued to attacker host) | needs work: overlaps redirect/redirect-oauth-theft; keep one, cross-link |
| code-leak | Easy | Authorization codes written to readable server log | B, C | OUT (stolen code exchanged) | strong |
| no-state | Medium | Missing `state` enables login CSRF (victim logs in as attacker) | B | OUT (session bound to attacker's account) | needs work: overlaps csrf/login-csrf; keep the better one |
| implicit | Medium | Token in URL fragment/history reused at userinfo | B, DT | OUT (leaked token accepted) | strong |
| scope-upgrade | Easy | IdP grants unrequested `admin` scope without entitlement check | B, C | OUT (admin-data read) | strong |
| secret-in-js | Easy | Confidential client secret in public app.js | DT, C | OUT (direct token exchange) | strong |
| code-replay | Medium | Codes never single-use: exchange twice, compare tokens | C | OUT (two valid tokens) | strong |
| pkce-skip | Medium | Verifier never required despite code_challenge | C | OUT (exchange without verifier) | strong |

## postmsg: postMessage Flaws [Mixed], 5 vulns

Module verdict: strong. Attacker/victim page pairs are the right design,
and since M5 the three prefix-match beacons are bound to per-session page
tokens; `wildcard` (session secret) and `csrf-action` (server state) were
already evidence-bound.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| no-check | Medium | No origin check: any site drives the handler | B, DT | BCN + page token (single-use) | strong |
| wildcard | Easy | Secret broadcast with `targetOrigin:'*'`, captured by embedder | B, DT | BCN (secret in beacon) | strong |
| data-xss | Medium | Unsanitized `event.data` rendered as HTML | B, DT | BCN + page token (single-use) | strong |
| substring | Medium | Substring origin check beaten by `pentrix.lab.evil.com` | B, DT | BCN + page token (single-use) | strong |
| csrf-action | Medium | Forged message triggers privileged action in victim | B, DT | BCN (server state `pm_deleted`) | strong |

## csti: Client-Side Template Injection [Mixed], 5 vulns

Module verdict: needs work. Good concept coverage (basic eval, delimiter
bypass, constructor breakout, attribute context, stored), but the beacon
check was `d === '49'` (or non-empty for constructor): any student could curl
`/csti/beacon?v=basic&d=49` with zero template execution. Fixed in M5: the
beacon is bound to a per-session token rendered by the lab page.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| basic | Easy | `{{7*7}}` evaluated client-side via Function constructor | B | BCN + page token (single-use) | strong |
| filter-bypass | Medium | `[[ ]]` delimiter bypasses the `{{ }}` blacklist | B | BCN + page token (single-use) | strong |
| constructor | Medium | `constructor.constructor(...)` reaches code execution | B, DT | BCN + page token (single-use) | strong |
| attr | Medium | Template inside an HTML attribute, decoded then evaluated | B, DT | BCN + page token (single-use) | strong |
| stored | Easy | Stored display name evaluated as template on view | B | BCN + page token (single-use) | strong |

## jsonp: JSONP Injection [Mixed], 5 vulns

Module verdict: strong. Since M5 all five require beacon evidence: the
reflection labs echo a per-session token from the executed script, and
`csrf-data` / `array-hijack` use per-session secrets.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| callback-xss | Easy | Callback reflected into JS with no validation breaks out | B | BCN (executed script echoes per-session token) | strong |
| csrf-data | Medium | JSONP as cross-origin data theft; beacon the secret | B, DT | BCN (per-session secret in beacon) | strong |
| filter-bypass | Medium | `alert` blocklist beaten with `'al'+'ert'` concatenation | B | BCN (token echo + bypass attempt recorded) | strong |
| array-hijack | Hard | Redefined Array constructor captures feed elements | B, DT | BCN (items incl. per-session token) | strong |
| mimetype | Easy | JSONP served as text/html parses as a document | B | BCN (token echo + HTML attempt recorded) | strong |

## formula: CSV Formula Injection [Mixed], 4 vulns

Module verdict: strong, small. Uniform by design (four payload families:
classic, DDE, HYPERLINK, pipe prefix); validation scans the exported CSV for
dangerous cells, so the award requires the payload to survive export. Keep.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| formula-csv | Easy | `=cmd|...` payload survives CSV export un-neutralized | B | OUT (dangerous cell in export) | strong |
| formula-dde | Easy | DDE command-execution payload in a field | B | OUT | strong |
| formula-hyperlink | Medium | HYPERLINK exfiltration payload | B | OUT | strong |
| formula-pipe | Easy | Pipe prefix (LibreOffice) payload | B | OUT | strong |

## redos: ReDoS [Mixed], 4 vulns

Module verdict: strong. Timing-based awards (elapsed > threshold) are genuine
evidence of catastrophic backtracking; the regex-injection search vuln (user
input becomes the pattern atom) is a standout. Keep.

| ID | Lvl | Learning objective | Tools | Validation | Verdict |
|---|---|---|---|---|---|
| redos-email | Medium | Nested quantifiers in email regex: long valid run + bad tail | B, C | TIME | strong |
| redos-username | Easy | Textbook `(a+)+` catastrophic pattern | B, C | TIME | strong |
| redos-url | Medium | Nested quantifiers in URL path group | B, C | TIME | strong |
| redos-search | Medium | Search term interpolated as regex atom: craft `^((a)+)+$` | B, C | TIME | strong (injection angle) |

---

## Module rollup

| Module | Vulns | Strong | Needs work | Shallow | Duplicate | Module takeaway |
|---|---|---|---|---|---|---|
| xss | 11 | 8 | 0 | 0 | 3 | context ladder is great; beacons now page-bound (M5) |
| sqli | 12 | 9 | 2 | 1 | 0 | best module; merge the two error-based |
| auth | 11 | 9 | 2 | 0 | 1 | drop jwt-none (lives in jwt) |
| idor | 11 | 5 | 0 | 0 | 6 | one technique x11; cut to 5-6 |
| ssrf | 10 | 9 | 0 | 0 | 1 | best bypass ladder; merge single-int into bypass |
| upload | 10 | 8 | 1 | 0 | 1 | excellent; merge double-ext/blacklist-bypass |
| cmdi | 10 | 10 | 0 | 0 | 0 | awards now output-evidence-based (M5); merge the two newline vulns |
| xxe | 8 | 8 | 0 | 0 | 0 | exemplary |
| ssti | 10 | 8 | 1 | 0 | 1 | rename `rce`; cut echo2 |
| lfi | 10 | 8 | 1 | 1 | 0 | merge the two encoding bypasses |
| csrf | 11 | 3 | 2 | 0 | 6 | clickjacking now needs a framed submission (M5); heavy dedupe |
| api | 11 | 3 | 0 | 0 | 8 | 4x mass assignment; BOLA/IDOR dupes |
| misconfig | 11 | 8 | 0 | 2 | 1 | honest Beginner; merge the two debug vulns |
| jwt | 8 | 8 | 0 | 0 | 0 | exemplary |
| session | 6 | 6 | 0 | 0 | 0 | exemplary |
| race | 8 | 8 | 0 | 0 | 0 | exemplary; best tool realism (parallel python) |
| bizlogic | 8 | 8 | 0 | 0 | 0 | exemplary outcome-based awards |
| redirect | 6 | 5 | 1 | 0 | 0 | canonical home for open redirect; cross-link oauth |
| hostheader | 6 | 4 | 1 | 0 | 1 | merge the two X-Forwarded-* variants |
| http | 6 | 2 | 1 | 0 | 3 | keep 3, merge the dupes |
| cors | 6 | 0 | 6 | 0 | 0 | rebuild as real exploit, not config quiz |
| proto | 6 | 6 | 0 | 0 | 0 | exemplary ladder |
| crypto | 8 | 6 | 2 | 0 | 0 | merge client-secret entries with auth |
| oauth | 8 | 6 | 2 | 0 | 0 | best multi-actor realism; cross-link dupes |
| postmsg | 5 | 5 | 0 | 0 | 0 | beacons bound to page tokens and state (M5) |
| csti | 5 | 5 | 0 | 0 | 0 | beacons bound to page tokens (M5) |
| jsonp | 5 | 5 | 0 | 0 | 0 | all five require beacon evidence (M5) |
| formula | 4 | 4 | 0 | 0 | 0 | small and solid |
| redos | 4 | 4 | 0 | 0 | 0 | small and solid |
| **Total** | **235** | **180** | **17** | **4** | **34** | |

Verdict distribution: 77% strong, 7% needs work, 2% shallow, 14% duplicate.
Net curriculum after dedupe and merges: roughly 195-200 distinct, high-quality
challenges.

---

## (a) Duplicates and near-duplicates across modules

**Exact-concept duplicates (delete one side, cross-link the survivor):**

1. `alg:none` JWT: auth/jwt-none vs jwt/none-admin. Keep jwt's.
2. Open redirect as a whole: csrf/redirect vs redirect module (6 vulns). Delete from csrf.
3. Unsigned base64 cookie to session: auth/rememberme vs crypto/crypto-b64-cookie. Keep one.
4. Secret in client-side code: auth/apikey-leak (HTML comment) vs crypto/crypto-key-in-js. Keep one, mention the other as a variant.
5. BOLA on orders: api/bola-orders vs idor/order. Keep idor's.
6. Invoice enumeration: api/id-enumeration vs idor/idor-download. Keep idor's.
7. Login CSRF: csrf/login-csrf vs oauth/no-state. Keep oauth's (richer context).
8. Referer trust: csrf/referer-bypass vs http/referer-auth. Keep one.
9. Method override: csrf/method-override-csrf vs http/method-override. Keep one.
10. X-Forwarded-For trust: http/xff-admin vs api/ratelimit-xff. Keep one.
11. OAuth redirect_uri theft: redirect/redirect-oauth-theft vs oauth/redirect-bypass. Keep one, cross-link.
12. Mass assignment x4 inside api: mass-assignment, mass-assign-role, unsafe-put, patch-self-admin. Keep 2 at most.
13. Newline command injection: cmdi/cmdi-newline vs cmdi/cmdi-env. Merge.
14. Error-based SQLi x2: sqli/error vs sqli/error-cast. Merge.
15. Encoding-bypass LFI x2: lfi/double-encode vs lfi/enc-slash. Merge.
16. X-Forwarded-Host variants: hostheader/host-xforwarded vs host-override. Merge.

**Near-duplicates inside modules (ladder or cut):**

17. xss/stored vs stored-xss-profile; xss/dom vs xss-hash-write; xss-svg-upload vs upload module SVG XSS.
18. idor: profile/order/idor-download/idor-address/idor-notes are the same move; cut to profile + one more.
19. ssti/ssti-echo2 vs basic; upload/blacklist-bypass vs upload-double-ext.
20. csrf: email/multipart-csrf/get-passwd-change/2fa-disable-get are all "no-token state change"; keep email + one more.
21. ssrf/ssrf-single-int vs bypass (same 2130706433 payload); misconfig/debug vs debug-param.

---

## (b) Difficulty progression analysis

**Is there any progression?** Within modules, yes: most modules order Easy to
Hard sensibly (sqli's 12 run login-bypass to second-order/RCE-adjacent;
cmdi's v1-v10 is a genuine filter-bypass ladder; jwt runs none to alg
confusion). Across modules, no: the home page lists 29 modules alphabetically
with no suggested order, no prerequisites, no skill tracks. 21 of 29 modules
carry the label `Mixed`, which conveys nothing (nearly every module mixes
Easy and Hard). Only csrf/idor/misconfig say `Beginner`; only
api/cmdi/ssrf/ssti/xxe say `Intermediate`; nothing is labeled Advanced even
though crypto-ecb-oracle, xxe-param-oob, and jwt alg-confusion are genuinely
advanced.

**Is it honest?** Mostly, with exceptions: sqli/error is labeled Hard but is a
stray quote (Easy); jwt/weak-secret is Medium but the hint names it a
"classic default" (borderline Easy); csrf labels everything Easy/Medium
correctly except that clickjacking requires no exploit at all (mislabeled by
construction); cors labels are honest but the challenges are config quizzes,
not exploits, so the labels measure the wrong skill.

**Tool progression:** implicit and untaught. Early modules need only a
browser; race/crypto/jwt/ssrf genuinely need curl/python/node, but nothing
tells the student which tools to learn first. The `Tools` column in this
matrix is the first explicit tool mapping the curriculum has.

---

## (c) Prioritized improvement plan (top 10, ranked by value)

1. **Fix flag verification integrity (Rule 2).** `csrf/clickjacking` awards on
   page visit; xss/postmsg/csti/jsonp beacons are URL-forgeable (`/xss/collect?v=reflected&c=x`
   awards with zero script execution); cmdi/jsonp award on input patterns, not
   evidence. Bind every award to server-observable state (nonce in the
   vulnerable page, secret in the beacon, output evidence for cmdi). This is
   the lab-engine fix the balance rule demands: without it, "completion" is
   unverifiable.
2. **Dedupe pass (section a, items 1-16).** Removes roughly 30-40 redundant
   challenges, sharpens each module's identity, and cuts maintenance surface.
   Do this before writing learning paths so paths don't route through
   duplicates.
3. **Rebuild cors as a real exploit module.** Replace the `/cors/prove`
   config-checker with attacker/victim page pairs that actually exfiltrate
   data cross-origin (the postmsg module already proves the pattern works).
4. **Add per-vuln remediation teaching ("the fix").** The single biggest
   pedagogical gap: the app never teaches the secure alternative. Add a
   post-capture "How to fix it" panel per vuln (parameterized queries, output
   encoding, allowlists). SOLUTIONS.md has walkthroughs; it has no fixes.
5. **Learning paths + honest difficulty.** Replace the meaningless `Mixed`
   label with real tracks (e.g. Foundations: misconfig, idor, xss, csrf;
   Injection: sqli, cmdi, ssti, xxe, lfi; Auth & Sessions: auth, session,
   jwt, oauth; Advanced: crypto, race, ssrf, proto), with prerequisites and a
   suggested order on the home page.
6. **Tiered hints (3 levels per vuln).** Current hints are single-level and
   often near-answers (`?host=127.0.0.1%26%26id` is basically the solution).
   Structure: L1 nudge, L2 technique, L3 near-answer, with SOLUTIONS.md as the
   final tier.
7. **Rename/repair small defects:** ssti `rce` (it is a scope leak; the real
   RCE is `ssti-rce`), cmdi award logic (check output, not input), http
   `crlf-log` (award on forged log line, not CR/LF in input), lfi/ssrf merge
   items from section (a).
8. **Evidence and reporting workflow.** Per-lab notes, request history export,
   flag timestamps, and a writeup/report export. This is what separates a
   training platform from a flag dispenser, and it is currently zero.
9. **Reset behavior and state isolation.** Flags live in session MemoryStore
   (die on restart); race/coupon/upload states are global and shared across
   students. Add per-lab reset and per-student state scoping.
10. **Correct stale metadata.** README says 235 (correct); audit docs say 244
    (wrong, fix to 235); SOLUTIONS.md header says "235 challenges" (correct
    count, keep); audit the Easy/Medium/Hard labels flagged in section (b).

---

## (d) Gaps vs a serious training platform

- **Learning paths:** none. No tracks, prerequisites, ordering, or skill
  progression. The matrix's section (c.5) is the starting point.
- **Remediation teaching:** zero in-app. No "fix it" content, no secure-code
  comparisons, no CWE/OWASP mapping per vuln.
- **Evidence and reporting:** zero. No notes, no request logs, no timestamps,
  no exportable writeups or completion certificates.
- **Hint tiers:** single-level hints, often near-answers. No progressive
  disclosure.
- **Tool skill tagging:** none until this matrix. No "bring Burp/ZAP" guidance
  per lab, no tool tutorials.
- **Assessment integrity:** beacon forgery and award-on-visit mean flags are
  not proof of exploitation (section c.1). No anti-cheat beyond a few ad-hoc
  checks (ssrf bypass, race `captured()` guards).
- **Identity and persistence:** session-cookie only, MemoryStore; progress
  dies on restart. No users, no teams, no instructor view.
- **Lab operations:** no per-lab reset, no state isolation between students,
  no timers, no search/filter on the module list.
- **Accessibility and mobile:** no skip links, minimal ARIA, browser-default
  focus styles; usable on mobile but not tuned.

---

## (e) Per-challenge file split status (2026-10-19)

The codebase is being split from monolithic `modules/<id>/router.js` files to
one file per challenge. Target layout, verified against the tree on
2026-10-19:

- `modules/<id>/index.js`: thin aggregator. Requires each challenge file,
  builds the module index page (vuln cards, hint ladders, tool pills), holds
  only module-level helper routes.
- `modules/<id>/challenges/<vulnId>.js`: one challenge per file. Exports the
  `vuln` metadata (id, name, difficulty, how, start, hint) plus its own
  express router, which the aggregator mounts.
- `modules/<id>/shared.js`: module-scoped shared state and helpers (shop
  state, session fixtures). Present in 23 of 29 modules; absent in cors,
  crypto, csti, formula, http.
- `tests/<module>.test.js`: per-challenge exploit tests (node:test). Each
  challenge gets a subtest that boots the lab via `tests/helpers.js`
  (`bootLab`, `client`, `flagFromDb`, `capturedSet`, `FLAG_RE`) and asserts
  the flag is awarded by the documented technique and NOT by the obvious
  shortcut (benign input earns nothing, unauthenticated request is rejected).
  27 of 29 modules have one; crypto and xxe have none yet. Supporting files:
  `tests/helpers.js`, `tests/platform.test.js`, and the fixmode suite
  (`fixmode.test.js`, `fixmode-sqli.test.js`, `fixmode-xss.test.js`,
  `fixmode-badges.test.js`).

The done set is 8 modules / 63 challenge files; the in-progress set is 21
modules / 138 challenge files. 63 + 138 = 201, the post-dedupe challenge
count (section (a) records the 34 removed challenges; that list is unchanged).
Challenge-file counts below are post-dedupe, so they differ from the
pre-dedupe vuln counts in the audit tables above (e.g. api 5 here vs 11
above, csrf 5 vs 11, idor 7 vs 11).

### Done: 8 modules, 63 challenge files

| Module | Challenge files | index.js (lines) | Tests |
|---|---|---|---|
| api | 5 | 87 | tests/api.test.js |
| sqli | 11 | 57 | tests/sqli.test.js |
| xss | 9 | 132 | tests/xss.test.js |
| auth | 8 | 83 | tests/auth.test.js |
| idor | 7 | 119 | tests/idor.test.js |
| csrf | 5 | 109 | tests/csrf.test.js |
| cmdi | 9 | 83 | tests/cmdi.test.js |
| lfi | 9 | 62 | tests/lfi.test.js |
| **Total** | **63** | | |

### In progress: 21 modules, 138 challenge files

| Module | Challenge files | index.js (lines) | shared.js | Note |
|---|---|---|---|---|
| ssrf | 9 | 175 | yes | |
| upload | 8 | 165 | yes | |
| xxe | 8 | none | yes | still monolithic `router.js` (623 lines); `challenges/` not wired |
| ssti | 9 | 65 | yes | |
| jwt | 8 | 140 | yes | |
| session | 6 | 67 | yes | |
| race | 8 | 87 | yes | |
| bizlogic | 8 | 103 | yes | |
| redirect | 5 | 66 | yes | |
| hostheader | 5 | 148 | yes | |
| http | 3 | 77 | no | |
| cors | 6 | 231 | no | `/cors/prove` harness still in index.js |
| proto | 6 | 76 | yes | |
| crypto | 8 | none | no | still monolithic `router.js` (665 lines); `challenges/` not wired |
| oauth | 8 | 391 | yes | in-lab IdP simulation lives in index.js |
| postmsg | 5 | 122 | yes | |
| csti | 5 | 142 | no | |
| jsonp | 5 | 100 | yes | |
| formula | 4 | 104 | no | |
| redos | 4 | 78 | yes | |
| misconfig | 10 | 68 | yes | plus `backup.sql`, `public-files/` assets |
| **Total** | **138** | | | |

Notes:

- crypto and xxe are the two modules with no `index.js` yet; they still mount
  via the old monolithic `modules/<id>/router.js`, so their split is not
  finished even though their `challenges/` files exist.
- oauth's aggregator is thickest (391 lines) because the OAuth IdP + client
  simulation is module-level machinery shared by all 8 challenges, not
  per-challenge logic.
- sqli and xss also carry `modules/<id>/fixes/` for the break-then-fix mode;
  lfi carries `docs/` and `lfi_secret.conf`; these are module extras, not
  part of the split layout.

---

*Method: all 29 `modules/*/router.js` read; vuln counts from exported
`vulns[]` arrays (235 total); VULN markers and award() call sites grepped and
read in context; SOLUTIONS.md checked for per-flag coverage (all 235 flags
documented); live instance spot-checked at `/`, `/cors`, `/scoreboard`.*
