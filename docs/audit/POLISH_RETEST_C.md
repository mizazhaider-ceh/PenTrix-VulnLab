# Polish-Wave Retest, Team C

Retest coordinator report. Instance: fresh copy of `~/workspace/pentrix-vulnlab` (git main) synced to `~/workspace/pentrix-verify`, run on `PORT=19703` with a fresh DB (`/tmp/polish-rt-c.db`). Three simulated students, one cookie jar per challenge, all flows taken from the rewritten `SOLUTIONS.md`. This is a fresh re-run; no state carried over from the earlier attempt. No product code edited, nothing committed or pushed. No flag literals appear in this report (D18).

## Method

* Student 1 (beginner): all 8 `oauth`, all 6 `proto`, all 10 `misconfig` challenges, executing the documented flows step by step with curl-equivalent requests (fresh jar per challenge; proto-client's page script executed in a node VM with a simulated DOM, exactly as `SOLUTIONS.md` describes).
* Student 2 (intermediate): all 8 `crypto`, all 8 `jwt`, all 5 `api` challenges. Real attack code throughout: from-scratch SHA-256 length extension, byte-at-a-time ECB decryption, CBC IV bit-flipping, XOR crib-dragging, hand-forged JWTs, parallel brute-force scripts for the PIN and OTP spaces.
* Student 3 (CTF player): all 8 `auth`, all 6 `session`, all 4 `redos` challenges via direct HTTP, plus two cheat-death attempts against FLAG BAR cheats the improvement wave closed (REVIEWS.md issues #1 and #11).

Success criterion per challenge: the documented flow produces the flag award ("Flag captured" banner or flag-bearing acceptance response) on a fresh session. Per-session isolation (improvement wave P1-1) held throughout: proto pollution and account overrides stayed inside each jar, so no challenge passed "for free" off another's state.

## Student 1: oauth (8/8) + proto (6/6) + misconfig (10/10)

oauth:
1. redirect-bypass: SOLVED. Approve with `redirect_uri=http://app.pentrix.lab.evil.com/cb`; banner on the approval page, code issued to the foreign host.
2. code-leak: SOLVED. Read alice's code from the world-readable `/oauth/idp/log`, exchanged it as bob at `/oauth/idp/token`; response carried the flag.
3. no-state: SOLVED. Attacker link from `/oauth/no-state/attacker` (bob's code) visited in alice's IdP session; client session became bob, flag shown.
4. implicit: SOLVED. Fragment token recorded via `/oauth/client/history-log`, stolen from `/oauth/client/history` in a clean session, accepted at `/oauth/idp/userinfo`; flag in response.
5. scope-upgrade: SOLVED. Authorized with `scope=admin` as bob, exchanged, called `/oauth/idp/admin-data`; flag returned.
6. secret-in-js: SOLVED. `CLIENT_SECRET` read from `/oauth/client/app.js`, used in the confidential-client exchange; flag returned.
7. code-replay: SOLVED. Challenge page visited first (flow stamp), code exchanged twice; second response carried the flag. The flow scoping held: only the stamped flow's replay awards.
8. pkce-skip: SOLVED. Code authorized with `code_challenge`/`S256`, exchanged with no `code_verifier`; flag returned.

proto:
1. query: SOLVED. `?__proto__%5Brole%5D=admin` then `/proto/query/admin` printed the flag.
2. json: SOLVED. Literal `__proto__` key (via defineProperty, since an object literal would set the prototype instead) merged, then `/proto/json/admin` awarded.
3. constructor: SOLVED. `?constructor%5Bprototype%5D%5Brole%5D=admin` back door, then `/proto/constructor/admin` awarded.
4. dos: SOLVED. `?__proto__%5BtoString%5D=boom` rendered the crash page ("The widget broke") with the flag.
5. client: SOLVED. Fetched `/proto/client?__proto__%5Btheme%5D=dark`, executed the page's exact parser+merge script in node with a simulated DOM (fresh `{}` read `theme='dark'`), then claimed with the one-time render proof; flag awarded. The claim endpoint rejects proof-less requests (400), confirming the evidence gate.
6. unicode: SOLVED. `\u005f` escapes sent as `text/plain` passed the raw-text blacklist scan, decoded by `JSON.parse` after it; `/proto/unicode/admin` awarded.

misconfig (all ten via the documented single requests):
1. debug: SOLVED. `GET /misconfig/debug?err=1` dumped config including the `debugToken` flag.
2. backup: SOLVED. `GET /misconfig/backup.sql` served the dump with the capture banner.
3. listing: SOLVED. `GET /misconfig/files/` listed `secret.txt`; fetching it awarded the flag.
4. git: SOLVED. Walked `HEAD` to `refs/heads/main` to the object store (`a1/...`), read the commit diff leaking the token; flag awarded.
5. swp: SOLVED. `GET /misconfig/app.js.swp` served the recovered editor backup with the flag.
6. trace: SOLVED. `TRACE /misconfig/trace` with `X-Custom: hello` echoed the full request; flag awarded.
7. env: SOLVED. `GET /misconfig/.env` printed the secrets and the flag.
8. manager: SOLVED. `admin:admin` HTTP Basic opened the panel; flag awarded.
9. robots: SOLVED. `robots.txt` disclosed `/misconfig/backup.zip`; unpacked `backup.txt` held the flag.
10. put: SOLVED. `PUT /misconfig/files/pwn.txt` returned 201; the read-back awarded the flag.

## Student 2: crypto (8/8) + jwt (8/8) + api (5/5)

crypto:
1. rand-pin: SOLVED. 10,000-space brute force at `POST /crypto/pin/verify` with a 24-worker keep-alive pool; winning PIN found after 2,209 guesses in 1.5 s (1,473 req/s measured on this VM).
2. ecb-oracle: SOLVED. Block size 16 confirmed (growth at prefix 4), ECB confirmed (three identical blocks on 48 identical bytes), secret length 28, then byte-at-a-time decryption (28 bytes x 256 guesses); `POST /crypto/ecb/solve` accepted the recovered secret.
3. cbc-bitflip: SOLVED. Decoded the cookie (IV + `{"role":"guest",...}`), flipped IV bytes 9-13 with `guest xor admin`, re-encoded; `/crypto/cbc/check` saw `role='admin'` and awarded.
4. hash-ext: SOLVED. From-scratch SHA-256 with injectable state: glue padding rebuilt for the 25-byte prefix, forged message `role=user || glue || ;admin=1` (56 bytes), MAC continued from the leaked digest; `/crypto/mac/verify` accepted it.
5. md5-crack: SOLVED. Hash from `/crypto/md5` matched against `/crypto/md5/wordlist.txt` offline; login as demo awarded the flag.
6. b64-cookie: SOLVED. Base64-decoded the cookie, flipped `"role":"user"` to `"role":"admin"`, re-encoded; check awarded.
7. xor-crib: SOLVED. 9-byte header crib `{"user":"` tried over key lengths 1-12; length 8 yielded valid JSON; `/crypto/xor/solve` accepted it.
8. key-in-js: SOLVED. Key read from `/crypto/keyjs/app.js`, ciphertext decrypted AES-128-CBC with the prepended IV; `/crypto/keyjs/solve` accepted the note.

jwt:
1. none: SOLVED. Hand-built unsigned token accepted at `/jwt/none`.
2. weak-secret: SOLVED. Admin token signed with `secret123` accepted at `/jwt/weak`.
3. kid-sqli: SOLVED. `kid` of `zzz' UNION SELECT 'attackerkey1` made the lookup return the attacker key; token signed with it accepted at `/jwt/kid`.
4. jku: SOLVED. Registered `kid=evil`/`evilsecret` at `/jwt/attacker-keys`, minted a token with `jku` pointing at the in-lab JWKS URL; accepted at `/jwt/jku`.
5. alg-confusion: SOLVED. Extracted the exact PEM bytes from `/jwt/confusion-pubkey` (see Finding F1 for the doc staleness), signed HS256 with those bytes as the key; accepted at `/jwt/confusion`.
6. no-expiry: SOLVED. Expired admin token from `/jwt/noexpiry` submitted unchanged; accepted.
7. aud-bypass: SOLVED. Partner token (`aud: billing-service`) from `/jwt/aud` submitted at `/jwt/aud/login`; accepted.
8. kid-default: SOLVED. Kid-less token signed with `test`; accepted at `/jwt/kiddefault`.

api:
1. mass-assignment: SOLVED. `PATCH /api/me` with `{"role":"admin"}` flipped role user to admin; flag in response.
2. exposure: SOLVED. `GET /api/users` returned full rows (password, secret fields) and the `X-Pentrix-Flag` header.
3. rate-limit: SOLVED. 14 wrong logins then the correct one in one session; success carried the flag, no lockout.
4. ratelimit-xff: SOLVED. Locked out after 4 bad attempts (429, including on the correct password), then logged in with `X-Forwarded-For: 10.9.9.9`; flag awarded.
5. version-bypass: SOLVED. `/api/v1/users/3` answered 403, `/api/v2/users/3` returned the full record with the flag.

## Student 3: auth (8/8) + session (6/6) + redos (4/4)

auth:
1. brute-force: SOLVED. Five wrong logins then `alice123` in one session; no throttling, flag on the successful login.
2. reset-predictable: SOLVED. `token` of base64(`admin`) with a new password accepted at `/auth/reset/confirm`; flag fired.
3. user-enum: SOLVED. Oracle distinguished ("not found" vs "wrong password"), confirmed `alice` submitted at `/auth/enum-submit`; flag awarded.
4. otp-bruteforce: SOLVED. Reset token copied from `/auth/otp-reset`, 10,000-code space brute forced at `/auth/otp-reset/verify` with a 24-worker pool; winning code found after 9,330 guesses in 5.2 s (1,794 req/s).
5. reset-sha256: SOLVED. Token forged as `sha256('admin' + 'reset-salt')` locally, confirmed at `/auth/sha-reset/confirm`; flag awarded.
6. security-question: SOLVED. Maiden name read from `/auth/bio/alice`, submitted at `/auth/question-reset`; flag awarded and the new password worked.
7. change-pass-noverify: SOLVED. Logged in as bob, changed the password with no current-password field; flag awarded, re-login with the new password confirmed.
8. support-impersonate: SOLVED. Walked tickets 1001-1005; ticket 1005 signed in as admin and awarded the flag.

session:
1. fixation: SOLVED. Preset `lab_sid=attacker123`, logged in as admin; the sid did not change and the flag showed.
2. logout: SOLVED. Logged in, logged out, reopened `/session/logoutdemo/secret` with the old cookie; flag shown.
3. predictable: SOLVED. Own id read from the page, admin id computed as +1, set as `lab_sid`; admin panel awarded the flag.
4. url: SOLVED. Visited `/session/urldemo`, found the admin's `sid=` URL in `/session/urldemo/proxy-log`, replayed it; flag awarded.
5. never-expires: SOLVED. Archived admin sid copied from `/session/legacy-archive`, set as `lab_sid`; legacy panel awarded the flag.
6. log-leak: SOLVED. Admin sid read from `/session/debug-log` (`admin session started sid=...`), replayed as `lab_sid`; admin panel awarded the flag.

redos (sequential; each request blocks the single-threaded lab):
1. email: SOLVED. 30 a's + `!` (no `@`) took 6.9 s; flag on the result page.
2. username: SOLVED. 27 a's + `!` took 8.2 s; flag shown.
3. url: SOLVED. `http://example.com/` + 12 `a/` segments + `!` took 10.0 s; flag shown.
4. search: SOLVED. `?q=a` against the fixed haystack took 8.4 s; flag shown.

## Cheat-death confirmations (Student 3)

Two FLAG BAR cheats from REVIEWS.md that the improvement wave closed, re-attempted against the current build:

Cheat A, REVIEWS issue #1 (XSS beacon awards with no JavaScript execution):
* The challenge page renders the page-bound token only as two random XOR share arrays (`__tkA`, `__tkK`); no raw token literal appears in the HTML. Scraping the page source yields shares, not the token. DEAD.
* Beacon with an empty token: 400, no flag. DEAD.
* Beacon with a fabricated 32-hex token: 400, no flag. DEAD.
* Control: executing the page's inline scripts in a node `vm` browser context (as `tests/xss.test.js` does) produced a runtime token whose beacon was accepted with the flag. The honest path works; the curl-only cheat does not.

Cheat B, REVIEWS issue #11 (cmdi quoted-echo evidence spoof):
* `GET /cmdi/ping?host=127.0.0.1;echo "uid=1000(cheater) gid=1000(cheater)"`: 200, command ran, no flag. DEAD.
* Single-quote variant: 200, no flag. DEAD.
* Control: `GET /cmdi/ping?host=127.0.0.1;id` produced genuine `id` output and the flag. The anti-spoof (evidence-shaped text that also appears in the input, quote-stripped, cannot count) holds while honest injection still awards.

## Fairness judgment per module (did the spoiler pass remove anything needed?)

Checked for all nine modules: the module index card (`v.how`) text, the module `brief()` text, the challenge-page `payloadBlock` shapes, and the 3-level hint ladders (all 63 challenges have all three levels; H1 nudges, H2 teaches the technique, H3 gives the attack shape, never a literal payload).

* oauth: FAIR. Cards name the flaw class and the goal ("a prefix check on redirect_uri trusts any URI that starts with the right text, including URIs whose host belongs to someone else"); the brief explains the IdP/client setup and the two sessions. Nothing needed is missing. Note: the Lab 1 page carries a "Start authorization with this redirect_uri" button linking the exact bypass URI, so that first lab is click-through by design; the other seven require constructing the exploit from the placeholder shapes.
* proto: FAIR. Cards name each mechanism (bracketed query keys, `constructor.prototype` back door, escapes decoded after the raw-text scan). The brief warns pollution is per-session with a restart tip. Nothing missing.
* misconfig: FAIR. Cards name the artifact class (backup, listing, `.git`, `.swp`, TRACE, `.env`, defaults, robots.txt, PUT). The git card describes the full walk ("walk the object store and reconstruct the repository, commit by commit"); the student still performs it. Nothing missing.
* crypto: FAIR. Cards teach the concept behind each attack (ECB structure leak, IV malleability, continuing a Merkle-Damgard hash from its output, known-header crib). The brief notes keys are random per boot. Nothing missing.
* jwt: FAIR. The brief teaches token structure and the module goal; the alg-confusion hint warns to copy the key "exactly, newlines included". Nothing missing from the briefings. (Finding F1 below is a `SOLUTIONS.md` staleness, not a briefing gap.)
* api: FAIR. The brief lists every endpoint and states flags arrive in the body or the `X-Pentrix-Flag` header. Cards describe each flaw. Nothing missing.
* auth: FAIR. Cards describe the oracles and goals (distinguish the two login messages, the deterministic recipe is "built only from things anyone can know"). Nothing missing.
* session: FAIR, with an observation. These cards are the most directive in the lab, narrating the exact steps ("Set the lab_sid cookie to a known value (with the preset link, or by editing the Cookie header in Repeater), log in as admin, and confirm the sid did not change"). That is more scaffolding than the other modules give, not less; nothing essential is missing.
* redos: FAIR. Cards describe the near-miss input shapes and the 1000 ms award threshold. Nothing missing.

Overall spoiler verdict: the spoiler pass removed payload literals from cards and briefings but left every concept, goal, endpoint, technique description, and hint-ladder level needed to solve. All 63 challenges were solvable from the in-app materials plus the documented flows. No finding of removed-essential-content in any of the nine modules.

## Time-estimate accuracy ratings

In-app `est` values versus the measured work (scripted expert times are far below human times; ratings judge plausibility for the target persona):

* oauth (5-25 min per challenge): ACCURATE. Heavily scaffolded pages; even the Mediums are quick once the two-session model clicks.
* proto (5-35 min): ACCURATE. The Hard unicode bypass earns its 20-35.
* misconfig (5-20 min): ACCURATE. The git chain walk fits its 10-20.
* crypto: ACCURATE with a conservative note. The Hard trio (ECB 30-45, CBC 20-40, hash-ext 25-45) are fair for hand-built attacks. `rand-pin` at 10-30 min and `otp-bruteforce` at 20-40 min are honest for Burp Community Intruder (throttled, the documented primary tool); a keep-alive script does the 10k space in seconds (measured 1,473 req/s for the PIN, 1,794 req/s for the OTP). No doc change needed; the estimates assume Intruder, not scripts.
* jwt (5-35 min): ACCURATE.
* api (5-25 min): ACCURATE.
* auth (5-40 min): ACCURATE, same Intruder-vs-script note as crypto for the OTP estimate.
* session (5-10 min): ACCURATE.
* redos (10-25 min): ACCURATE. Server-side delays measured 6.9-10.0 s; the estimate covers tuning the input length to cross the threshold.

## Findings

### F1. SOLUTIONS.md jwt alg-confusion: PEM extraction regex is stale (minor, doc-only)

The doc instructs:
`const pem = html.match(/<pre>([\s\S]*?)<\/pre>/)[1];`
The pubkey page no longer renders a bare `<pre>` tag; the key sits in `<pre class="payload-body">` (via `payloadBlock`). A student following the doc literally gets `null` and a TypeError. The working extraction is `/<pre class="payload-body">([\s\S]*?)<\/pre>/` plus HTML-unescape, which yields the exact verifier key bytes (trailing newline included). The in-app hint ("copy it exactly, newlines included") is correct, so this is a one-line doc fix, not a lab bug.

No other flow mismatches found in the tested modules. The oauth flow-stamping (code-replay scoping), the pkce-skip/code-leak/replay award precedence at the token endpoint, the proto per-session pollution scopes, the per-session account overrides, the redos delay thresholds, and both cheat-death gatings all behaved exactly as documented.

## Summary

63/63 challenges solved honestly across the three students (oauth 8/8, proto 6/6, misconfig 10/10, crypto 8/8, jwt 8/8, api 5/5, auth 8/8, session 6/6, redos 4/4). Both re-attempted FLAG BAR cheats (XSS beacon without JS execution, cmdi quoted-echo spoof) stay dead while the honest paths still award. The de-spoilered briefings are fair in all nine modules: nothing essential was removed, hint ladders are intact at three levels everywhere, and the only defect found is the minor F1 doc staleness above.
